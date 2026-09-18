//! Zeptun Tor SOCKS facade. TCP is strict SOCKS CONNECT; UDP/53 and TCP/53
//! become length-prefixed DNS-over-TCP CONNECT dest:53. Tor has no UDP
//! ASSOCIATE, so zeptun ASSOCIATEs here instead of at the exit.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_DNS: usize = 32768;

fn error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

pub(super) struct Adapter {
    endpoint: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Adapter {
    pub(super) fn start(upstream: SocketAddr) -> io::Result<Self> {
        if !upstream.ip().is_loopback() || upstream.port() == 0 {
            return Err(error("socks5t requires a loopback Tor SOCKS endpoint"));
        }
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let listener = {
            let _entered = runtime.enter();
            TcpListener::from_std(listener)?
        };
        let (shutdown, stopped) = oneshot::channel();
        let thread = std::thread::Builder::new().name("zeptun-socks5t".into()).spawn(move || {
            runtime.block_on(serve(listener, upstream, stopped));
        })?;
        Ok(Self { endpoint, shutdown: Some(shutdown), thread: Some(thread) })
    }

    pub(super) fn endpoint(&self) -> SocketAddr { self.endpoint }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); }
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

async fn serve(listener: TcpListener, upstream: SocketAddr, mut stopped: oneshot::Receiver<()>) {
    let logged = Arc::new(AtomicBool::new(false));
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            _ = clients.join_next(), if !clients.is_empty() => {},
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(value) => value,
                    Err(e) => { log::error!("[zeptun socks5t] accept failed: {e}"); break; }
                };
                if !peer.ip().is_loopback() || clients.len() >= 1024 { continue; }
                let logged = Arc::clone(&logged);
                clients.spawn(async move { let _ = serve_client(client, upstream, logged).await; });
            }
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
}

async fn read_ip_address<R: AsyncRead + Unpin>(reader: &mut R, kind: u8) -> io::Result<SocketAddr> {
    let ip = match kind {
        1 => { let mut bytes = [0; 4]; reader.read_exact(&mut bytes).await?; IpAddr::V4(bytes.into()) }
        4 => { let mut bytes = [0; 16]; reader.read_exact(&mut bytes).await?; IpAddr::V6(bytes.into()) }
        _ => return Err(error("SOCKS address must be an IP; local DNS resolution is forbidden")),
    };
    Ok(SocketAddr::new(ip, reader.read_u16().await?))
}

async fn reply(client: &mut TcpStream, status: u8, port: u16) -> io::Result<()> {
    let mut bytes = [5, status, 0, 1, 127, 0, 0, 1, 0, 0];
    bytes[8..].copy_from_slice(&port.to_be_bytes());
    client.write_all(&bytes).await
}

async fn negotiate(client: &mut TcpStream) -> io::Result<(u8, SocketAddr)> {
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 { return Err(error("invalid SOCKS greeting")); }
    let mut methods = vec![0; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 255]).await?;
        return Err(error("SOCKS no-auth method not offered"));
    }
    client.write_all(&[5, 0]).await?;
    let mut request = [0; 4];
    client.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 { return Err(error("invalid SOCKS request")); }
    let address = match read_ip_address(client, request[3]).await {
        Ok(address) => address,
        Err(e) => { reply(client, 8, 0).await?; return Err(e); }
    };
    Ok((request[1], address))
}

async fn serve_client(mut client: TcpStream, upstream: SocketAddr, logged: Arc<AtomicBool>) -> io::Result<()> {
    let (command, destination) = timeout(HANDSHAKE_TIMEOUT, negotiate(&mut client)).await??;
    match command {
        1 if destination.port() == 53 => {
            reply(&mut client, 0, 0).await?;
            serve_tcp_dns(client, upstream, destination, logged).await
        }
        1 if destination.port() == 853 => reply(&mut client, 5, 0).await,
        1 => {
            match socks_connect(upstream, destination).await {
                Ok(mut remote) => {
                    reply(&mut client, 0, 0).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
                    Ok(())
                }
                Err(_) => reply(&mut client, 5, 0).await,
            }
        }
        3 => serve_udp(client, upstream, logged).await,
        _ => reply(&mut client, 7, 0).await,
    }
}

async fn socks_connect(upstream: SocketAddr, destination: SocketAddr) -> io::Result<TcpStream> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut stream = TcpStream::connect(upstream).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut method = [0; 2];
        stream.read_exact(&mut method).await?;
        if method != [5, 0] { return Err(error("Tor rejected SOCKS authentication")); }
        let mut request = vec![5, 1, 0];
        match destination.ip() {
            IpAddr::V4(ip) => { request.push(1); request.extend_from_slice(&ip.octets()); }
            IpAddr::V6(ip) => { request.push(4); request.extend_from_slice(&ip.octets()); }
        }
        request.extend_from_slice(&destination.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut response = [0; 4];
        stream.read_exact(&mut response).await?;
        if response[0] != 5 || response[1] != 0 || response[2] != 0 {
            return Err(error("Tor rejected SOCKS CONNECT"));
        }
        match response[3] {
            1 | 4 => { read_ip_address(&mut stream, response[3]).await?; }
            3 => {
                let length = stream.read_u8().await? as usize;
                let mut ignored = vec![0; length + 2];
                stream.read_exact(&mut ignored).await?;
            }
            _ => return Err(error("invalid Tor SOCKS reply")),
        }
        Ok(stream)
    }).await?
}

fn valid_query(query: &[u8]) -> bool {
    (12..=MAX_DNS).contains(&query.len()) && query[2] & 0x80 == 0
}

fn servfail(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] = (answer[2] & 0x79) | 0x80;
    answer[3] = 0x82;
    answer
}

fn dns_target(dest: SocketAddr) -> SocketAddr {
    if dest.ip().is_unspecified() {
        SocketAddr::from(([1, 1, 1, 1], 53))
    } else {
        SocketAddr::new(dest.ip(), 53)
    }
}

async fn dns_over_tcp(
    upstream: SocketAddr,
    dest: SocketAddr,
    query: &[u8],
    logged: &AtomicBool,
) -> io::Result<Vec<u8>> {
    if !valid_query(query) { return Err(error("invalid DNS query")); }
    let dest = dns_target(dest);
    timeout(DNS_TIMEOUT, async {
        let mut stream = socks_connect(upstream, dest).await?;
        stream.write_u16(query.len() as u16).await?;
        stream.write_all(query).await?;
        let n = stream.read_u16().await? as usize;
        if !(12..=MAX_DNS).contains(&n) { return Err(error("invalid DNS-over-TCP size")); }
        let mut answer = vec![0; n];
        stream.read_exact(&mut answer).await?;
        if !logged.swap(true, Ordering::SeqCst) {
            log::info!("dns over tcp succeeded");
        }
        Ok(answer)
    }).await?
}

async fn serve_tcp_dns(
    mut client: TcpStream,
    upstream: SocketAddr,
    dest: SocketAddr,
    logged: Arc<AtomicBool>,
) -> io::Result<()> {
    loop {
        let query = timeout(Duration::from_secs(30), async {
            let size = client.read_u16().await? as usize;
            if !(12..=MAX_DNS).contains(&size) { return Err(error("invalid TCP DNS size")); }
            let mut query = vec![0; size];
            client.read_exact(&mut query).await?;
            if !valid_query(&query) { return Err(error("invalid TCP DNS query")); }
            Ok::<_, io::Error>(query)
        }).await??;
        let answer = dns_over_tcp(upstream, dest, &query, &logged).await.unwrap_or_else(|_| servfail(&query));
        timeout(DNS_TIMEOUT, async {
            client.write_u16(answer.len() as u16).await?;
            client.write_all(&answer).await
        }).await??;
    }
}

fn udp_dns_header(packet: &[u8]) -> Option<usize> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] { return None; }
    let header = match packet[3] { 1 => 10, 4 => 22, _ => return None };
    if packet.len() < header + 12 { return None; }
    if u16::from_be_bytes([packet[header - 2], packet[header - 1]]) != 53 { return None; }
    valid_query(&packet[header..]).then_some(header)
}

fn udp_dns_dest(packet: &[u8]) -> SocketAddr {
    match packet[3] {
        1 => SocketAddr::from((Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]), 53)),
        4 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&packet[4..20]);
            SocketAddr::from((Ipv6Addr::from(oct), 53))
        }
        _ => SocketAddr::from(([1, 1, 1, 1], 53)),
    }
}

async fn serve_udp(mut control: TcpStream, upstream: SocketAddr, logged: Arc<AtomicBool>) -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    reply(&mut control, 0, socket.local_addr()?.port()).await?;
    let mut buffer = vec![0; 65535];
    let mut control_byte = [0; 1];
    let mut peer = None;
    let mut queries = JoinSet::new();
    loop {
        tokio::select! {
            _ = control.read(&mut control_byte) => break,
            _ = queries.join_next(), if !queries.is_empty() => {},
            packet = socket.recv_from(&mut buffer) => {
                let (size, source) = packet?;
                if !source.ip().is_loopback() || peer.is_some_and(|p| p != source) { continue; }
                let Some(header) = udp_dns_header(&buffer[..size]) else { continue; };
                peer = Some(source);
                if queries.len() >= 64 { continue; }
                let dest = udp_dns_dest(&buffer[..size]);
                let packet = buffer[..size].to_vec();
                let socket = Arc::clone(&socket);
                let logged = Arc::clone(&logged);
                queries.spawn(async move {
                    let answer = dns_over_tcp(upstream, dest, &packet[header..], &logged).await
                        .unwrap_or_else(|_| servfail(&packet[header..]));
                    let mut response = packet[..header].to_vec();
                    response.extend_from_slice(&answer);
                    let _ = socket.send_to(&response, source).await;
                });
            }
        }
    }
    queries.abort_all();
    while queries.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open(adapter: SocketAddr, command: u8, ip: [u8; 4], port: u16) -> (TcpStream, u16) {
        let mut stream = TcpStream::connect(adapter).await.unwrap();
        let mut request = vec![5, 1, 0, 5, command, 0, 1];
        request.extend_from_slice(&ip);
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0; 12];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 5, 0]);
        (stream, u16::from_be_bytes([reply[10], reply[11]]))
    }

    #[tokio::test]
    async fn tor_exit_dns_is_connect_port_53_length_prefixed() {
        timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let adapter = Adapter::start(listener.local_addr().unwrap()).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..3], &[5, 1, 0]);
                assert_eq!(read_ip_address(&mut stream, request[3]).await.unwrap(), "1.1.1.1:53".parse().unwrap());
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let n = stream.read_u16().await.unwrap() as usize;
                let mut body = vec![0; n];
                stream.read_exact(&mut body).await.unwrap();
                assert_eq!(&body[..2], &[0x12, 0x34]);
                body[2] |= 0x80;
                stream.write_u16(body.len() as u16).await.unwrap();
                stream.write_all(&body).await.unwrap();
                assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err());
            });
            let (control, port) = open(adapter.endpoint(), 3, [0, 0, 0, 0], 0).await;
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut query = vec![0; 12];
            query[..3].copy_from_slice(&[0x12, 0x34, 1]);
            let mut packet = vec![0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
            packet.extend_from_slice(&query);
            udp.send_to(&packet, (Ipv4Addr::LOCALHOST, port)).await.unwrap();
            let mut response = [0; 512];
            let (size, _) = udp.recv_from(&mut response).await.unwrap();
            assert_eq!(size, packet.len());
            assert_eq!(&response[..10], &packet[..10]);
            assert_eq!(response[12] & 0x80, 0x80);
            server.await.unwrap();
            drop(adapter);
            drop(control);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn unspecified_udp_dns_rewrites_to_1_1_1_1() {
        timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let adapter = Adapter::start(listener.local_addr().unwrap()).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(read_ip_address(&mut stream, request[3]).await.unwrap(), "1.1.1.1:53".parse().unwrap());
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let n = stream.read_u16().await.unwrap() as usize;
                let mut body = vec![0; n];
                stream.read_exact(&mut body).await.unwrap();
                body[2] |= 0x80;
                stream.write_u16(body.len() as u16).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
            let (control, port) = open(adapter.endpoint(), 3, [0, 0, 0, 0], 0).await;
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut query = vec![0; 12];
            query[..3].copy_from_slice(&[0x12, 0x34, 1]);
            let mut packet = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 53];
            packet.extend_from_slice(&query);
            udp.send_to(&packet, (Ipv4Addr::LOCALHOST, port)).await.unwrap();
            let mut response = [0; 512];
            udp.recv_from(&mut response).await.unwrap();
            server.await.unwrap();
            drop(adapter);
            drop(control);
        }).await.unwrap();
    }
}
