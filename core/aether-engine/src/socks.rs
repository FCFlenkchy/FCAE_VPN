use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;
use crate::stats;

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const REP_OK: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_NOT_SUPPORTED: u8 = 0x07;

enum Target {
    Ip(IpAddr),
    Domain(String),
}

pub async fn serve(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("socks5 listening on {listen}");
    let bind_ip = listen.ip();

    loop {
        let (sock, peer) = listener.accept().await?;
        let stack = stack.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, stack, bind_ip).await {
                // 10054 / connection reset is normal when clients close mid-stream
                let msg = e.to_string();
                if msg.contains("10054")
                    || msg.contains("forcibly closed")
                    || msg.contains("Connection reset")
                    || msg.contains("broken pipe")
                {
                    log::trace!("socks client {peer} closed: {e}");
                } else {
                    log::debug!("socks client {peer} ended: {e}");
                }
            }
        });
    }
}

async fn handle_client(mut sock: TcpStream, stack: StackHandle, bind_ip: IpAddr) -> Result<()> {
    handshake(&mut sock).await?;

    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(AetherError::Other("bad socks version".into()));
    }

    let cmd = head[1];
    let atyp = head[3];
    let (target, port) = read_target(&mut sock, atyp).await?;

    match cmd {
        CMD_CONNECT => handle_connect(sock, stack, target, port).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(sock, stack, bind_ip).await,
        _ => {
            reply(&mut sock, REP_NOT_SUPPORTED).await?;
            Err(AetherError::Other("unsupported socks command".into()))
        }
    }
}

async fn handshake(sock: &mut TcpStream) -> Result<()> {
    let mut prefix = [0u8; 2];
    sock.read_exact(&mut prefix).await?;
    if prefix[0] != VER {
        return Err(AetherError::Other("bad greeting version".into()));
    }
    let nmethods = prefix[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[VER, 0x00]).await?;
    Ok(())
}

async fn read_target(sock: &mut TcpStream, atyp: u8) -> Result<(Target, u16)> {
    let target = match atyp {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            Target::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            Target::Ip(IpAddr::V6(b.into()))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            Target::Domain(String::from_utf8_lossy(&name).to_string())
        }
        _ => return Err(AetherError::Other("bad atyp".into())),
    };

    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    Ok((target, u16::from_be_bytes(port)))
}

async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[VER, code, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn reply_bound(sock: &mut TcpStream, bound: SocketAddr) -> Result<()> {
    let mut buf = vec![VER, REP_OK, 0x00];
    match bound.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&bound.port().to_be_bytes());
    sock.write_all(&buf).await?;
    Ok(())
}

async fn resolve(stack: &StackHandle, target: Target) -> Result<IpAddr> {
    match target {
        Target::Ip(ip) => Ok(ip),
        Target::Domain(name) => {
            if let Ok(ip) = name.parse::<IpAddr>() {
                return Ok(ip);
            }
            dns_resolve(stack, &name).await
        }
    }
}

fn dns_server() -> SocketAddr {
    let raw = std::env::var("AETHER_DNS").unwrap_or_else(|_| "1.1.1.1:53".into());
    if let Ok(a) = raw.parse::<SocketAddr>() {
        return a;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return SocketAddr::new(ip, 53);
    }
    "1.1.1.1:53".parse().unwrap()
}

fn dns_prefer() -> u8 {
    // 4 = A, 6 = AAAA, 10 = dual (AAAA then A)
    match std::env::var("AETHER_DNS_IP")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "6" | "v6" | "ipv6" => 6,
        "both" | "dual" | "10" => 10,
        _ => 4,
    }
}

fn dns_mode_doh() -> bool {
    matches!(
        std::env::var("AETHER_DNS_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "doh" | "https" | "1" | "true" | "yes"
    )
}

fn doh_url() -> String {
    std::env::var("AETHER_DOH_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".into())
}

pub(crate) async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    if dns_mode_doh() {
        return dns_resolve_doh(name).await;
    }
    dns_resolve_udp(stack, name).await
}

async fn dns_resolve_udp(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    let prefer = dns_prefer();
    let types: &[u16] = match prefer {
        6 => &[28],
        10 => &[28, 1],
        _ => &[1],
    };
    let server = dns_server();
    let mut last_err = AetherError::Other(format!("no DNS record for {name}"));
    for qtype in types {
        match dns_query_udp(stack, name, server, *qtype).await {
            Ok(ip) => return Ok(ip),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn dns_query_udp(
    stack: &StackHandle,
    name: &str,
    server: SocketAddr,
    qtype: u16,
) -> Result<IpAddr> {
    let udp = stack.open_udp().await?;
    let query = build_dns_query(name, qtype);
    udp.send_to(server, query).await?;
    let (_sender, mut from_stack) = udp.into_split();
    let resp = tokio::time::timeout(Duration::from_secs(5), from_stack.recv())
        .await
        .map_err(|_| AetherError::Other("dns timeout".into()))?
        .ok_or_else(|| AetherError::Other("dns channel closed".into()))?;
    parse_dns_answer(&resp.1, qtype)
        .ok_or_else(|| AetherError::Other(format!("no DNS type {qtype} for {name}")))
}

async fn dns_resolve_doh(name: &str) -> Result<IpAddr> {
    let prefer = dns_prefer();
    let types: &[&str] = match prefer {
        6 => &["AAAA"],
        10 => &["AAAA", "A"],
        _ => &["A"],
    };
    let base = doh_url();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| AetherError::Other(format!("doh client: {e}")))?;
    let mut last_err = AetherError::Other(format!("no DoH record for {name}"));
    for t in types {
        let url = format!(
            "{base}?name={}&type={t}",
            urlencoding_simple(name)
        );
        match client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
        {
            Ok(resp) => {
                let text = resp
                    .text()
                    .await
                    .map_err(|e| AetherError::Other(format!("doh body: {e}")))?;
                if let Some(ip) = parse_doh_json(&text) {
                    return Ok(ip);
                }
                last_err = AetherError::Other(format!("DoH empty for {name} type {t}"));
            }
            Err(e) => last_err = AetherError::Other(format!("doh: {e}")),
        }
    }
    Err(last_err)
}

fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_doh_json(text: &str) -> Option<IpAddr> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let answers = v.get("Answer")?.as_array()?;
    for a in answers {
        let ty = a.get("type")?.as_u64()?;
        let data = a.get("data")?.as_str()?;
        if ty == 1 || ty == 28 {
            if let Ok(ip) = data.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

fn parse_dns_answer(resp: &[u8], want_type: u16) -> Option<IpAddr> {
    if resp.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qd {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?;
    }

    for _ in 0..an {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return None;
        }
        if rtype == want_type || (want_type == 0 && (rtype == 1 || rtype == 28)) {
            if rtype == 1 && rdlen == 4 {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    resp[pos],
                    resp[pos + 1],
                    resp[pos + 2],
                    resp[pos + 3],
                )));
            }
            if rtype == 28 && rdlen == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&resp[pos..pos + 16]);
                return Some(IpAddr::V6(b.into()));
            }
        }
        pos += rdlen;
    }
    None
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

async fn handle_connect(
    mut sock: TcpStream,
    stack: StackHandle,
    target: Target,
    port: u16,
) -> Result<()> {
    let ip = match resolve(&stack, target).await {
        Ok(ip) => ip,
        Err(e) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(e);
        }
    };

    let dst = SocketAddr::new(ip, port);
    let conn = match stack.open_tcp(dst).await {
        Ok(c) => c,
        Err(e) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(e);
        }
    };

    reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;

    let (sender, mut from_stack) = conn.into_split();
    let (mut rd, mut wr) = sock.into_split();

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    sender.close().await;
                    break;
                }
                Ok(n) => {
                    stats::add_tx(n as u64);
                    if sender.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    sender.close().await;
                    break;
                }
            }
        }
    });

    while let Some(chunk) = from_stack.recv().await {
        stats::add_rx(chunk.len() as u64);
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
    }

    let _ = wr.shutdown().await;
    up.abort();
    Ok(())
}

async fn handle_udp_associate(mut sock: TcpStream, stack: StackHandle, bind_ip: IpAddr) -> Result<()> {
    let relay = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let relay_addr = relay.local_addr()?;
    reply_bound(&mut sock, relay_addr).await?;

    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();

    let mut client: Option<SocketAddr> = None;
    let mut cbuf = vec![0u8; 16384];
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            r = relay.recv_from(&mut cbuf) => {
                let (n, from) = match r { Ok(v) => v, Err(_) => break };
                client = Some(from);
                if let Some((dst, payload)) = parse_udp_request(&cbuf[..n]) {
                    let dst = match dst {
                        Target::Ip(ip) => SocketAddr::new(ip, payload.0),
                        Target::Domain(name) => {
                            match dns_resolve(&stack, &name).await {
                                Ok(ip) => SocketAddr::new(ip, payload.0),
                                Err(_) => continue,
                            }
                        }
                    };
                    stats::add_tx(payload.1.len() as u64);
                    let _ = sender.send_to(dst, payload.1).await;
                }
            }

            maybe = from_stack.recv() => {
                let (src, data) = match maybe { Some(v) => v, None => break };
                if let Some(c) = client {
                    stats::add_rx(data.len() as u64);
                    let pkt = build_udp_reply(src, &data);
                    let _ = relay.send_to(&pkt, c).await;
                }
            }

            r = sock.read(&mut ctrl) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
        }
    }

    sender.close().await;
    Ok(())
}

fn parse_udp_request(buf: &[u8]) -> Option<(Target, (u16, Vec<u8>))> {
    if buf.len() < 4 || buf[2] != 0 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4;
    let target = match atyp {
        ATYP_V4 => {
            if buf.len() < pos + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            pos += 4;
            Target::Ip(IpAddr::V4(ip))
        }
        ATYP_V6 => {
            if buf.len() < pos + 16 {
                return None;
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            Target::Ip(IpAddr::V6(b.into()))
        }
        ATYP_DOMAIN => {
            let len = *buf.get(pos)? as usize;
            pos += 1;
            if buf.len() < pos + len {
                return None;
            }
            let name = String::from_utf8_lossy(&buf[pos..pos + len]).to_string();
            pos += len;
            Target::Domain(name)
        }
        _ => return None,
    };

    if buf.len() < pos + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some((target, (port, buf[pos..].to_vec())))
}

fn build_udp_reply(src: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x00, 0x00, 0x00];
    match src.ip() {
        IpAddr::V4(v4) => {
            pkt.push(ATYP_V4);
            pkt.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            pkt.push(ATYP_V6);
            pkt.extend_from_slice(&v6.octets());
        }
    }
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}
