// Package main is the cgo shim that turns xjasonlyu/tun2socks into an
// in-process library instead of a subprocess.
//
// It is compiled with `go build -buildmode=c-archive`, producing
// libfcae_go_bridge.a + .h, which the Rust crate links statically. The Go
// runtime then lives inside libfcae_ffi.a, so there is no tun2socks
// executable to extract, no fd inheritance across execve, no taskkill, and no
// antivirus flagging an unsigned binary dropped into %TEMP%.
//
// Threading contract (important, this is a cgo boundary):
//
//   - t2s_start blocks only long enough to bring the gVisor stack up; the
//     stack itself runs on Go-owned goroutines.
//   - t2s_stop is idempotent and safe to call from any thread, including
//     concurrently with t2s_start.
//   - All exported functions serialise on a single mutex, so the Rust side
//     never has to.
//   - Logs are pushed to Rust through a registered C callback rather than
//     stdout, because a library has no business writing to the host's stdout.
package main

/*
#include <stdint.h>
#include <stdlib.h>

// Implemented on the Rust side; see bridges/tun2socks/src/lib.rs.
// Declared here so cgo lets Go call back into the host.
typedef void (*t2s_log_fn)(int level, const char *msg);

static void t2s_invoke_log(t2s_log_fn fn, int level, const char *msg) {
    if (fn != NULL) {
        fn(level, msg);
    }
}
*/
import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	socks5wire "github.com/xjasonlyu/tun2socks/v2/transport/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	logError = 1
	logWarn  = 2
	logInfo  = 3
	logDebug = 4
)

// The bridge keeps one public proxy schema: "socks5". The upstream SOCKS5
// implementation always sends UDP ASSOCIATE (0x03), but Psiphon's local
// listener is CONNECT-only and rejects that command. A small query flag on
// the Psiphon URL selects the Psiphon DNS behavior inside this same schema;
// ordinary Aether SOCKS endpoints keep the normal full SOCKS5 UDP path.
const schemeSocks5 = "socks5"

const psiphonDNSQuery = "fcae_psiphon_dns"

// blackholeConn is a net.PacketConn that swallows every write and blocks
// forever on read. Returning an error from DialUDP instead would make
// tun2socks log one error per UDP flow -- the same flood, different message.
type blackholeConn struct {
	done chan struct{}
	once sync.Once
}

func (c *blackholeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.done
	return 0, nil, net.ErrClosed
}

func (c *blackholeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *blackholeConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *blackholeConn) LocalAddr() net.Addr              { return nil }
func (c *blackholeConn) SetDeadline(time.Time) error      { return nil }
func (c *blackholeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blackholeConn) SetWriteDeadline(time.Time) error { return nil }

// socks5Proxy is the pinned tun2socks SOCKS5 client with one FCAE-specific
// option. Keeping the option in the standard "socks5" parser avoids a second
// protocol registration and an extra scheme-selection branch in Rust.
//
// For ordinary endpoints it is equivalent to the upstream client, including
// UDP ASSOCIATE. For a URL carrying fcae_psiphon_dns=1 it sends CONNECT for
// TCP, silently absorbs non-DNS UDP, and sends DNS through Psiphon's native
// UDP gateway. The wrapper is allocation-free on the TCP data path beyond the
// normal SOCKS connection and handshake.
type socks5Proxy struct {
	addr       string
	user       string
	pass       string
	unix       bool
	psiphonDNS bool
	ctx        context.Context
	gw         *udpgwGateway
}

func newSocks5Proxy(u *url.URL) (*socks5Proxy, error) {
	addr := u.Host
	if addr == "" {
		addr = u.Path
	}
	unix := len(addr) > 0 && addr[0] == '/'
	if len(addr) > 2 && (addr[1] == '@' || addr[1] == 0x00) {
		addr = addr[1:]
	}

	p := &socks5Proxy{
		addr: addr,
		unix: unix,
		ctx: currentDNSContext(),
	}
	if u.User != nil {
		p.user = u.User.Username()
		p.pass, _ = u.User.Password()
	}
	p.psiphonDNS = u.Query().Get(psiphonDNSQuery) == "1"
	if p.psiphonDNS {
		// One gateway per tun2socks session: all copies of this proxy share
		// one channel, as required by Psiphon's server-side UDPGW handler.
		p.gw = newUdpgwGateway(p.ctx, p.connectOnly())
	}
	return p, nil
}

func (p *socks5Proxy) userInfo() *socks5wire.User {
	if p.user == "" {
		return nil
	}
	return &socks5wire.User{Username: p.user, Password: p.pass}
}

func (p *socks5Proxy) dialEndpoint(ctx context.Context) (net.Conn, error) {
	network := "tcp"
	if p.unix {
		network = "unix"
	}
	conn, err := dialer.DialContext(ctx, network, p.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", p.addr, err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	return conn, nil
}

func (p *socks5Proxy) connectOnly() *socks5Proxy {
	q := *p
	q.psiphonDNS = false
	q.gw = nil
	return &q
}

func (p *socks5Proxy) dialConnect(ctx context.Context, m *metadata.Metadata) (conn net.Conn, err error) {
	conn, err = p.dialEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	_, err = socks5wire.ClientHandshake(conn,
		socks5wire.SerializeAddr("", m.DstIP, m.DstPort),
		socks5wire.CmdConnect, p.userInfo())
	return conn, err
}

func (p *socks5Proxy) DialContext(ctx context.Context, m *metadata.Metadata) (net.Conn, error) {
	if p.psiphonDNS && m.DstPort == 853 {
		return nil, errDoTRefused
	}
	if p.psiphonDNS && m.DstPort == 53 && m.DstIP.IsValid() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		client, server := net.Pipe()
		relay := newDNSRelay(p.ctx, server, p.gw)
		go func() {
			defer server.Close()
			defer relay.Close()
			// Do not retain the caller's dial timeout as the stream lifetime.
			// Each frame/query has its own deadline; closing client breaks I/O.
			for {
				_ = server.SetDeadline(time.Now().Add(30 * time.Second))
				var header [2]byte
				if _, err := io.ReadFull(server, header[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(header[:]))
				if size < 12 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(server, query); err != nil {
					return
				}
				if query[2]&0x80 != 0 {
					return
				}
				answer, err := relay.resolvePsiphon(query)
				if err != nil {
					emit(logWarn, "[dns] Psiphon TCP DNS relay failed: %v", err)
					answer = dnsServfail(query)
				}
				binary.BigEndian.PutUint16(header[:], uint16(len(answer)))
				if _, err := server.Write(append(header[:], answer...)); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	return p.dialConnect(ctx, m)
}

func (p *socks5Proxy) DialUDP(m *metadata.Metadata) (net.PacketConn, error) {
	if p.psiphonDNS {
		if m.DstPort == 53 && m.DstIP.IsValid() {
			return newDNSRelay(p.ctx, nil, p.gw), nil
		}
		return &blackholeConn{done: make(chan struct{})}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.dialEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	closeConn := true
	defer func() {
		if closeConn {
			_ = conn.Close()
		}
	}()
	addr, err := socks5wire.ClientHandshake(conn,
		socks5wire.Addr{socks5wire.AtypIPv4, 0, 0, 0, 0, 0, 0},
		socks5wire.CmdUDPAssociate, p.userInfo())
	if err != nil {
		return nil, fmt.Errorf("client handshake: %w", err)
	}
	pc, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("listen packet: %w", err)
	}

	go func() {
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		_ = pc.Close()
	}()

	bindAddr := addr.UDPAddr()
	if bindAddr == nil {
		_ = pc.Close()
		return nil, fmt.Errorf("invalid UDP binding address: %#v", addr)
	}
	if bindAddr.IP.IsUnspecified() {
		udpAddr, err := net.ResolveUDPAddr("udp", p.addr)
		if err != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("resolve udp address %s: %w", p.addr, err)
		}
		bindAddr.IP = udpAddr.IP
	}
	closeConn = false
	return &socksPacketConn{PacketConn: pc, rAddr: bindAddr, tcpConn: conn}, nil
}

type socksPacketConn struct {
	net.PacketConn
	rAddr   net.Addr
	tcpConn net.Conn
}

func (pc *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if ma, ok := addr.(*metadata.Addr); ok {
		b, err = socks5wire.EncodeUDPPacket(
			socks5wire.SerializeAddr("", ma.Metadata().DstIP, ma.Metadata().DstPort), b)
	} else {
		b, err = socks5wire.EncodeUDPPacket(socks5wire.ParseAddr(addr), b)
	}
	if err != nil {
		return 0, err
	}
	return pc.PacketConn.WriteTo(b, pc.rAddr)
}

func (pc *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	addr, payload, err := socks5wire.DecodeUDPPacket(b)
	if err != nil {
		return 0, nil, err
	}
	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, fmt.Errorf("convert %s to UDPAddr is nil", addr)
	}
	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
}

func (pc *socksPacketConn) Close() error {
	_ = pc.tcpConn.Close()
	return pc.PacketConn.Close()
}

// errDoTRefused is returned for TCP/853 in Psiphon mode; see DialContext.
var errDoTRefused = errors.New("dns: DNS-over-TLS is not carried in Psiphon mode; plain DNS goes through the exit's gateway")

// Psiphon's official SOCKS listener is CONNECT-only. Intercept TCP/53 too:
// Android and desktop resolvers may retry a UDP lookup over TCP. Forwarding
// that retry to an exit which denies TCP/53 defeats the native DNS relay.
//
// TCP/853 (DNS-over-TLS) is refused locally in Psiphon mode. Android's
// "Private DNS: automatic" probes the TUN resolver on 853 before every
// cleartext lookup; Psiphon exits whitelist ports and 853 is not on it, so
// each probe was a tunneled CONNECT answered with "administratively
// prohibited" -- one "port forward failure" per probe and, until the probe
// timed out, no cleartext fallback and therefore no DNS at all. A local
// refusal makes the OS fall back to plain DNS immediately, which the
// gateway below then resolves through the exit. Nothing is resolved outside
// the tunnel. (Strict mode with a named DoT host cannot work through
// Psiphon; the OS reports "Private DNS server cannot be accessed".)

func newDNSRelay(parent context.Context, stream net.Conn, gw *udpgwGateway) *dnsRelayConn {
	ctx, cancel := context.WithCancel(parent)
	c := &dnsRelayConn{
		ctx: ctx, cancel: cancel, pending: make(chan struct{}, 4),
		replies: make(chan dnsReply, 8), done: make(chan struct{}),
		stream: stream, deadlineChanged: make(chan struct{}), gw: gw,
	}
	context.AfterFunc(ctx, func() { c.Close() })
	return c
}

func dnsServfail(query []byte) []byte {
	response := append([]byte(nil), query...)
	response[2] = (response[2] & 0x79) | 0x80
	response[3] = 0x82
	return response
}

// dnsRelayTimeout bounds one native DNS exchange and the initial UDPGW
// CONNECT. A warmed gateway normally answers well below this limit; the
// bound prevents a dead egress from parking a TUN flow indefinitely.
const dnsRelayTimeout = 8 * time.Second

// dnsReply is one completed native Psiphon DNS answer. Failed exchanges are
// converted to SERVFAIL before they reach this channel so the resolver can
// retry without tearing down the UDP flow.
type dnsReply struct {
	payload []byte
	src     net.Addr
}

// dnsRelayConn is the PacketConn handed to one Psiphon DNS flow. The native
// Psiphon UDP gateway returns the answer without sending SOCKS UDP ASSOCIATE.
type dnsRelayConn struct {
	gw *udpgwGateway
	stream net.Conn
	deadlineMu sync.Mutex
	readDeadline time.Time
	deadlineChanged chan struct{}
	ctx context.Context
	cancel context.CancelFunc
	pending chan struct{}
	replies chan dnsReply
	done chan struct{}
	once sync.Once
}

func (c *dnsRelayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || len(p) < 12 || len(p) > 0xffff || p[2]&0x80 != 0 {
		return len(p), nil
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case c.pending <- struct{}{}:
	default:
		return len(p), nil
	}
	payload := append([]byte(nil), p...)
	go func() {
		defer func() { <-c.pending }()
		resp, err := c.resolvePsiphon(payload)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			emit(logWarn, "[dns] tunneled DNS relay failed: %v", err)
			resp = dnsServfail(payload)
		}
		select {
		case c.replies <- dnsReply{payload: resp, src: udpAddr}:
		case <-c.done:
		}
	}()
	return len(p), nil
}

func (c *dnsRelayConn) resolvePsiphon(query []byte) ([]byte, error) {
	if c.gw == nil {
		return nil, errors.New("psiphon DNS gateway unavailable")
	}
	return c.gw.exchange(c.ctx, query)
}

func (c *dnsRelayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.deadlineMu.Lock()
		deadline, changed := c.readDeadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case r := <-c.replies:
			if timer != nil { timer.Stop() }
			if len(r.payload) > len(p) { return 0, nil, io.ErrShortBuffer }
			return copy(p, r.payload), r.src, nil
		case <-c.done:
			if timer != nil { timer.Stop() }
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil { timer.Stop() }
			continue
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *dnsRelayConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		close(c.done)
		if c.stream != nil { _ = c.stream.Close() }
	})
	return nil
}

func (c *dnsRelayConn) LocalAddr() net.Addr              { return nil }
func (c *dnsRelayConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *dnsRelayConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}
func (c *dnsRelayConn) SetWriteDeadline(time.Time) error { return nil }

// udpgw wire constants, mirroring the BadVPN protocol the Psiphon server
// implements in psiphon/server/udp.go.
const (
	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3

	udpgwMaxPayload     = 32768
	udpgwMaxMessageSize = 23 + udpgwMaxPayload // max preamble + max payload

	// Psiphon's server intercepts CONNECTs to this address and speaks
	// BadVPN UDPGW inside the SSH channel instead (see tunnelServer.go:
	// UDPInterceptUdpgwServerAddress).
	udpgwServerPort = 7300

	// DNS queries are multiplexed over a SMALL FIXED POOL of udpgw
	// connection IDs. Each distinct connection ID is one UDP port forward
	// on the exit, and the exit keeps at most MaxUDPPortForwardCount (32
	// by default, server/trafficRules.go) per client, closing the least
	// recently used one when a new ID arrives. Minting a fresh ID per
	// query -- what this gateway used to do -- therefore evicted in-flight
	// exchanges as soon as a resolver burst exceeded 32 lookups, which
	// surfaced as reply timeouts / SERVFAIL and as a steady stream of
	// server-side forward closes (the climbing "port forward failures"
	// counter). Eight slots stay well under the cap and under the 30 s
	// idle timer thanks to the keepalive, so the forwards never churn.
	udpgwDNSSlots       = 8
	udpgwMaxPending     = 512
	udpgwDialCooldown   = 250 * time.Millisecond
	udpgwKeepaliveEvery = 20 * time.Second
)

// udpgwGateway multiplexes every DNS exchange over ONE long-lived BadVPN
// UDPGW channel to the Psiphon exit.
//
// The server allows exactly one udpgw channel per SSH client: when a new
// channel arrives it REPLACES -- and therefore closes -- any previously
// existing one (psiphon/server/udp.go, handleUdpgwChannel: "This channel
// will replace any previously existing udpgw channel for this client").
//
// Within that channel the server is a plain UDP NAT table keyed by
// connection ID with LRU eviction (see udpgwDNSSlots). The official BadVPN
// client reuses one ID per flow for exactly that reason; this gateway does
// the same for DNS: queries are spread round-robin over udpgwDNSSlots IDs
// and demultiplexed by the DNS transaction ID, which the gateway rewrites
// to a value unique among in-flight exchanges (and restores in the reply)
// exactly like any forwarding resolver. Writes are serialised, the channel
// reconnects automatically with in-flight retry, and keepalives keep the
// slots warm on the exit.
type udpgwGateway struct {
	ctx   context.Context
	inner proxy.Proxy

	dialMu sync.Mutex // single-flight channel (re)connects
	mu     sync.Mutex
	conn   net.Conn
	pending  map[uint16]chan gwReply // keyed by rewritten DNS transaction ID
	nextTxID uint16
	nextSlot uint16
	lastDial time.Time

	writeMu sync.Mutex // SSH channels must not be written concurrently

	keepaliveOnce sync.Once

	// lastDialErr is the last CONNECT failure reported to the host log.
	// The gateway is the ONLY DNS path in Psiphon mode, so a refused or
	// failing CONNECT means "no DNS at all" and must be visible at the
	// default (errors only) log level -- but once per distinct cause, not
	// once per query.
	lastDialErr string
}

// gwReply is one completed UDPGW exchange delivered to the waiting query.
type gwReply struct {
	payload []byte
	err     error
}

func newUdpgwGateway(parent context.Context, inner proxy.Proxy) *udpgwGateway {
	ctx, cancel := context.WithCancel(parent)
	g := &udpgwGateway{
		ctx: ctx, inner: inner,
		pending: make(map[uint16]chan gwReply),
	}
	// Session teardown (or a new t2s_start retiring this context) must not
	// leak the channel or leave exchanges parked on a dead connection.
	context.AfterFunc(ctx, func() {
		cancel()
		g.close()
	})
	return g
}

// exchange runs one DNS query over the gateway. It retries once on a
// broken/replaced channel; if the gateway still cannot answer (exit without
// UDP intercept, tunnel flapping) the error propagates and the caller
// answers SERVFAIL so the OS retries. There is no other resolver.
func (g *udpgwGateway) exchange(parent context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > udpgwMaxPayload {
		return nil, errors.New("invalid UDPGW DNS size")
	}
	origTxID := binary.BigEndian.Uint16(query[0:2])
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := parent.Err(); err != nil {
			return nil, err
		}
		if attempt > 0 {
			// Give the reconnect cooldown room to elapse before retrying.
			select {
			case <-time.After(udpgwDialCooldown):
			case <-parent.Done():
				return nil, parent.Err()
			}
		}
		conn, err := g.channel()
		if err != nil {
			lastErr = err
			continue
		}
		txID, slot, ch, ok := g.register()
		if !ok {
			lastErr = errors.New("udpgw: query table full")
			continue
		}
		if err := g.send(conn, slot, txID, query); err != nil {
			g.retire(txID)
			g.invalidate(conn)
			lastErr = err
			continue
		}
		select {
		case rep := <-ch:
			g.retire(txID)
			if rep.err == nil {
				binary.BigEndian.PutUint16(rep.payload[0:2], origTxID)
				return rep.payload, nil
			}
			lastErr = rep.err
		case <-time.After(dnsRelayTimeout):
			g.retire(txID)
			lastErr = errors.New("udpgw: reply timeout")
		case <-parent.Done():
			g.retire(txID)
			return nil, parent.Err()
		}
	}
	return nil, lastErr
}

// channel returns the shared gateway connection, dialing it through the
// Psiphon SOCKS listener if necessary. Dialing is single-flight: two
// concurrent channels would replace each other server-side, recreating the
// very EOF storm this gateway exists to fix.
func (g *udpgwGateway) channel() (net.Conn, error) {
	g.dialMu.Lock()
	defer g.dialMu.Unlock()

	g.mu.Lock()
	if g.conn != nil {
		c := g.conn
		g.mu.Unlock()
		return c, nil
	}
	if !g.lastDial.IsZero() && time.Since(g.lastDial) < udpgwDialCooldown {
		g.mu.Unlock()
		return nil, errors.New("udpgw: reconnect cooldown")
	}
	g.mu.Unlock()

	ctx, cancel := context.WithTimeout(g.ctx, dnsRelayTimeout)
	defer cancel()
	conn, err := g.inner.DialContext(ctx, &metadata.Metadata{
		Network: metadata.TCP,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: udpgwServerPort,
	})
	if err != nil {
		g.mu.Lock()
		g.lastDial = time.Now()
		first := g.lastDialErr != err.Error()
		g.lastDialErr = err.Error()
		g.mu.Unlock()
		if first {
			// "general SOCKS server failure" = the local SOCKS listener had
			// no active tunnel (reconnecting); "connection refused" = the
			// exit rejected the udpgw CONNECT itself (no UDP intercept on
			// this server) -- the latter means DNS stays dead until the
			// controller moves to another exit.
			emit(logError, "[dns] Psiphon UDPGW CONNECT failed: %v", err)
		}
		return nil, fmt.Errorf("Psiphon UDPGW CONNECT failed: %w", err)
	}
	g.mu.Lock()
	g.lastDial = time.Now()
	g.conn = conn
	recovered := g.lastDialErr != ""
	g.lastDialErr = ""
	g.mu.Unlock()
	if recovered {
		emit(logError, "[dns] Psiphon UDPGW channel re-established")
	}

	g.keepaliveOnce.Do(func() { go g.keepaliveLoop() })
	go g.readLoop(conn)
	return conn, nil
}

// register claims a DNS transaction ID that is not currently in flight and
// picks the next pool slot (udpgw connection ID 1..udpgwDNSSlots) round
// robin. Transaction IDs are handed out monotonically and wrap; a wrapped
// ID can only collide with an equally long-lived exchange, which the scan
// skips. Slots are never "owned": the reply is matched by transaction ID,
// so sharing a slot between concurrent queries is safe.
func (g *udpgwGateway) register() (txID, slot uint16, ch chan gwReply, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pending) >= udpgwMaxPending {
		return 0, 0, nil, false
	}
	for {
		g.nextTxID++
		if _, taken := g.pending[g.nextTxID]; taken {
			continue
		}
		ch = make(chan gwReply, 1) // buffered: a timed-out query never blocks the reader
		g.pending[g.nextTxID] = ch
		g.nextSlot = g.nextSlot%udpgwDNSSlots + 1
		return g.nextTxID, g.nextSlot, ch, true
	}
}

func (g *udpgwGateway) retire(txID uint16) {
	g.mu.Lock()
	delete(g.pending, txID)
	g.mu.Unlock()
}

// send writes one UDPGW frame as a transparent DNS exchange, flagged DNS
// exactly like the official client. The exit resolves the query with its
// own resolver; the zero address is only a flow label. The DNS transaction
// ID is replaced by the gateway-unique txID; exchange restores it.
//
// The DNS flag is what makes this work on every exit. A plain UDP port
// forward to a resolver of our choosing goes through the exit's traffic
// rules (AllowUDPPorts, subnet/ASN filters) and, when refused, is dropped
// with no error -- udpgw has no NAK -- which surfaced as an 8 s stall and
// SERVFAIL for every lookup on restrictive servers. The flagged exchange
// bypasses those rules server-side because DNS is treated as essential.
//
// Wire layout mirrors the official server/udp.go: LE length excluding the
// length field, flags, LE connection ID, raw IP, BE port, UDP payload.
func (g *udpgwGateway) send(conn net.Conn, slot, txID uint16, query []byte) error {
	ip := net.IPv4zero.To4()
	frame := make([]byte, 11+len(query))
	binary.LittleEndian.PutUint16(frame[0:2], uint16(len(frame)-2))
	frame[2] = udpgwFlagDNS
	binary.LittleEndian.PutUint16(frame[3:5], slot)
	copy(frame[5:9], ip)
	binary.BigEndian.PutUint16(frame[9:11], 53)
	copy(frame[11:], query)
	binary.BigEndian.PutUint16(frame[11:13], txID)

	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	_, err := conn.Write(frame)
	return err
}

// readLoop demultiplexes gateway replies by DNS transaction ID. One
// goroutine per channel; it exits on an I/O error or a corrupt length
// prefix (the stream is unrecoverable then), failing every pending
// exchange so they retry on a fresh channel. A well-framed message with
// an unusable body -- empty resolver answer, unknown flag layout -- is
// skipped: one odd datagram must not tear down every lookup in flight.
func (g *udpgwGateway) readLoop(conn net.Conn) {
	defer g.drop(conn)
	buf := make([]byte, 2+udpgwMaxMessageSize)
	for {
		if _, err := io.ReadFull(conn, buf[0:2]); err != nil {
			g.failAll(conn, err)
			return
		}
		size := int(binary.LittleEndian.Uint16(buf[0:2]))
		if size < 3 || size > udpgwMaxMessageSize {
			g.failAll(conn, errors.New("invalid UDPGW frame size"))
			return
		}
		if _, err := io.ReadFull(conn, buf[2:2+size]); err != nil {
			g.failAll(conn, err)
			return
		}
		flags := buf[2]
		if flags&udpgwFlagKeepalive != 0 {
			continue // the server never sends these today; tolerate anyway
		}
		addrLen := 4
		if flags&udpgwFlagIPv6 != 0 {
			addrLen = 16
		}
		// Envelope: flags(1) connID(2) ip(addrLen) port(2) payload...
		if size < 5+addrLen+12 {
			continue // not a DNS message; nothing to match, nothing to fail
		}
		payload := append([]byte(nil), buf[7+addrLen:2+size]...)
		txID := binary.BigEndian.Uint16(payload[0:2])

		g.mu.Lock()
		ch, ok := g.pending[txID]
		g.mu.Unlock()
		if !ok {
			continue // reply for an already-retired exchange (e.g. timed out)
		}
		select {
		case ch <- gwReply{payload: payload}:
		default:
		}
	}
}

// keepaliveLoop keeps the shared channel warm and detects silent deaths.
// Server-side keepalive frames are simply consumed, and an unwritable
// channel is torn down so the next exchange reconnects immediately.
func (g *udpgwGateway) keepaliveLoop() {
	ticker := time.NewTicker(udpgwKeepaliveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
		}
		g.mu.Lock()
		conn := g.conn
		g.mu.Unlock()
		if conn == nil {
			continue
		}
		frame := []byte{0x03, 0x00, udpgwFlagKeepalive, 0x00, 0x00} // size 3, flags keepalive, connID 0
		g.writeMu.Lock()
		_, err := conn.Write(frame)
		g.writeMu.Unlock()
		if err != nil {
			g.invalidate(conn)
		}
	}
}

func (g *udpgwGateway) invalidate(conn net.Conn) {
	g.mu.Lock()
	if g.conn == conn {
		g.conn = nil
	}
	g.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (g *udpgwGateway) drop(conn net.Conn) {
	g.invalidate(conn)
}

// failAll tears down a broken channel and fails every in-flight exchange so
// their callers retry on a fresh channel instead of waiting out the timeout.
func (g *udpgwGateway) failAll(conn net.Conn, cause error) {
	g.mu.Lock()
	if g.conn == conn {
		g.conn = nil
	}
	pending := g.pending
	g.pending = make(map[uint16]chan gwReply)
	g.mu.Unlock()
	_ = conn.Close()
	wrapped := fmt.Errorf("UDPGW reply: %w", cause)
	for _, ch := range pending {
		select {
		case ch <- gwReply{err: wrapped}:
		default:
		}
	}
}

func (g *udpgwGateway) close() {
	g.mu.Lock()
	conn := g.conn
	g.conn = nil
	pending := g.pending
	g.pending = make(map[uint16]chan gwReply)
	g.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	wrapped := errors.New("udpgw: gateway closed")
	for _, ch := range pending {
		select {
		case ch <- gwReply{err: wrapped}:
		default:
		}
	}
}

// Capture a per-start parent in each proxy. Cancellation closes DNS pipes,
// active gateway requests, including on failed starts.
// A retired proxy can never borrow the next session's lifetime.
var dnsContextMu sync.RWMutex
var dnsContext = context.Background()
var dnsCancel context.CancelFunc

func currentDNSContext() context.Context {
    dnsContextMu.RLock()
    defer dnsContextMu.RUnlock()
    return dnsContext
}

func startDNSContext() {
    dnsContextMu.Lock()
    defer dnsContextMu.Unlock()
    if dnsCancel != nil { dnsCancel() }
    dnsContext, dnsCancel = context.WithCancel(context.Background())
}

func stopDNSContext() {
    dnsContextMu.RLock()
    cancel := dnsCancel
    dnsContextMu.RUnlock()
    if cancel != nil { cancel() }
}

// parseSocks5 installs the FCAE-aware implementation under the standard
// SOCKS5 schema. Psiphon is selected with a query flag, not a second scheme.
func parseSocks5(u *url.URL) (proxy.Proxy, error) {
	return newSocks5Proxy(u)
}

func init() {
	proxy.RegisterProtocol(schemeSocks5, parseSocks5)
}

var (
	mu      sync.Mutex
	running bool

	// hostLogLevel caps which of the bridge's OWN diagnostics (the [bridge]/
	// [dns] lines emitted through emit()) reach the host logger, independent
	// of the zap level that filters tun2socks-core records. The default --
	// matching the configurable "tun2socks log" setting in both UIs -- is
	// errors only: a healthy session logs nothing from this bridge, and the
	// per-query DNS warnings only appear when the user opts into verbose
	// tun2socks logs.
	hostLogLevel = logError

	// logMu guards logFn and hostLogLevel and is DELIBERATELY separate from
	// mu.
	//
	// emit() is called from inside t2s_start/t2s_stop, which already hold mu.
	// Go's sync.Mutex is not reentrant, so guarding logFn with mu too meant
	// the very first emit() inside t2s_start deadlocked against its own
	// caller: the Go runtime blocked forever on a cgo thread, t2s_start never
	// returned, and the Rust side sat in fcae_start with the TUN fd dup'd but
	// no netstack -- exactly the "stops after 'using VpnService fd'" hang.
	logMu sync.Mutex
	logFn C.t2s_log_fn
)

// emit forwards a message to the host logger. Never panics if no callback is
// registered yet, never touches mu -- see the comment above -- and drops
// records above the configured host log level (default: errors only).
func emit(level int, format string, args ...any) {
	logMu.Lock()
	fn, gate := logFn, hostLogLevel
	logMu.Unlock()
	if fn == nil || level > gate {
		return
	}
	msg := fmt.Sprintf(format, args...)
	c := C.CString(msg)
	defer C.free(unsafe.Pointer(c))
	C.t2s_invoke_log(fn, C.int(level), c)
}

// setHostLogLevel maps a tun2socks log-level string onto the emit() gate.
// "silent" keeps error-level lines only; the zap logger installed by
// installNonFatalLogger separately silences tun2socks-core records.
func setHostLogLevel(level string) {
	gate := logError // "silent" and anything unrecognised
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		gate = logDebug
	case "info":
		gate = logInfo
	case "warn":
		gate = logWarn
	case "error":
		gate = logError
	}
	logMu.Lock()
	hostLogLevel = gate
	logMu.Unlock()
}

//export t2s_set_log_callback
//
// Register (or clear, with NULL) the host log sink.
func t2s_set_log_callback(fn C.t2s_log_fn) {
	logMu.Lock()
	logFn = fn
	logMu.Unlock()
}

// installNonFatalLogger routes tun2socks' global logger into emit() and makes
// Fatal records panic instead of calling os.Exit(1).
//
// Two reasons this exists:
//
//  1. A library must never exit the host process. engine.Stop() reports
//     failures with log.Fatalf, and zap's default fatal hook is
//     WriteThenFatal -> os.Exit(1), which would kill the VPN app on
//     disconnect. WriteThenPanic turns that into a recoverable panic.
//  2. Without it, tun2socks logs go to zap's production logger on stderr,
//     which on Android goes nowhere useful.
//
// NOTE: this can only be installed *after* engine.Start(). The first thing
// engine.start() does is general(), which calls log.SetLogger() with its own
// logger built from Key.LogLevel -- anything installed beforehand is
// discarded. That is why the start path relies on pre-validation instead.
func installNonFatalLogger(level string) {
	lvl, err := t2slog.ParseLevel(level)
	if err != nil {
		lvl = zapcore.InfoLevel
	}
	// SilentLevel is defined as InvalidLevel+1, i.e. ABOVE FatalLevel, so a
	// silent logger would filter the fatal record out before OnFatal ever
	// ran -- and zap would then exit anyway. Clamp so Fatal is always
	// enabled; ordinary records stay suppressed by the level check below.
	if lvl > zapcore.FatalLevel {
		lvl = zapcore.FatalLevel
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(hostWriter{}),
		lvl,
	)
	// OnFatal=WriteThenPanic converts zap's os.Exit into a panic the caller
	// can recover from.
	logger := zap.New(core, zap.OnFatal(zapcore.WriteThenPanic))

	t2slog.SetLogger(logger)
}

// hostWriter forwards zap output to the Rust log callback.
type hostWriter struct{}

func (hostWriter) Write(p []byte) (int, error) {
	emit(logInfo, "%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// validateKey checks everything engine.Start would otherwise reject.
//
// This matters more than it looks: upstream's engine.Start calls log.Fatalf on
// failure, which terminates the *whole process*. Acceptable for a standalone
// binary, fatal for an in-process library that a VPN GUI links. So we
// pre-validate here and refuse the call ourselves, leaving engine.Start only
// the cases it can actually handle.
// Values are canonical byte counts from the Rust config, not UI text.
// Validate before any device/FD is opened, including the direct Android path.
func tcpBufferOptions(k *engine.Key) ([]option.Option, error) {
    snd, err := strconv.Atoi(k.TCPSendBufferSize)
    if err != nil || snd < tcp.MinBufferSize || snd > tcp.MaxBufferSize {
        return nil, fmt.Errorf("invalid TCP send buffer %q (4096..4194304 bytes)", k.TCPSendBufferSize)
    }
    rcv, err := strconv.Atoi(k.TCPReceiveBufferSize)
    if err != nil || rcv < tcp.MinBufferSize || rcv > tcp.MaxBufferSize {
        return nil, fmt.Errorf("invalid TCP receive buffer %q (4096..4194304 bytes)", k.TCPReceiveBufferSize)
    }
    return []option.Option{
        option.WithTCPSendBufferSize(snd),
        option.WithTCPReceiveBufferSize(rcv),
        option.WithTCPModerateReceiveBuffer(k.TCPModerateReceiveBuffer),
    }, nil
}

func validateKey(k *engine.Key) error {
    if _, err := tcpBufferOptions(k); err != nil { return err }
	if strings.TrimSpace(k.Device) == "" {
		return errors.New("empty device")
	}
	if strings.TrimSpace(k.Proxy) == "" {
		return errors.New("empty proxy")
	}
	u, err := url.Parse(k.Proxy)
	if err != nil {
		return fmt.Errorf("invalid proxy url %q: %w", k.Proxy, err)
	}
	switch strings.ToLower(u.Scheme) {
	case schemeSocks5, "socks4", "socks4a", "http", "https", "ss", "relay", "direct", "reject":
	default:
		return fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Host == "" && u.Scheme != "direct" && u.Scheme != "reject" {
		return fmt.Errorf("proxy url %q has no host", k.Proxy)
	}
	if k.MTU < 0 || k.MTU > 65535 {
		return fmt.Errorf("mtu %d out of range", k.MTU)
	}

	// The device string is parsed by engine.parseDevice, whose failures also
	// reach log.Fatalf. Mirror its accepted drivers here so a typo returns -2
	// instead of taking the process down.
	dev := k.Device
	if !strings.Contains(dev, "://") {
		dev = "tun://" + dev
	}
	du, err := url.Parse(dev)
	if err != nil {
		return fmt.Errorf("invalid device url %q: %w", k.Device, err)
	}
	switch strings.ToLower(du.Scheme) {
	case "tun":
		if du.Host == "" {
			return fmt.Errorf("device %q has no interface name", k.Device)
		}
	case "fd":
		// fd://<n> -- the descriptor must be a plain non-negative integer, or
		// gvisor's fdbased.New fails deep inside the stack.
		n, convErr := strconv.Atoi(du.Host)
		if convErr != nil || n < 0 {
			return fmt.Errorf("device %q is not a valid fd", k.Device)
		}
	default:
		return fmt.Errorf("unsupported device driver %q", du.Scheme)
	}

	// log.ParseLevel is the very first thing engine.start() does, and it is
	// also on the Fatalf path.
	if _, err := t2slog.ParseLevel(k.LogLevel); err != nil {
		return fmt.Errorf("invalid log level %q", k.LogLevel)
	}
	return nil
}

// Bring the stack up.
//
//	device   - "tun://<name>", "tun://<name>?guid=..." on Windows, or "fd://<n>"
//	proxy    - e.g. "socks5://127.0.0.1:1819"
//	mtu      - 0 for the tun2socks default
//	loglevel - "debug" | "info" | "warn" | "error" | "silent" (default: silent)
//	tcpSndbuf/tcpRcvbuf - TCP defaults in bytes (4096..4194304 bytes)
//	tcpAutoTuning - 0 disables, nonzero enables receive-buffer auto-tuning
//
// Returns 0 on success, or a negative error code:
//
//	-1 already running
//	-2 invalid argument
//	-3 engine failed to start
//
// For supplied descriptors, keep device ownership explicit instead of hiding
// it inside engine's globals. The pinned FD.Close closes the numeric fd.
// Rust relinquishes it on success or -4; on other errors Rust still owns it.
var fdDevice device.Device
var fdStack *stack.Stack

func startFD(k *engine.Key) error {
    options, err := tcpBufferOptions(k)
    if err != nil { return err }
    u, err := url.Parse(k.Proxy)
    if err != nil { return err }
    p, err := proxy.Parse(u)
    if err != nil { return err }
    dialer.Reset()
    tunnel.T().SetUDPTimeout(k.UDPTimeout)
    tunnel.T().SetProxy(p)
    installNonFatalLogger(k.LogLevel)
    d, err := url.Parse(k.Device)
    if err != nil { return err }
    offset := 0
    if runtime.GOOS == "darwin" || runtime.GOOS == "ios" { offset = 4 }
    fdDevice, err = fdbased.Open(d.Host, uint32(k.MTU), offset)
    if err != nil { return err } // FD.Open only takes ownership on success
    fdStack, err = core.CreateStack(&core.Config{
        LinkEndpoint: fdDevice,
        TransportHandler: tunnel.T(),
        Options: options,
    })
    return err
}

func stopFD() {
    d, s := fdDevice, fdStack
    fdDevice, fdStack = nil, nil
    if d != nil { d.Close() }
    if s != nil { s.Close(); s.Wait() }
}

//export t2s_start
func t2s_start(device *C.char, proxy *C.char, mtu C.int, loglevel *C.char,
    tcpSndbuf C.uint32_t, tcpRcvbuf C.uint32_t, tcpAutoTuning C.int) C.int {
	mu.Lock()
	defer mu.Unlock()

	if running {
		emit(logWarn, "[bridge] start ignored: already running")
		return -1
	}

	key := &engine.Key{
		Device:   C.GoString(device),
		Proxy:    C.GoString(proxy),
		MTU:      int(mtu),
		LogLevel: C.GoString(loglevel),
        TCPSendBufferSize: strconv.FormatUint(uint64(tcpSndbuf), 10),
        TCPReceiveBufferSize: strconv.FormatUint(uint64(tcpRcvbuf), 10),
        TCPModerateReceiveBuffer: tcpAutoTuning != 0,
		// Expire idle UDP flows quicker than the 60s default so the NAT
		// table (and any parked goroutines) drains promptly.
		UDPTimeout: 30 * time.Second,
	}
	// The bridge's own diagnostics default to silent: the configurable
	// "tun2socks log" UI setting feeds this value; an empty string keeps
	// the quiet default instead of the old "info" chatter.
	if key.LogLevel == "" {
		key.LogLevel = "silent"
	}
	// Gate emit() before anything can log, including the validation errors
	// below, so the chosen level covers every bridge message.
	setHostLogLevel(key.LogLevel)

	if err := validateKey(key); err != nil {
		emit(logError, "[bridge] invalid configuration: %v", err)
		return -2
	}

	// engine.Start() reports failure with log.Fatalf, and zap's Fatal hook
	// calls os.Exit(1) -- it does NOT panic, so the recover() below cannot
	// catch it, and a logger installed here would be thrown away by
	// general() anyway (see installNonFatalLogger). validateKey() above is
	// therefore the real protection: it rejects everything engine.start()
	// would reject, so the Fatalf path stays unreachable in practice.
    startDNSContext()
	var startErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				startErr = fmt.Errorf("engine.Start failed: %v", r)
			}
		}()
        if strings.HasPrefix(key.Device, "fd://") {
            startErr = startFD(key)
        } else {
            engine.Insert(key)
            startErr = engine.Start() // pinned API returns errors; do not ignore them
        }
	}()

    if startErr != nil {
        stopDNSContext()
        emit(logError, "[bridge] %v", startErr)
        consumedFD := fdDevice != nil
        func() {
            defer func() { _ = recover() }()
            if strings.HasPrefix(key.Device, "fd://") { stopFD() } else { _ = engine.Stop() }
        }()
        if consumedFD { return -4 } // already closed by Go; MUST NOT close again in Rust
        return -3
    }

	// Now that general() has installed its own logger, replace it with ours:
	// runtime logs reach the host, and a Fatalf during Stop panics (which
	// t2s_stop recovers) instead of killing the process.
	installNonFatalLogger(key.LogLevel)

	running = true
	emit(logInfo, "[bridge] tun2socks running in-process: %s <-> %s", key.Device, key.Proxy)
	return 0
}

//export t2s_stop
//
// Tear the stack down. Idempotent; returns 0 on success.
func t2s_stop() C.int {
	mu.Lock()
	defer mu.Unlock()

	if !running {
		return 0
	}
    stopDNSContext()
	func() {
		defer func() {
			if r := recover(); r != nil {
				emit(logWarn, "[bridge] panic during stop (ignored): %v", r)
			}
		}()
        if fdDevice != nil { stopFD() } else { _ = engine.Stop() }
	}()
	running = false
	emit(logInfo, "[bridge] tun2socks stopped")
	return 0
}

//export t2s_is_running
func t2s_is_running() C.int {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return 1
	}
	return 0
}

//export t2s_version
//
// Returns a static, caller-must-not-free string identifying the bridge ABI.
func t2s_version() *C.char {
	return versionString
}

// Allocated once at init so the pointer stays valid forever and the caller
// never has to free it.
var versionString = C.CString("fcae-bridge-tun2socks-bridge/1 (in-process)")

func main() {}
