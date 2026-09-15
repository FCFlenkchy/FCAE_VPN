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
	"bytes"
	"crypto/tls"
	"net/http"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"net"
	"net/netip"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/socks5" // registers the "socks5" scheme
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	logError = 1
	logWarn  = 2
	logInfo  = 3
	logDebug = 4
)

// The plain "socks5" scheme speaks the full protocol, including the UDP
// ASSOCIATE command (0x03). Upstreams that are CONNECT-only -- Psiphon's local
// proxy is the one that matters here -- reject every 0x03 with a log line, so
// every app that sends a single DNS or QUIC packet floods the tunnel log with
// "SOCKS message field command was 0x03, not 0x01" noise. Backends like that
// therefore get endpoints with udp=false and the Rust layer hands tun2socks a
// "socks5t://" URL instead: same SOCKS5 handshake for TCP, while UDP flows are
// absorbed locally in silence (the user-visible behaviour of a network with
// no UDP route) instead of provoking per-flow errors upstream.
const (
	schemeSocks5  = "socks5"
	schemeSocks5t = "socks5t"
	schemePsiphon = "socks5p" // CONNECT-only, DNS via tunneled HTTPS/443
)

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

// udpDroppingProxy wraps a SOCKS5 proxy and replaces its UDP path with a
// silent blackhole -- except port 53: DNS queries are answered by relaying
// them as DNS-over-TCP through the upstream CONNECT, so system DNS keeps
// working on egresses that cannot carry UDP (every Tor mode, Psiphon's
// CONNECT-only proxy). Without this a TUN session in Tor-only mode leaves
// the whole device unable to resolve anything.
type udpDroppingProxy struct {
	proxy.Proxy
	doh bool
}

func (p udpDroppingProxy) DialUDP(m *metadata.Metadata) (net.PacketConn, error) {
	if m.DstPort == 53 && m.DstIP.IsValid() {
		ctx, cancel := context.WithCancel(context.Background())
		return &dnsRelayConn{
			doh: p.doh, ctx: ctx, cancel: cancel, pending: make(chan struct{}, 4),
			inner:   p.Proxy,
			resolver: m.DstIP,
			replies: make(chan dnsReply, 8),
			done:    make(chan struct{}),
		}, nil
	}
	return &blackholeConn{done: make(chan struct{})}, nil
}

// dnsRelayTimeout bounds one tunneled DNS exchange. A warmed Tor circuit
// answers in ~1s; 8s leaves margin for a fresh one without parking a
// goroutine forever when the egress is truly gone.
const dnsRelayTimeout = 8 * time.Second

// dnsReply is one completed DNS-over-TCP answer plus the address it must be
// reported from (the queried resolver -- apps match src+ID).
type dnsReply struct {
	payload []byte
	src     net.Addr
	err     error
}

// dnsRelayConn is the PacketConn handed to one UDP flow whose destination is
// a resolver. The wire format of a DNS message is identical over UDP and
// TCP (length-prefixed) or HTTPS (application/dns-message). Replies retain
// the original query ID and appear to come from the intercepted resolver.
type dnsRelayConn struct {
	doh bool
	ctx context.Context
	cancel context.CancelFunc
	pending chan struct{}
	inner   proxy.Proxy
	resolver netip.Addr // flow destination; every WriteTo is expected to match
	replies chan dnsReply
	done    chan struct{}
	once    sync.Once
}

func (c *dnsRelayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || len(p) < 12 || len(p) > 0xffff || p[2]&0x80 != 0 {
		// Swallow silently like the blackhole: never inject errors into the
		// NAT loop for traffic we deliberately refuse to carry.
		return len(p), nil
	}
	// Each query gets its own exchange goroutine; apps de-multiplex by the
	// DNS header ID, so reply order is irrelevant and bursts cannot block
	// the stack's NAT goroutine.
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case c.pending <- struct{}{}:
	default:
		return len(p), nil // bound work; resolver retries if overloaded
	}
	payload := append([]byte(nil), p...)
	go func() {
		defer func() { <-c.pending }()
		var resp []byte
		var err error
		if c.doh { resp, err = c.dnsOverHTTPS(payload) } else { resp, err = c.dnsOverTCP(payload, udpAddr) }
		if err != nil {
			// A failed query is not a fatal UDP-association error. Return SERVFAIL
			// so the OS can retry instead of destroying the entire DNS flow.
			resp = append([]byte(nil), payload...)
			resp[2] = (resp[2] & 0x79) | 0x80
			resp[3] = 0x82
			// Preserve the question and any EDNS OPT record from the query.
			err = nil
		}
		select {
		case c.replies <- dnsReply{payload: resp, src: udpAddr, err: err}:
		case <-c.done:
		}
	}()
	return len(p), nil
}

// dnsOverTCP dials the resolver through the upstream proxy (plain SOCKS5
// CONNECT by IP -- spoken by the tor and aether socks servers; tor exits
// allow tcp/53) and shuttles one query/answer pair.
func (c *dnsRelayConn) dnsOverTCP(query []byte, dst *net.UDPAddr) ([]byte, error) {
	resolver := c.resolver
	if dstIP, ok := netip.AddrFromSlice(dst.IP); ok {
		resolver = dstIP // use the packet's own resolver (1.1.1.1, ::1111, ...)
	}
	md := &metadata.Metadata{
		Network: metadata.TCP,
		DstIP:   resolver,
		DstPort: 53,
	}
	ctx, cancel := context.WithTimeout(c.ctx, dnsRelayTimeout)
	defer cancel()
	conn, err := c.inner.DialContext(ctx, md)
	if err != nil {
		return nil, fmt.Errorf("dns: connect %s: %w", resolver, err)
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(dnsRelayTimeout))

	frame := make([]byte, 2, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)
	if _, err := io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return nil, fmt.Errorf("dns: write: %w", err)
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("dns: read header: %w", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 12 {
		return nil, fmt.Errorf("dns: unexpected reply length %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("dns: read body: %w", err)
	}
	return resp, nil
}

func (c *dnsRelayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case r := <-c.replies:
		if r.err != nil {
			return 0, nil, r.err
		}
		if len(r.payload) > len(p) {
			return 0, nil, io.ErrShortBuffer
		}
		return copy(p, r.payload), r.src, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-time.After(dnsRelayTimeout):
		return 0, nil, errors.New("dns: no answer within " + dnsRelayTimeout.String())
	}
}

func (c *dnsRelayConn) Close() error {
	c.once.Do(func() { c.cancel(); close(c.done) })
	return nil
}

func (c *dnsRelayConn) LocalAddr() net.Addr              { return nil }
func (c *dnsRelayConn) SetDeadline(time.Time) error      { return nil }
func (c *dnsRelayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dnsRelayConn) SetWriteDeadline(time.Time) error { return nil }

// Psiphon exits need not permit TCP/53. Send wire-format DNS inside HTTPS
// through the SAME SOCKS exit, preserving the original DNS ID and response.
// The fixed bootstrap IP avoids both local DNS and a DNS bootstrap loop.
// TLS verifies cloudflare-dns.com; redirects and environment proxies are off.
func (c *dnsRelayConn) dnsOverHTTPS(query []byte) ([]byte, error) {
    ctx, cancel := context.WithTimeout(c.ctx, dnsRelayTimeout)
    defer cancel()
    transport := &http.Transport{
        Proxy: nil,
        MaxResponseHeaderBytes: 64 * 1024,
        TLSClientConfig: &tls.Config{ServerName: "cloudflare-dns.com", MinVersion: tls.VersionTLS12},
        DisableKeepAlives: true,
        DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
            if address != "cloudflare-dns.com:443" { return nil, fmt.Errorf("unexpected DoH destination: %s", address) }
            return c.inner.DialContext(ctx, &metadata.Metadata{
                Network: metadata.TCP, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443,
            })
        },
    }
    defer transport.CloseIdleConnections()
    client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
    request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
    if err != nil { return nil, err }
    request.Header.Set("Content-Type", "application/dns-message")
    request.Header.Set("Accept", "application/dns-message")
    response, err := client.Do(request)
    if err != nil { return nil, err }
    defer response.Body.Close()
    if response.StatusCode != http.StatusOK || !strings.EqualFold(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]), "application/dns-message") {
        return nil, fmt.Errorf("dns: unexpected DoH response %s", response.Status)
    }
    answer, err := io.ReadAll(io.LimitReader(response.Body, 65536))
    if err != nil { return nil, err }
    if len(answer) < 12 || len(answer) > 65535 || !bytes.Equal(answer[:2], query[:2]) || answer[2]&0x80 == 0 {
        return nil, errors.New("dns: invalid DoH reply")
    }
    return answer, nil
}

// parseSocks5t reuses the upstream socks5 parser (its init registers only the
// "socks5" scheme) by rewriting the scheme on the incoming URL.
func parseSocks5t(u *url.URL) (proxy.Proxy, error) {
	doh := u.Scheme == schemePsiphon
	u.Scheme = schemeSocks5
	inner, err := proxy.Parse(u)
	if err != nil {
		return nil, err
	}
	return udpDroppingProxy{Proxy: inner, doh: doh}, nil
}

func init() {
	proxy.RegisterProtocol(schemeSocks5t, parseSocks5t)
	proxy.RegisterProtocol(schemePsiphon, parseSocks5t)
}

var (
	mu      sync.Mutex
	running bool

	// logMu guards logFn and is DELIBERATELY separate from mu.
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
// registered yet, and never touches mu -- see the comment above.
func emit(level int, format string, args ...any) {
	logMu.Lock()
	fn := logFn
	logMu.Unlock()
	if fn == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	c := C.CString(msg)
	defer C.free(unsafe.Pointer(c))
	C.t2s_invoke_log(fn, C.int(level), c)
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
func validateKey(k *engine.Key) error {
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
	case schemeSocks5, schemeSocks5t, "socks4", "socks4a", "http", "https", "ss", "relay", "direct", "reject":
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
//	loglevel - "debug" | "info" | "warn" | "error" | "silent"
//
// Returns 0 on success, or a negative error code:
//
//	-1 already running
//	-2 invalid argument
//	-3 engine failed to start
//
//export t2s_start
func t2s_start(device *C.char, proxy *C.char, mtu C.int, loglevel *C.char) C.int {
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
		// Expire idle UDP flows quicker than the 60s default so the NAT
		// table (and any parked goroutines) drains promptly.
		UDPTimeout: 30 * time.Second,
	}
	if key.LogLevel == "" {
		key.LogLevel = "info"
	}

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
	var startErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				startErr = fmt.Errorf("engine.Start failed: %v", r)
			}
		}()
		engine.Insert(key)
		engine.Start()
	}()

	if startErr != nil {
		emit(logError, "[bridge] %v", startErr)
		// Leave nothing half-initialised behind.
		func() {
			defer func() { _ = recover() }()
			engine.Stop()
		}()
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
	func() {
		defer func() {
			if r := recover(); r != nil {
				emit(logWarn, "[bridge] panic during stop (ignored): %v", r)
			}
		}()
		engine.Stop()
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
