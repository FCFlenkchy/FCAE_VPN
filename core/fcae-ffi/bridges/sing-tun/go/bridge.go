//go:build fcae_sing_tun

package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*mtun_log_fn)(int, const char*);
static void mtun_emit_log(mtun_log_fn fn, int level, const char* text) { if(fn) fn(level,text); }
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
static int mtun_dup_fd(int fd) { return fcntl(fd,F_DUPFD_CLOEXEC,3); }
static void mtun_close_fd(int fd) { close(fd); }
#else
static int mtun_dup_fd(int fd) { return -1; }
static void mtun_close_fd(int fd) {}
#endif
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/udpnat"
	"github.com/metacubex/sing/protocol/socks"
)

type mtunCore struct {
	cancel  context.CancelFunc
	device  tun.Tun
	stack   tun.Stack
	handler *mtunHandler
	routing mtunAppRouter
}

func (c *mtunCore) close() {
	c.cancel()
	if c.handler != nil {
		c.handler.close()
	}
	// Detach the stack before releasing its device. The Unix gVisor endpoint
	// stops and joins its FD readers on detach; closing the FD first can let
	// those readers observe a reused descriptor. Wintun detach is nonblocking,
	// and closing the device below wakes its outstanding read.
	if c.stack != nil {
		_ = c.stack.Close()
	}
	if c.device != nil {
		_ = c.device.Close()
	}
	if c.routing != nil {
		_ = c.routing.Close()
	}
}

var mtunLogMu sync.RWMutex
var mtunLog C.mtun_log_fn
var mtunLogGate = 1

//export mtun_set_log
func mtun_set_log(sink C.mtun_log_fn, gate C.int) {
	mtunLogMu.Lock()
	mtunLog, mtunLogGate = sink, int(gate)
	mtunLogMu.Unlock()
}
func mtunLogf(level int, format string, args ...any) {
	mtunLogMu.RLock()
	sink, gate := mtunLog, mtunLogGate
	mtunLogMu.RUnlock()
	if sink == nil || level > gate {
		return
	}
	text := C.CString(fmt.Sprintf(format, args...))
	defer C.free(unsafe.Pointer(text))
	C.mtun_emit_log(sink, C.int(level), text)
}

func mtunLogGateForSetting(level int) (int, bool) {
	switch level {
	case 0, 1, 2:
		return 1, true // default/silent and error: keep only failure diagnostics
	case 3:
		return 2, true
	case 4:
		return 3, true
	case 5:
		return 4, true
	default:
		return 0, false
	}
}

var mtunMu sync.Mutex
var mtunNext uint64

// Invalidate starts already in progress when stop-all is requested.
var mtunGeneration uint64
var mtunCores = make(map[uint64]*mtunCore)

//export mtun_start
func mtun_start(text *C.char, handle *C.uint64_t) (result *C.char) {
	if text == nil || handle == nil {
		return C.CString("missing sing-tun start arguments")
	}
	*handle = 0
	mtunLogf(3, "startup entered (%s/%s)", runtime.GOOS, runtime.GOARCH)
	var cfg struct {
		Name      string          `json:"name"`
		MTU       uint32          `json:"mtu"`
		Addresses []string        `json:"addresses"`
		Socks     string          `json:"socks"`
		UDP       bool            `json:"udp"`
		FD            *int            `json:"fd"`
		Routing       json.RawMessage `json:"routing"`
		TunLogLevel   int             `json:"fcae-tun-log-level"`
	}
	if err := json.Unmarshal([]byte(C.GoString(text)), &cfg); err != nil {
		return C.CString(err.Error())
	}
	gate, validLogLevel := mtunLogGateForSetting(cfg.TunLogLevel)
	if !validLogLevel {
		return C.CString("sing-tun TUN log level must be 0..5")
	}
	mtunLogMu.Lock()
	mtunLogGate = gate
	mtunLogMu.Unlock()
	mtunLogf(3, "startup entered (%s/%s)", runtime.GOOS, runtime.GOARCH)
	socksAddr, err := netip.ParseAddrPort(cfg.Socks)
	if err != nil || !socksAddr.Addr().IsLoopback() || socksAddr.Port() == 0 {
		return C.CString("sing-tun requires the session's loopback SOCKS exit")
	}
	if cfg.MTU < 1280 || cfg.MTU > 9000 || len(cfg.Name) == 0 || len(cfg.Name) > 64 {
		return C.CString("invalid sing-tun interface settings")
	}
	options := tun.Options{Name: cfg.Name, MTU: cfg.MTU, DNSMode: tun.DNSModeDisabled, AutoRoute: false}
	for _, address := range cfg.Addresses {
		prefix, e := netip.ParsePrefix(address)
		if e != nil {
			return C.CString(e.Error())
		}
		if prefix.Addr().Is4() {
			options.Inet4Address = append(options.Inet4Address, prefix)
		} else {
			options.Inet6Address = append(options.Inet6Address, prefix)
		}
	}
	if len(options.Inet4Address) != 1 {
		return C.CString("sing-tun needs one IPv4 interface address")
	}
	mobile := runtime.GOOS == "android" || runtime.GOOS == "ios"
	if mobile && (cfg.FD == nil || *cfg.FD < 0) {
		return C.CString("sing-tun requires the mobile VPN host's packet descriptor")
	}
	if cfg.FD != nil && !mobile {
		return C.CString("external sing-tun descriptors are mobile-only")
	}
	mtunMu.Lock()
	generation := mtunGeneration
	mtunMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	core := &mtunCore{cancel: cancel}
	owned := false
	defer func() {
		if failure := recover(); failure != nil {
			mtunLogf(1, "startup panic: %v\n%s", failure, debug.Stack())
			result = C.CString(fmt.Sprintf("sing-tun startup panic: %v", failure))
		}
		if result != nil {
			mtunLogf(1, "startup failed: %s", C.GoString(result))
		}
		if !owned {
			core.close()
		}
	}()
	if len(cfg.Routing) > 0 && string(cfg.Routing) != "null" {
		if mobile {
			return C.CString("desktop app routing is not available on a mobile descriptor")
		}
		core.routing, err = mtunNewAppRouter(ctx, cfg.Routing)
		if err != nil {
			return C.CString("sing-tun app router: " + err.Error())
		}
	}
	if mobile {
		fd := int(C.mtun_dup_fd(C.int(*cfg.FD)))
		if fd < 0 {
			return C.CString("cannot duplicate the system VPN descriptor")
		}
		options.FileDescriptor = fd
	}
	mtunLogf(3, "creating TUN interface %s", cfg.Name)
	core.device, err = tun.New(options)
	if err != nil {
		if mobile {
			C.mtun_close_fd(C.int(options.FileDescriptor))
		}
		return C.CString("sing-tun interface: " + err.Error())
	}
	handler := &mtunHandler{ctx: ctx, socks: M.SocksaddrFromNetIP(socksAddr), udp: cfg.UDP, active: make(map[io.Closer]struct{}), routing: core.routing}
	handler.nat = udpnat.New[netip.AddrPort](120, handler)
	core.handler = handler
	mtunLogf(3, "interface created; initializing gVisor")
	core.stack, err = tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: core.device, TunOptions: options, Handler: handler, Logger: logger.NOP(), UDPTimeout: 120 * time.Second, ICMPTimeout: 10 * time.Second})
	if err != nil {
		return C.CString("sing-tun stack: " + err.Error())
	}
	mtunLogf(3, "starting packet stack")
	if err = core.stack.Start(); err != nil {
		return C.CString("sing-tun stack start: " + err.Error())
	}
	mtunMu.Lock()
	if generation != mtunGeneration {
		mtunMu.Unlock()
		return C.CString("sing-tun startup cancelled")
	}
	mtunNext++
	id := mtunNext
	mtunCores[id] = core
	engineStarted(engineMetaTun)
	owned = true
	mtunMu.Unlock()
	*handle = C.uint64_t(id)
	mtunLogf(3, "packet engine started (handle %d)", id)
	return nil
}

//export mtun_stop
func mtun_stop(id C.uint64_t) {
	mtunMu.Lock()
	core := mtunCores[uint64(id)]
	delete(mtunCores, uint64(id))
	mtunMu.Unlock()
	if core != nil {
		core.close()
		engineStopped(engineMetaTun)
	}
}

//export mtun_stop_all
func mtun_stop_all() {
	mtunMu.Lock()
	mtunGeneration++
	cores := mtunCores
	mtunCores = make(map[uint64]*mtunCore)
	mtunMu.Unlock()
	for _, core := range cores {
		core.close()
		engineStopped(engineMetaTun)
	}
}

//export mtun_running
func mtun_running(id C.uint64_t) C.int {
	mtunMu.Lock()
	core := mtunCores[uint64(id)]
	mtunMu.Unlock()
	return mtunHealth(core)
}

func mtunHealth(core *mtunCore) C.int {
	if core != nil && core.handler.ctx.Err() == nil {
		if health, ok := core.device.(interface{ PacketReadError() error }); ok {
			if err := health.PacketReadError(); err != nil {
				mtunLogf(1, "Wintun packet reader stopped: %v", err)
				core.cancel()
				return 0
			}
		}
		return 1
	}
	return 0
}

//export mtun_string_free
func mtun_string_free(message *C.char) { C.free(unsafe.Pointer(message)) }

type mtunAppRouter interface {
	RouteTCP(context.Context, net.Conn, M.Metadata) error
	RouteUDP(context.Context, N.PacketConn, M.Metadata) error
	Close() error
}

type mtunHandler struct {
	routing mtunAppRouter
	ctx     context.Context
	socks   M.Socksaddr
	udp     bool
	nat     *udpnat.Service[netip.AddrPort]
	mu      sync.Mutex
	active  map[io.Closer]struct{}
}

func (h *mtunHandler) add(c io.Closer) bool {
	h.mu.Lock()
	if h.ctx.Err() != nil {
		h.mu.Unlock()
		_ = c.Close()
		return false
	}
	h.active[c] = struct{}{}
	h.mu.Unlock()
	return true
}
func (h *mtunHandler) remove(c io.Closer) { h.mu.Lock(); delete(h.active, c); h.mu.Unlock() }
func (h *mtunHandler) close() {
	h.mu.Lock()
	active := h.active
	h.active = make(map[io.Closer]struct{})
	h.mu.Unlock()
	for c := range active {
		_ = c.Close()
	}
}
func (h *mtunHandler) NewError(_ context.Context, err error) {
	if err != nil && h.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		mtunLogf(4, "packet forwarding: %v", err)
	}
}
func (h *mtunHandler) PrepareConnection(network string, _ M.Socksaddr, _ M.Socksaddr, _ tun.DirectRouteContext, _ time.Duration) (tun.DirectRouteDestination, error) {
	// SOCKS carries TCP/UDP only. Never turn unsupported traffic into DIRECT.
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, tun.ErrDrop
	}
	return nil, nil
}
func (h *mtunHandler) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) (result error) {
	defer func() {
		if result != nil {
			h.NewError(h.ctx, fmt.Errorf("TCP %s: %w", metadata.Destination, result))
		}
	}()
	if !h.add(conn) {
		return net.ErrClosed
	}
	defer func() { h.remove(conn); _ = conn.Close() }()
	if h.routing != nil {
		return h.routing.RouteTCP(h.ctx, conn, metadata)
	}
	dialer := &mtunDialer{handler: h}
	client := socks.NewClient(dialer, h.socks, socks.Version5, "", "")
	remote, err := client.DialContext(h.ctx, "tcp", metadata.Destination)
	dialer.finish(err != nil)
	if err != nil {
		return err
	}
	defer remote.Close()
	return bufio.CopyConn(h.ctx, conn, remote)
}
func (h *mtunHandler) NewPacket(_ context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	if !h.udp || h.ctx.Err() != nil {
		buffer.Release()
		return
	}
	h.nat.NewPacket(h.ctx, key, buffer, metadata, init)
}
func (h *mtunHandler) NewPacketConnection(_ context.Context, conn N.PacketConn, metadata M.Metadata) (result error) {
	defer func() {
		if result != nil {
			h.NewError(h.ctx, fmt.Errorf("UDP %s: %w", metadata.Destination, result))
		}
	}()
	if !h.udp {
		_ = conn.Close()
		return fmt.Errorf("the session exit does not carry UDP")
	}
	if !h.add(conn) {
		return net.ErrClosed
	}
	defer func() { h.remove(conn); _ = conn.Close() }()
	if h.routing != nil {
		return h.routing.RouteUDP(h.ctx, conn, metadata)
	}
	dialer := &mtunDialer{handler: h}
	client := socks.NewClient(dialer, h.socks, socks.Version5, "", "")
	remote, err := client.ListenPacket(h.ctx, metadata.Destination)
	dialer.finish(err != nil)
	if err != nil {
		return err
	}
	defer remote.Close()
	outbound := bufio.NewPacketConn(remote)
	touch := func() {
		deadline := time.Now().Add(120 * time.Second)
		_ = conn.SetReadDeadline(deadline)
		_ = outbound.SetReadDeadline(deadline)
	}
	touch()
	return bufio.CopyPacketConn(h.ctx, &mtunIdlePacket{conn, touch}, &mtunIdlePacket{outbound, touch})
}

type mtunIdlePacket struct {
	N.PacketConn
	touch func()
}

// CopyPacket allocates buffers based on the writer's headroom interfaces.
// Forward these through the idle wrapper: SOCKS UDP must prepend its header.
// Do not expose Upstream, which could let the copier bypass deadline updates.
func (p *mtunIdlePacket) FrontHeadroom() int { return N.CalculateFrontHeadroom(p.PacketConn) }
func (p *mtunIdlePacket) RearHeadroom() int  { return N.CalculateRearHeadroom(p.PacketConn) }

func (p *mtunIdlePacket) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	p.touch()
	return p.PacketConn.WritePacket(buffer, destination)
}

// Track even SOCKS handshake sockets: cancellation must unblock handshakes and
// UDP control connections, not just already established application streams.
type mtunTrackedConn struct {
	net.Conn
	owner *mtunHandler
	once  sync.Once
}

func (c *mtunTrackedConn) Close() error {
	var err error
	c.once.Do(func() { c.owner.remove(c); err = c.Conn.Close() })
	return err
}

type mtunDialer struct {
	handler     *mtunHandler
	connections []net.Conn
}

func (d *mtunDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.Addr.IsUnspecified() {
		destination.Addr = d.handler.socks.Addr
	}
	if !destination.Addr.IsLoopback() {
		return nil, fmt.Errorf("sing-tun SOCKS relay must remain on loopback")
	}
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	conn := &mtunTrackedConn{Conn: raw, owner: d.handler}
	if !d.handler.add(conn) {
		return nil, net.ErrClosed
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	d.connections = append(d.connections, conn)
	return conn, nil
}
func (d *mtunDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("direct UDP sockets are disabled")
}
func (d *mtunDialer) finish(failed bool) {
	for _, conn := range d.connections {
		if failed {
			_ = conn.Close()
		} else {
			_ = conn.SetDeadline(time.Time{})
		}
	}
}
