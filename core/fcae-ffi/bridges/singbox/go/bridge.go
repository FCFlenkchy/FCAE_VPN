//go:build fcae_singbox

// sing-box shim, compiled into the app's single Go archive.
//
// Same package as tun2socks, Psiphon and Xray-core: Go's linker keeps one copy
// of everything they share. The `fcae_singbox` build tag is set only when the
// Cargo feature is on, so a build without sing-box links no sing-box code.
// sing-box's own gVisor fork is a different module path from the one Xray-core
// and tun2socks use, so both netstack forks coexist in the one runtime.
//
// There is no `sing-box` executable, no config file on disk and no subprocess.
//
// Log lines and byte totals leave through the prefixed entry points below
// instead of the process's stderr and a discarded connection tracker.
package main

/*
#include <stdint.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
static int sb_dup_mobile_fd(int fd) { return fcntl(fd,F_DUPFD_CLOEXEC,3); }
#else
static int sb_dup_mobile_fd(int fd) { return -1; }
#endif

// Host log sink, implemented on the Rust side; see bridges/singbox/src/lib.rs.
// Declared here so cgo lets Go call back into the host.
typedef void (*sb_log_fn)(int level, const char *msg);

static void sb_invoke_log(sb_log_fn fn, int level, const char *msg) {
	if (fn != NULL) {
		fn(level, msg);
	}
}
*/
import "C"

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"unsafe"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	sbendpoint "github.com/sagernet/sing-box/adapter/endpoint"
	sbinbound "github.com/sagernet/sing-box/adapter/inbound"
	sboutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/include"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

// Host log levels: the scale the Rust sink maps onto the app logger (see
// `forward_log` in fcae_runtime::sing_xray). The shims all land in one package,
// so each core prefixes its own.
const (
	sbLogError = 1
	sbLogWarn  = 2
	sbLogInfo  = 3
	sbLogDebug = 4
)

// sbCore is one running instance and the router tracker behind its byte totals.
//
// A session can chain sing-box to sing-box -- two saved configs, two hops -- and
// this shim hosts both. One slot for the process meant the second hop was
// refused with "a core is already running", so instances are kept in a registry
// and every entry point carries the handle a start handed back.
type sbCore struct {
	ctx    context.Context
	box    *box.Box
	cancel context.CancelFunc
	// The synthetic DNS-routing stage has a valid box/service context, but it
	// is not the configured session core. A desktop TUN must not attach to it.
	tunAttachable bool
	// Nil only if the tracker could not be attached; the core then reports no
	// traffic totals.
	traffic *trafficcontrol.Manager
	// The inbounds this instance actually runs, read from the config the box
	// was handed: a saved config declares its own ports and a chain runs one
	// instance per hop, so the settings' single number is not the answer to
	// "what is listening".
	listeners []coreListener
	// What this config calls itself -- `vless reality` -- so a session running
	// two instances of this core names each of them instead of numbering them.
	label string
}

// sbInbounds reads every inbound of a sing-box config, in the order the config
// lists them.
//
// The fields every version agrees on, and nothing else: an unknown type or a
// listener inherited from a shared object still reports what it can, and an
// inbound without a listen_port is not a TCP listener this app can name.
//
// The standard library's json is named explicitly: this file also imports
// sing's own `common/json`, which is a different decoder and must not be used
// to read a field list.
func sbInbounds(text string) []coreListener {
	var cfg struct {
		Inbounds []struct {
			Type       string             `json:"type"`
			Listen     stdjson.RawMessage `json:"listen"`
			ListenPort stdjson.RawMessage `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := stdjson.Unmarshal([]byte(text), &cfg); err != nil {
		return nil
	}
	out := make([]coreListener, 0, len(cfg.Inbounds))
	for _, inbound := range cfg.Inbounds {
		if port := coreConfigPort(inbound.ListenPort); port > 0 {
			out = append(out, coreListener{
				proto: coreConfigName(inbound.Type),
				port:  port,
				any:   coreConfigScope(inbound.Listen),
			})
		}
	}
	return out
}

// sbFlavor is the config's first real outbound and the transport carrying it:
// the vocabulary a share link uses, so `vless reality` on screen names the same
// thing the link the user pasted named.
//
// The first outbound that is not an engine built-in is the one the route ends
// in. `tls` is read for both of its spellings, because sing-box reports a
// Reality server as TLS with the Reality block switched on.
func sbFlavor(text string) string {
	var cfg struct {
		Outbounds []struct {
			Type      string `json:"type"`
			Transport struct {
				Type string `json:"type"`
			} `json:"transport"`
			TLS struct {
				Enabled bool `json:"enabled"`
				Reality struct {
					Enabled bool `json:"enabled"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := stdjson.Unmarshal([]byte(text), &cfg); err != nil {
		return ""
	}
	for _, outbound := range cfg.Outbounds {
		switch strings.ToLower(strings.TrimSpace(outbound.Type)) {
		case "", "direct", "block", "dns":
			continue
		}
		security := ""
		if outbound.TLS.Reality.Enabled {
			security = "reality"
		} else if outbound.TLS.Enabled {
			security = "tls"
		}
		return coreTransportWords(outbound.Type, outbound.Transport.Type, security)
	}
	return ""
}

var (
	sbMu     sync.Mutex
	sbCores  = make(map[uint64]*sbCore)
	sbNextID uint64

	// sbLogMu guards the host sink and its level gate, and is DELIBERATELY
	// separate from sbMu: sing-box logs while sbMu is held, and Go's
	// sync.Mutex is not reentrant.
	sbLogMu      sync.Mutex
	sbLogFn      C.sb_log_fn
	sbLogGate    int
	sbTunLogFn   C.sb_log_fn
	sbTunLogGate int
)

//export sb_check
func sb_check(text *C.char) (result *C.char) {
	defer func() {
		if err := recover(); err != nil {
			result = C.CString(fmt.Sprintf("sing-box config: %v", err))
		}
	}()
	if text == nil {
		return C.CString("missing sing-box config")
	}
	ctx := include.Context(service.ContextWithDefaultRegistry(context.Background()))
	_, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(C.GoString(text)))
	if err != nil {
		return C.CString("sing-box config: " + err.Error())
	}
	return nil
}

// Brings one instance up and writes its handle to `handle`. The build happens
// outside the registry lock: it parses a config and binds the core's inbounds,
// which is per-instance work that a second hop must not be serialised behind.
//
//export sb_start
func sb_start(config *C.char, handle *C.uint64_t) *C.char {
	return sbStartRole(config, handle, true, false)
}

// The DNS-only destination router is a helper service, not a session core that
// a TUN should borrow as its parent context.
//export sb_destination_start
func sb_destination_start(config *C.char, handle *C.uint64_t) *C.char {
	return sbStartRole(config, handle, false, false)
}

func sbStartRole(config *C.char, handle *C.uint64_t, tunAttachable, tunLogger bool) (result *C.char) {
	defer func() {
		if failure := recover(); failure != nil {
			result = C.CString(fmt.Sprintf("sing-box start panic: %v\n%s", failure, debug.Stack()))
		}
	}()
	if config == nil || handle == nil {
		return C.CString("missing sing-box arguments")
	}
	*handle = 0
	text := C.GoString(config)
	// include.Context registers every protocol, transport and service this
	// build carries; box.New refuses to run without those registries and fails
	// with "missing ... registry in context" for an empty one.
	//
	// The service registry itself has to exist before box.New too: what the box
	// registers in it has to be readable from this context afterwards, and a
	// registry created inside box.New would not be. include.Context only adds
	// entries to an existing registry, it never clones one.
	base, cancel := context.WithCancel(context.Background())
	owned := false
	defer func() {
		if !owned {
			cancel()
		}
	}()
	ctx := include.Context(service.ContextWithDefaultRegistry(base))
	ctx, clean, err := sbMobileContext(ctx, text)
	if err != nil {
		return C.CString(err.Error())
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, clean)
	if err != nil {
		return C.CString("sing-box: config: " + err.Error())
	}
	created, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return C.CString("sing-box: " + err.Error())
	}
	// Logs are attached here rather than through box.Options.PlatformLogWriter:
	// that option also makes box.New open its bbolt cache file (`cache.db`) in
	// the process working directory, and a sandboxed app has a read-only one --
	// the failed open aborts the whole start.
	created.LogFactory().AttachPlatformWriter(sbPlatformWriter{tun: tunLogger})
	// Byte totals: the router wraps every connection it dials with the trackers
	// appended here. Same reason as above -- box.New creates a traffic manager
	// of its own only for the clash/API/platform-writer cases.
	traffic := trafficcontrol.NewManager()
	created.Router().AppendTracker(traffic)
	if err = created.Start(); err != nil {
		cancel()
		_ = created.Close()
		return C.CString("sing-box: " + err.Error())
	}
	core := &sbCore{ctx: ctx, box: created, cancel: cancel, tunAttachable: tunAttachable, traffic: traffic, listeners: sbInbounds(text), label: sbFlavor(text)}
	sbMu.Lock()
	sbNextID++
	id := sbNextID
	sbCores[id] = core
	owned = true
	sbMu.Unlock()
	engineStarted(engineSingBox)
	*handle = C.uint64_t(id)
	return nil
}

// Closes one instance. The registry entry goes first, so a stop that races a
// stop of the same handle closes the box exactly once.
//
//export sb_stop
func sb_stop(id C.uint64_t) {
	sbMu.Lock()
	core := sbCores[uint64(id)]
	sbCloseTunLocked(uint64(id))
	delete(sbCores, uint64(id))
	sbMu.Unlock()
	if core == nil {
		return
	}
	core.cancel()
	_ = core.box.Close()
	engineStopped(engineSingBox)
}

// The session teardown net: closes every instance this shim still holds,
// including one whose start was abandoned before its handle reached the caller.
//
//export sb_stop_all
func sb_stop_all() {
	sbMu.Lock()
	sbCloseTunLocked(0)
	cores := sbCores
	sbCores = make(map[uint64]*sbCore)
	sbMu.Unlock()
	for _, core := range cores {
		core.cancel()
	}
	for _, core := range cores {
		_ = core.box.Close()
	}

	// Every instance this engine had is closed above, so its run count is
	// settled rather than decremented: one that outlived its instances would
	// keep the idle scrub armed for the life of the process and suppress the
	// heap release that runs once the last engine is gone.
	engineReclaimed(engineSingBox)
}

// sb_listeners writes what this shim is actually running: one
// `handle|label|type|port|scope` record per inbound of every live instance, in
// a `;`-separated list. Returns the bytes written without the terminator, or
// the bytes it needs when the buffer is too small (nothing is written then).
//
// Records carry the handle the instance was started with: a route can run this
// core twice, another core beside it, and the host is what knows the order the
// instances were started in and the name the user gave each config.
//
//export sb_listeners
func sb_listeners(buf *C.char, capacity C.int) C.int {
	if buf == nil || capacity <= 0 {
		return 0
	}
	sbMu.Lock()
	handles := make([]uint64, 0, len(sbCores))
	for id := range sbCores {
		handles = append(handles, id)
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	var records []string
	for _, id := range handles {
		core := sbCores[id]
		for _, listener := range core.listeners {
			records = append(records, coreRecord(id, core.label, listener))
		}
	}
	sbMu.Unlock()
	return writeCoreRecords(buf, capacity, records)
}

//export sb_running
func sb_running(id C.uint64_t) C.int {
	sbMu.Lock()
	core := sbCores[uint64(id)]
	sbMu.Unlock()
	if core == nil {
		return 0
	}
	return 1
}

// Cumulative tunnelled bytes as (uplink, downlink); 0 when no tracker is
// attached.
//
//export sb_stats
func sb_stats(id C.uint64_t, uplink *C.int64_t, downlink *C.int64_t) C.int {
	sbMu.Lock()
	core := sbCores[uint64(id)]
	sbMu.Unlock()
	if core == nil || core.traffic == nil {
		return 0
	}
	up, down := core.traffic.Total()
	*uplink = C.int64_t(up)
	*downlink = C.int64_t(down)
	return 1
}

// Installs (or clears, with NULL) the host log sink and its level gate: 0
// silences the core, 1..=4 are errors, warnings, info and debug.
//
//export sb_set_log
func sb_set_log(fn C.sb_log_fn, gate C.int) {
	sbLogMu.Lock()
	sbLogFn, sbLogGate = fn, int(gate)
	sbLogMu.Unlock()
}

//export sb_set_tun_log
func sb_set_tun_log(fn C.sb_log_fn, gate C.int) {
	sbLogMu.Lock()
	sbTunLogFn, sbTunLogGate = fn, int(gate)
	sbLogMu.Unlock()
}

//export sb_string_free
func sb_string_free(value *C.char) {
	C.free(unsafe.Pointer(value))
}

// sbPlatformWriter forwards one box's logs to either the regular core sink or
// the independent TUN sink. The role is fixed when that box is created.
type sbPlatformWriter struct{ tun bool }

func (writer sbPlatformWriter) WriteMessage(level sblog.Level, message string) {
	if writer.tun {
		sbTunEmit(sbLevel(level), message)
	} else {
		sbEmit(sbLevel(level), message)
	}
}

func sbLevel(level sblog.Level) int {
	switch {
	case level <= sblog.LevelError:
		return sbLogError
	case level == sblog.LevelWarn:
		return sbLogWarn
	case level == sblog.LevelInfo:
		return sbLogInfo
	default:
		return sbLogDebug
	}
}

// sbEmit hands one line to the host. Dropped without a sink, and above the
// configured gate so a quiet session costs no C string per record.
func sbEmit(level int, text string) {
	sbLogMu.Lock()
	fn, gate := sbLogFn, sbLogGate
	sbLogMu.Unlock()
	if fn == nil || level > gate {
		return
	}
	msg := C.CString(strings.TrimRight(text, "\n"))
	defer C.free(unsafe.Pointer(msg))
	C.sb_invoke_log(fn, C.int(level), msg)
}

func sbTunEmit(level int, text string) {
	sbLogMu.Lock()
	fn, gate := sbTunLogFn, sbTunLogGate
	sbLogMu.Unlock()
	if fn == nil || level > gate {
		return
	}
	msg := C.CString(strings.TrimRight(text, "\n"))
	defer C.free(unsafe.Pointer(msg))
	C.sb_invoke_log(fn, C.int(level), msg)
}

// Attached TUN components use the existing box's service context and logging,
// but a private routing/outbound namespace. No proxy-listener rules are changed.
type sbTunAttachment struct {
	parent uint64
	scope  *adapter.Scope
}

var sbTuns = make(map[uint64]sbTunAttachment)

func sbCloseTunLocked(parent uint64) {
	for id, tun := range sbTuns {
		if parent == 0 || tun.parent == parent {
			delete(sbTuns, id)
			_ = tun.scope.Close()
		}
	}
}

//export sb_tun_start
func sb_tun_start(text *C.char, handle *C.uint64_t) (result *C.char) {
	var scope *adapter.Scope
	owned := false
	locked := false
	defer func() {
		if failure := recover(); failure != nil {
			result = C.CString(fmt.Sprintf("sing-box TUN panic: %v\n%s", failure, debug.Stack()))
		}
		if locked {
			sbMu.Unlock()
		}
		if !owned && scope != nil {
			_ = scope.Close()
		}
	}()
	if text == nil || handle == nil {
		return C.CString("missing sing-box TUN arguments")
	}
	*handle = 0
	sbMu.Lock()
	locked = true
	// Attach only to a regular session core. The synthetic DNS-only
	// destination-router box has services but no session proxy topology.
	// Deterministic selection also works when a session core is an intermediate
	// chain hop: the private TUN exit still targets the final session SOCKS.
	var parent uint64
	for id, core := range sbCores {
		if core.tunAttachable && (parent == 0 || id < parent) {
			parent = id
		}
	}
	if parent == 0 {
		locked = false
		sbMu.Unlock()
		return sbStartRole(text, handle, false, true)
	}
	base := sbCores[parent]
	ctx := service.ExtendContext(base.ctx)
	ctx, clean, err := sbMobileContext(ctx, C.GoString(text))
	if err != nil {
		return C.CString(err.Error())
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, clean)
	if err != nil {
		return C.CString("sing-box TUN: " + err.Error())
	}
	if len(options.Inbounds) != 1 || options.Inbounds[0].Type != "tun" || options.Route == nil {
		return C.CString("invalid sing-box TUN attachment")
	}
	logger := base.box.LogFactory().NewLogger("fcae-tun")
	scope = adapter.NewScope(ctx, logger)
	ctx = scope.Context()
	endpoint := sbendpoint.NewManager(service.FromContext[adapter.EndpointRegistry](ctx))
	inbound := sbinbound.NewManager(service.FromContext[adapter.InboundRegistry](ctx), endpoint)
	outbound := sboutbound.NewManager(service.FromContext[adapter.OutboundRegistry](ctx), endpoint, options.Route.Final)
	service.MustRegister[adapter.EndpointManager](ctx, endpoint)
	service.MustRegister[adapter.InboundManager](ctx, inbound)
	service.MustRegister[adapter.OutboundManager](ctx, outbound)
	// A private connection manager makes detach close only captured TUN flows.
	connection := route.NewConnectionManager(ctx, logger)
	service.MustRegister[adapter.ConnectionManager](ctx, connection)
	dnsOptions := option.DNSOptions{}
	if options.DNS != nil {
		dnsOptions = *options.DNS
	}
	network, err := route.NewNetworkManager(ctx, logger, *options.Route, dnsOptions)
	if err != nil {
		return C.CString("sing-box TUN network: " + err.Error())
	}
	service.MustRegister[adapter.NetworkManager](ctx, network)
	router := route.NewRouter(ctx, base.box.LogFactory(), *options.Route, dnsOptions)
	service.MustRegister[adapter.Router](ctx, router)
	if err = router.Initialize(options.Route.Rules, options.Route.RuleSet); err != nil {
		return C.CString("sing-box TUN rules: " + err.Error())
	}
	if base.traffic != nil {
		router.AppendTracker(base.traffic)
	}
	for _, o := range options.Outbounds {
		if err = outbound.Create(ctx, router, logger, o.Tag, o.Type, o.Options); err != nil {
			return C.CString("sing-box TUN outbound: " + err.Error())
		}
	}
	for _, i := range options.Inbounds {
		if err = inbound.Create(ctx, router, logger, i.Tag, i.Type, i.Options); err != nil {
			return C.CString("sing-box TUN inbound: " + err.Error())
		}
	}
	components := []struct {
		name      string
		component adapter.Lifecycle
	}{{"network", network}, {"connection", connection}, {"outbound", outbound}, {"router", router}, {"inbound", inbound}}
	for _, stage := range adapter.ListStartStages {
		for _, component := range components {
			if err = scope.Start(component.name, component.component, stage); err != nil {
				return C.CString("sing-box TUN start: " + err.Error())
			}
		}
	}
	sbNextID++
	id := sbNextID
	sbTuns[id] = sbTunAttachment{parent, scope}
	owned = true
	*handle = C.uint64_t(id)
	return nil
}

//export sb_tun_stop
func sb_tun_stop(id C.uint64_t) {
	sbMu.Lock()
	tun, attached := sbTuns[uint64(id)]
	if attached {
		delete(sbTuns, uint64(id))
		_ = tun.scope.Close()
		sbMu.Unlock()
		return
	}
	sbMu.Unlock()
	sb_stop(id)
}

//export sb_tun_running
func sb_tun_running(id C.uint64_t) C.int {
	sbMu.Lock()
	tun, attached := sbTuns[uint64(id)]
	if attached {
		_, alive := sbCores[tun.parent]
		sbMu.Unlock()
		if alive {
			return 1
		}
		return 0
	}
	sbMu.Unlock()
	return sb_running(id)
}

// Mobile hosts supply packets and own routes/DNS/app selection. This platform
// adapter lets the native sing-box TUN inbound consume that descriptor without
// privileged interface creation, Android package scans or route discovery.
func sbMobileContext(ctx context.Context, text string) (context.Context, []byte, error) {
	if !strings.Contains(text, `"fcae-mobile-fd"`) {
		return ctx, []byte(text), nil
	}
	var raw map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal([]byte(text), &raw); err != nil {
		return ctx, nil, err
	}
	encoded, ok := raw["fcae-mobile-fd"]
	if !ok {
		return ctx, []byte(text), nil
	}
	var fd int
	if err := stdjson.Unmarshal(encoded, &fd); err != nil {
		return ctx, nil, err
	}
	if fd < 0 || (runtime.GOOS != "android" && runtime.GOOS != "ios") {
		return ctx, nil, fmt.Errorf("system TUN descriptor is valid only in the mobile VPN host")
	}
	delete(raw, "fcae-mobile-fd")
	clean, err := stdjson.Marshal(raw)
	if err != nil {
		return ctx, nil, err
	}
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.PlatformInterface](ctx, &sbMobilePlatform{fd: fd})
	return ctx, clean, nil
}

type sbMobilePlatform struct{ fd int }

func (*sbMobilePlatform) Initialize(adapter.NetworkManager) error { return nil }
func (*sbMobilePlatform) UsePlatformInterface() bool              { return true }
func (p *sbMobilePlatform) OpenInterface(o *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	fd := int(C.sb_dup_mobile_fd(C.int(p.fd)))
	if fd < 0 {
		return nil, fmt.Errorf("duplicate system VPN descriptor failed")
	}
	o.FileDescriptor = fd
	o.AutoRoute = false
	o.EXP_ExternalConfiguration = true
	o.EXP_MultiPendingPackets = false
	o.EXP_SendMsgX = false
	device, err := tun.New(*o)
	return device, err
}
func (*sbMobilePlatform) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }
func (*sbMobilePlatform) UsePlatformAutoDetectInterfaceControl() bool            { return false }
func (*sbMobilePlatform) AutoDetectInterfaceControl(int) error {
	return fmt.Errorf("mobile TUN uses only the protected loopback session exit")
}
func (*sbMobilePlatform) UsePlatformDefaultInterfaceMonitor() bool { return true }
func (*sbMobilePlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return &sbMobileMonitor{}
}
func (*sbMobilePlatform) UsePlatformNetworkInterfaces() bool                     { return true }
func (*sbMobilePlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) { return nil, nil }
func (*sbMobilePlatform) UnderNetworkExtension() bool                            { return runtime.GOOS == "ios" }
func (*sbMobilePlatform) NetworkExtensionIncludeAllNetworks() bool               { return false }
func (*sbMobilePlatform) ClearDNSCache()                                         {}
func (*sbMobilePlatform) RequestPermissionForWIFIState() error {
	return fmt.Errorf("Wi-Fi state is not exposed to the packet engine")
}
func (*sbMobilePlatform) ReadWIFIState(context.Context) adapter.WIFIState { return adapter.WIFIState{} }
func (*sbMobilePlatform) UsePlatformConnectionOwnerFinder() bool          { return false }
func (*sbMobilePlatform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, fmt.Errorf("app selection is owned by the mobile VPN host")
}
func (*sbMobilePlatform) UsePlatformWIFIMonitor() bool  { return false }
func (*sbMobilePlatform) UsePlatformNotification() bool { return false }
func (*sbMobilePlatform) SendNotification(*adapter.Notification) error {
	return fmt.Errorf("notifications are owned by the host")
}
func (*sbMobilePlatform) CancelNotification(string, int32) error { return nil }
func (*sbMobilePlatform) MyInterfaceAddress() []netip.Addr       { return nil }
func (*sbMobilePlatform) UsePlatformNeighborResolver() bool      { return false }
func (*sbMobilePlatform) StartNeighborMonitor(adapter.NeighborUpdateListener) error {
	return fmt.Errorf("neighbor lookup is not available in the packet adapter")
}
func (*sbMobilePlatform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (*sbMobilePlatform) UsePlatformShell() bool                                    { return false }
func (*sbMobilePlatform) CheckPlatformShell() error {
	return fmt.Errorf("shell access is disabled in the packet adapter")
}
func (*sbMobilePlatform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, fmt.Errorf("shell access is disabled in the packet adapter")
}
func (*sbMobilePlatform) LookupUser(string) (*adapter.PlatformUser, error) {
	return nil, fmt.Errorf("user lookup is not available")
}
func (*sbMobilePlatform) LookupSFTPServer() (string, error) {
	return "", fmt.Errorf("SFTP is disabled")
}
func (*sbMobilePlatform) ReadSystemSSHHostKey() ([]byte, error) {
	return nil, fmt.Errorf("SSH is disabled")
}
func (*sbMobilePlatform) TailscaleHostname() string { return "" }
func (*sbMobilePlatform) UsePlatformBridge() bool   { return false }
func (*sbMobilePlatform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, fmt.Errorf("bridge creation is disabled")
}
func (*sbMobilePlatform) UsePlatformAutoRedirect() bool { return false }
func (*sbMobilePlatform) CreateAutoRedirect(adapter.AutoRedirectOptions) (adapter.AutoRedirectSession, error) {
	return nil, fmt.Errorf("automatic redirection is disabled")
}

// No underlying-interface selection is needed: this engine's only outbound is
// the already protected loopback SOCKS listener; the VPN host owns connectivity.
type sbMobileMonitor struct{}

func (*sbMobileMonitor) Start() error                         { return nil }
func (*sbMobileMonitor) Close() error                         { return nil }
func (*sbMobileMonitor) DefaultInterface() *control.Interface { return nil }
func (*sbMobileMonitor) OverrideAndroidVPN() bool             { return false }
func (*sbMobileMonitor) AndroidVPNEnabled() bool              { return true }
func (*sbMobileMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return new(list.Element[tun.DefaultInterfaceUpdateCallback])
}
func (*sbMobileMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {}
func (*sbMobileMonitor) RegisterMyInterface(string)                                           {}
func (*sbMobileMonitor) MyInterfaces() []string                                               { return nil }
