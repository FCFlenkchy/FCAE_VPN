//go:build fcae_xray

// Xray-core shim, compiled into the app's single Go archive.
//
// One archive, one Go runtime: this file joins tun2socks, Psiphon, Xray-core and
// sing-box in the package `bridges/tun2socks/build.rs` assembles, and Go's
// linker keeps one copy of every dependency. The `fcae_xray` build tag is set
// only when the Cargo feature is on, so a build without Xray links no Xray code.
//
// There is no `xray` executable, no config file on disk and no subprocess.
//
// Exported symbols are prefixed per core: two shims in one package cannot both
// own `start`. Log lines and byte counters go to the host through these
// prefixed entry points rather than stdout and a discarded stats manager.
package main

/*
#include <stdint.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
static int xray_dup_mobile_fd(int fd) { return fcntl(fd,F_DUPFD_CLOEXEC,3); }
static void xray_close_mobile_fd(int fd) { close(fd); }
#else
static int xray_dup_mobile_fd(int fd) { return -1; }
static void xray_close_mobile_fd(int fd) {}
#endif

// Host log sink, implemented on the Rust side; see bridges/xray/src/lib.rs.
// Declared here so cgo lets Go call back into the host.
typedef void (*xray_log_fn)(int level, const char *msg);

static void xray_invoke_log(xray_log_fn fn, int level, const char *msg) {
	if (fn != NULL) {
		fn(level, msg);
	}
}
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	applog "github.com/xtls/xray-core/app/log"
	xrouter "github.com/xtls/xray-core/app/router"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	xcore "github.com/xtls/xray-core/core"
	xinbound "github.com/xtls/xray-core/features/inbound"
	xoutbound "github.com/xtls/xray-core/features/outbound"
	xrouting "github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"google.golang.org/protobuf/proto"
	// Registers the JSON config loader and every inbound/outbound proxy, the
	// same set the `xray` executable carries.
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Xray's counter names. `uplink` is what the client sent, `downlink` what it
// received.
const (
	xrayUplinkSuffix   = ">>>traffic>>>uplink"
	xrayDownlinkSuffix = ">>>traffic>>>downlink"
)

// Host log levels: the scale the Rust sink maps onto the app logger (see
// `forward_log` in fcae_runtime::sing_xray). The shims all land in one package,
// so each core prefixes its own.
const (
	xrayLogError = 1
	xrayLogWarn  = 2
	xrayLogInfo  = 3
	xrayLogDebug = 4
)

// xrayCore is one running instance: the core itself and the stats manager its
// own config registered.
//
// A session can chain Xray to Xray -- two saved configs, two hops -- and this
// shim hosts both. One slot for the process meant the second hop was refused
// with "a core is already running" and the session retried until it gave up, so
// instances are kept in a registry and every entry point carries the handle a
// start handed back.
type xrayCore struct {
	routing  *xrouter.Config
	instance *xcore.Instance
	// Nil when this config carries no `stats` app; the core then keeps no
	// traffic totals at all.
	stats featurestats.Manager
	// The inbounds this instance actually runs, read from the very config the
	// core was handed. The app cannot know them: a saved config declares its
	// own ports, a chain runs one instance per hop, and a dynamic port is only
	// settled once the listener binds -- so the settings' one number is not the
	// answer to "what is listening".
	listeners []coreListener
	// What this config calls itself -- `vless reality` -- so a session running
	// two instances of this core names each of them instead of numbering them.
	label string
}

// xrayInbounds reads every inbound of a core config, in the order the core
// lists them.
//
// Only the fields both dialects agree on are read: a config that spells its
// port as a string, an inbound with an inherited listener object or an unknown
// protocol still reports what it can, and an inbound with no port is not a TCP
// listener this app can name.
func xrayInbounds(text string) []coreListener {
	var cfg struct {
		Inbounds []struct {
			Protocol string          `json:"protocol"`
			Port     json.RawMessage `json:"port"`
			Listen   json.RawMessage `json:"listen"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return nil
	}
	out := make([]coreListener, 0, len(cfg.Inbounds))
	for _, inbound := range cfg.Inbounds {
		if port := coreConfigPort(inbound.Port); port > 0 {
			out = append(out, coreListener{
				proto: coreConfigName(inbound.Protocol),
				port:  port,
				any:   coreConfigScope(inbound.Listen),
			})
		}
	}
	return out
}

// xrayFlavor is the config's first real outbound and the transport carrying it:
// the vocabulary a share link uses, so `vless reality` on screen names the same
// thing the link the user pasted named.
//
// The first outbound that is not an engine built-in is the one the config
// routes through, and the fields are read the way Xray spells them: a config
// this app generated and a hand-written one answer the same way.
func xrayFlavor(text string) string {
	var cfg struct {
		Outbounds []struct {
			Protocol       string `json:"protocol"`
			StreamSettings struct {
				Network  string `json:"network"`
				Security string `json:"security"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return ""
	}
	for _, outbound := range cfg.Outbounds {
		switch strings.ToLower(strings.TrimSpace(outbound.Protocol)) {
		case "", "freedom", "blackhole", "dns", "loopback":
			continue
		}
		network := strings.ToLower(strings.TrimSpace(outbound.StreamSettings.Network))
		if network == "tcp" {
			network = ""
		}
		security := strings.ToLower(strings.TrimSpace(outbound.StreamSettings.Security))
		if security == "none" {
			security = ""
		}
		return coreTransportWords(outbound.Protocol, network, security)
	}
	return ""
}

var (
	xrayMu     sync.Mutex
	xrayCores  = make(map[uint64]*xrayCore)
	xrayNextID uint64

	// xrayLogMu guards the host sink and its level gate, and is DELIBERATELY
	// separate from xrayMu: the core logs while xrayMu is held, and Go's
	// sync.Mutex is not reentrant, so a shared lock would deadlock the shim
	// against its own caller.
	xrayLogMu       sync.Mutex
	xrayLogFn       C.xray_log_fn
	xrayLogGate     int
	xrayTunLogFn    C.xray_log_fn
	xrayTunLogGate  int
	xrayTunLogActive bool
)

// Console records are created by `app/log` for the instance's error logger;
// taking over that creator is what routes them to the host.
//
// The alternative -- replacing the global handler after the instance starts --
// would also swallow what `app/log` does for a native config: its configured
// level, `maskAddress`, and an access or error log it writes to a file.
func init() {
	common.Must(applog.RegisterHandlerCreator(applog.LogType_Console, func(applog.LogType, applog.HandlerCreatorOptions) (xlog.Handler, error) {
		return hostLogHandler{}, nil
	}))
}

//export xray_check
func xray_check(text *C.char) (result *C.char) {
	defer func() {
		if err := recover(); err != nil {
			result = C.CString(fmt.Sprintf("Xray config: %v", err))
		}
	}()
	if text == nil {
		return C.CString("missing Xray config")
	}
	_, err := xcore.LoadConfig("json", bytes.NewReader([]byte(C.GoString(text))))
	if err != nil {
		return C.CString("Xray config: " + err.Error())
	}
	return nil
}

// Brings one instance up and writes its handle to `handle`. The build happens
// outside the registry lock: it parses a config and binds the core's inbounds,
// which is per-instance work that a second hop must not be serialised behind.
//
//export xray_start
func xray_start(config *C.char, handle *C.uint64_t) *C.char {
	xrayMobileFdMu.Lock()
	defer xrayMobileFdMu.Unlock()
	return xrayStart(config, handle)
}
func xrayStart(config *C.char, handle *C.uint64_t) *C.char {
	text := C.GoString(config)
	configOptions, err := xcore.LoadConfig("json", bytes.NewReader([]byte(text)))
	if err != nil {
		return C.CString("xray: " + err.Error())
	}
	baseline := &xrouter.Config{}
	hasRouter := false
	for _, app := range configOptions.App {
		instance, e := app.GetInstance()
		if e != nil {
			return C.CString("xray: " + e.Error())
		}
		if router, ok := instance.(*xrouter.Config); ok {
			baseline = router
			hasRouter = true
		}
	}
	if !hasRouter {
		configOptions.App = append(configOptions.App, serial.ToTypedMessage(baseline))
	}
	created, err := xcore.New(configOptions)
	if err != nil {
		return C.CString("xray: " + err.Error())
	}
	if err = created.Start(); err != nil {
		_ = created.Close()
		return C.CString("xray: " + err.Error())
	}
	core := &xrayCore{routing: baseline, instance: created, listeners: xrayInbounds(text), label: xrayFlavor(text)}
	if manager, ok := created.GetFeature(featurestats.ManagerType()).(featurestats.Manager); ok {
		core.stats = manager
	}
	xrayMu.Lock()
	xrayNextID++
	id := xrayNextID
	xrayCores[id] = core
	xrayMu.Unlock()
	engineStarted(engineXray)
	*handle = C.uint64_t(id)
	return nil
}

// Closes one instance. The registry entry goes first, so a stop that races a
// stop of the same handle closes the core exactly once.
//
//export xray_stop
func xray_stop(id C.uint64_t) {
	xrayMu.Lock()
	core := xrayCores[uint64(id)]
	xrayCloseTunLocked(uint64(id))
	delete(xrayCores, uint64(id))
	xrayMu.Unlock()
	if core == nil {
		return
	}
	_ = core.instance.Close()
	engineStopped(engineXray)
}

// The session teardown net: closes every instance this shim still holds,
// including one whose start was abandoned before its handle reached the caller.
//
//export xray_stop_all
func xray_stop_all() {
	xraySetTunLogActive(false)
	xrayMu.Lock()
	xrayCloseTunLocked(0)
	cores := xrayCores
	xrayCores = make(map[uint64]*xrayCore)
	xrayMu.Unlock()
	for _, core := range cores {
		_ = core.instance.Close()
	}

	// Every instance this engine had is closed above, so its run count is
	// settled rather than decremented: one that outlived its instances would
	// keep the idle scrub armed for the life of the process and suppress the
	// heap release that runs once the last engine is gone.
	engineReclaimed(engineXray)
}

// xray_listeners writes what this shim is actually running: one
// `handle|label|protocol|port|scope` record per inbound of every live instance,
// in a `;`-separated list. Returns the bytes written without the terminator, or
// the bytes it needs when the buffer is too small (nothing is written then).
//
// Records carry the handle the instance was started with: a route can run this
// core twice, another core beside it, and the host is what knows the order the
// instances were started in and the name the user gave each config.
//
//export xray_listeners
func xray_listeners(buf *C.char, capacity C.int) C.int {
	if buf == nil || capacity <= 0 {
		return 0
	}
	xrayMu.Lock()
	handles := make([]uint64, 0, len(xrayCores))
	for id := range xrayCores {
		handles = append(handles, id)
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	var records []string
	for _, id := range handles {
		core := xrayCores[id]
		for _, listener := range core.listeners {
			records = append(records, coreRecord(id, core.label, listener))
		}
	}
	xrayMu.Unlock()
	return writeCoreRecords(buf, capacity, records)
}

//export xray_running
func xray_running(id C.uint64_t) C.int {
	xrayMu.Lock()
	core := xrayCores[uint64(id)]
	xrayMu.Unlock()
	if core == nil || !core.instance.IsRunning() {
		return 0
	}
	return 1
}

// Cumulative tunnelled bytes as (uplink, downlink). Returns 0 when the core
// keeps no counters, which is what a config without the `stats` app or the
// policy flags gets.
//
//export xray_stats
func xray_stats(id C.uint64_t, uplink *C.int64_t, downlink *C.int64_t) C.int {
	xrayMu.Lock()
	core := xrayCores[uint64(id)]
	xrayMu.Unlock()
	if core == nil || core.stats == nil {
		return 0
	}
	// VisitCounters is on the concrete manager only; the feature interface has
	// no way to enumerate what the handlers registered.
	counters, ok := core.stats.(*appstats.Manager)
	if !ok {
		return 0
	}
	var inboundUp, inboundDown, outboundUp, outboundDown int64
	counters.VisitCounters(func(name string, counter featurestats.Counter) bool {
		switch {
		case strings.HasPrefix(name, "inbound>>>"):
			switch {
			case strings.HasSuffix(name, xrayUplinkSuffix):
				inboundUp += counter.Value()
			case strings.HasSuffix(name, xrayDownlinkSuffix):
				inboundDown += counter.Value()
			}
		case strings.HasPrefix(name, "outbound>>>"):
			switch {
			case strings.HasSuffix(name, xrayUplinkSuffix):
				outboundUp += counter.Value()
			case strings.HasSuffix(name, xrayDownlinkSuffix):
				outboundDown += counter.Value()
			}
		}
		return true
	})
	// Inbound counters are the client's own traffic: one connection enters one
	// listener, so they never overlap. Xray registers none for an untagged
	// inbound, so a native config that leaves its socks inbound untagged has no
	// inbound counter on the very listener a chained hop dials, while a tagged
	// one nothing routes through keeps a counter pinned at zero: a registered
	// counter is no evidence of metering. The outbound counters are the totals
	// when the inbound ones add up to nothing. The two are never summed -- a
	// chained session counts the same bytes once per outbound hop.
	totalUp, totalDown := inboundUp, inboundDown
	if inboundUp == 0 && inboundDown == 0 {
		totalUp, totalDown = outboundUp, outboundDown
	}
	*uplink = C.int64_t(totalUp)
	*downlink = C.int64_t(totalDown)
	return 1
}

// Installs (or clears, with NULL) the host log sink and its level gate: 0
// silences the core, 1..=4 are errors, warnings, info and debug.
//
//export xray_set_log
func xray_set_log(fn C.xray_log_fn, gate C.int) {
	xrayLogMu.Lock()
	xrayLogFn, xrayLogGate = fn, int(gate)
	xrayLogMu.Unlock()
}

// Installs the independent sink used only by a standalone Xray TUN instance.
// The regular core sink/gate above remains untouched.
//export xray_set_tun_log
func xray_set_tun_log(fn C.xray_log_fn, gate C.int) {
	xrayLogMu.Lock()
	xrayTunLogFn, xrayTunLogGate = fn, int(gate)
	xrayLogMu.Unlock()
}

//export xray_string_free
func xray_string_free(value *C.char) {
	C.free(unsafe.Pointer(value))
}

// hostLogHandler is the console handler `app/log` builds for a core instance: it
// forwards the records the core's own level settings let through.
type hostLogHandler struct{}

func (hostLogHandler) Handle(msg xlog.Message) {
	level, text := xrayRecord(msg)
	xrayEmit(level, text)
}

// Close satisfies the closable check `app/log` runs over the handlers it owns;
// there is nothing to release.
func (hostLogHandler) Close() error {
	return nil
}

// xrayRecord splits a record into the host level it carries and its text.
//
// A masked record (a native config's `maskAddress`) wraps the original, so the
// severity is read from the inner message while the text stays the masked one.
func xrayRecord(msg xlog.Message) (int, string) {
	level, text := xrayLogInfo, msg.String()
	switch record := msg.(type) {
	case *xlog.GeneralMessage:
		level, text = xrayLevel(record.Severity), fmt.Sprint(record.Content)
	case *applog.MaskedMsgWrapper:
		if general, ok := record.Message.(*xlog.GeneralMessage); ok {
			level = xrayLevel(general.Severity)
		}
	}
	return level, text
}

func xrayLevel(severity xlog.Severity) int {
	switch severity {
	case xlog.Severity_Error:
		return xrayLogError
	case xlog.Severity_Warning:
		return xrayLogWarn
	case xlog.Severity_Debug:
		return xrayLogDebug
	default:
		return xrayLogInfo
	}
}

// xrayEmit hands one line to the host. Dropped without a sink, and above the
// configured gate so a quiet session costs no C string per record.
func xrayEmit(level int, text string) {
	xrayLogMu.Lock()
	fn, gate := xrayLogFn, xrayLogGate
	tunFn, tunGate, tunActive := xrayTunLogFn, xrayTunLogGate, xrayTunLogActive
	xrayLogMu.Unlock()
	// A standalone TUN is a core instance in its own right: route its records
	// exclusively to the TUN sink. The generic core sink can still contain a
	// callback from an earlier session and must not capture TUN logs. Attached
	// TUNs leave tunActive false and intentionally share their parent's logger.
	toTun := tunActive && tunFn != nil && level <= tunGate
	toCore := !tunActive && fn != nil && level <= gate
	if !toCore && !toTun {
		return
	}
	msg := C.CString(strings.TrimRight(text, "\n"))
	defer C.free(unsafe.Pointer(msg))
	if toCore {
		C.xray_invoke_log(fn, C.int(level), msg)
	}
	if toTun {
		C.xray_invoke_log(tunFn, C.int(level), msg)
	}
}

func xraySetTunLogActive(active bool) {
	xrayLogMu.Lock()
	xrayTunLogActive = active
	xrayLogMu.Unlock()
}

type xrayTunAttachment struct {
	parent    uint64
	inbound   string
	outbounds []string
}

var xrayTuns = make(map[uint64]xrayTunAttachment)

func xrayCloseTunLocked(parent uint64) {
	for id, tun := range xrayTuns {
		if parent == 0 || tun.parent == parent {
			xrayDetachTunLocked(id, tun)
		}
	}
}
func xrayDetachTunLocked(id uint64, tun xrayTunAttachment) {
	delete(xrayTuns, id)
	core := xrayCores[tun.parent]
	if core == nil {
		return
	}
	ctx := context.Background()
	im := core.instance.GetFeature(xinbound.ManagerType()).(xinbound.Manager)
	om := core.instance.GetFeature(xoutbound.ManagerType()).(xoutbound.Manager)
	router := core.instance.GetFeature(xrouting.RouterType()).(xrouting.Router)
	_ = im.RemoveHandler(ctx, tun.inbound)
	_ = router.AddRule(serial.ToTypedMessage(core.routing), false)
	for _, tag := range tun.outbounds {
		_ = om.RemoveHandler(ctx, tag)
	}
}

//export xray_tun_start
func xray_tun_start(text *C.char, handle *C.uint64_t) (result *C.char) {
	release, err := xrayMobileDescriptor(text)
	if err != nil {
		return C.CString(err.Error())
	}
	defer release()

	if text == nil || handle == nil {
		return C.CString("missing Xray TUN arguments")
	}
	*handle = 0
	xrayMu.Lock()
	var parent uint64
	for id := range xrayCores {
		if parent == 0 || id < parent {
			parent = id
		}
	}
	if parent == 0 {
		xrayMu.Unlock()
		xraySetTunLogActive(true)
		result = xrayStart(text, handle)
		if result != nil {
			xraySetTunLogActive(false)
		}
		return result
	}
	xraySetTunLogActive(false)
	defer xrayMu.Unlock()
	for _, tun := range xrayTuns {
		if tun.parent == parent {
			return C.CString("Xray TUN is already attached")
		}
	}
	base := xrayCores[parent]
	options, err := xcore.LoadConfig("json", bytes.NewReader([]byte(C.GoString(text))))
	if err != nil {
		return C.CString("Xray TUN: " + err.Error())
	}
	if len(options.Inbound) != 1 || len(options.Outbound) == 0 {
		return C.CString("invalid Xray TUN attachment")
	}
	im := base.instance.GetFeature(xinbound.ManagerType()).(xinbound.Manager)
	om := base.instance.GetFeature(xoutbound.ManagerType()).(xoutbound.Manager)
	router := base.instance.GetFeature(xrouting.RouterType()).(xrouting.Router)
	inboundTag := options.Inbound[0].Tag
	if handler, _ := im.GetHandler(context.Background(), inboundTag); handler != nil {
		return C.CString("reserved Xray TUN inbound tag is already in use")
	}
	for _, out := range options.Outbound {
		if om.GetHandler(out.Tag) != nil {
			return C.CString("reserved Xray TUN outbound tag is already in use")
		}
	}
	overlay := &xrouter.Config{}
	for _, app := range options.App {
		instance, e := app.GetInstance()
		if e != nil {
			return C.CString(e.Error())
		}
		if cfg, ok := instance.(*xrouter.Config); ok {
			overlay = cfg
		}
	}
	if len(overlay.Rule) == 0 {
		return C.CString("missing inbound-scoped Xray TUN rules")
	}
	combined := proto.Clone(base.routing).(*xrouter.Config)
	combined.Rule = append(append([]*xrouter.RoutingRule{}, overlay.Rule...), combined.Rule...)
	xrayNextID++
	id := xrayNextID
	tun := xrayTunAttachment{parent: parent, inbound: inboundTag}
	xrayTuns[id] = tun
	owned := false
	defer func() {
		if failure := recover(); failure != nil {
			result = C.CString(fmt.Sprintf("Xray TUN panic: %v", failure))
		}
		if !owned {
			xrayDetachTunLocked(id, xrayTuns[id])
		}
	}()
	for _, out := range options.Outbound {
		if err = xcore.AddOutboundHandler(base.instance, out); err != nil {
			return C.CString("Xray TUN outbound: " + err.Error())
		}
		tun.outbounds = append(tun.outbounds, out.Tag)
		xrayTuns[id] = tun
	}
	if err = router.AddRule(serial.ToTypedMessage(combined), false); err != nil {
		return C.CString("Xray TUN routing: " + err.Error())
	}
	if err = xcore.AddInboundHandler(base.instance, options.Inbound[0]); err != nil {
		return C.CString("Xray TUN inbound: " + err.Error())
	}
	owned = true
	*handle = C.uint64_t(id)
	return nil
}

//export xray_tun_stop
func xray_tun_stop(id C.uint64_t) {
	xrayMu.Lock()
	tun, attached := xrayTuns[uint64(id)]
	if attached {
		xrayDetachTunLocked(uint64(id), tun)
		xrayMu.Unlock()
		xraySetTunLogActive(false)
		return
	}
	xrayMu.Unlock()
	// Keep the TUN sink active through core.Close so any final diagnostics stay
	// on the TUN stream, then disable it for the next session.
	xray_stop(id)
	xraySetTunLogActive(false)
}

//export xray_tun_running
func xray_tun_running(id C.uint64_t) C.int {
	xrayMu.Lock()
	tun, attached := xrayTuns[uint64(id)]
	if attached {
		core := xrayCores[tun.parent]
		alive := core != nil && core.instance.IsRunning()
		if alive {
			handler, _ := core.instance.GetFeature(xinbound.ManagerType()).(xinbound.Manager).GetHandler(context.Background(), tun.inbound)
			alive = handler != nil
		}
		xrayMu.Unlock()
		if alive {
			return 1
		}
		return 0
	}
	xrayMu.Unlock()
	return xray_running(id)
}

var xrayMobileFdMu sync.Mutex

func xrayMobileDescriptor(text *C.char) (func(), error) {
	xrayMobileFdMu.Lock()
	unlock := func() { xrayMobileFdMu.Unlock() }
	if text == nil {
		return unlock, nil
	}
	var raw struct {
		FD *int `json:"fcae-mobile-fd"`
	}
	if err := json.Unmarshal([]byte(C.GoString(text)), &raw); err != nil {
		unlock()
		return nil, err
	}
	if raw.FD == nil {
		return unlock, nil
	}
	if *raw.FD < 0 || (runtime.GOOS != "android" && runtime.GOOS != "ios") {
		unlock()
		return nil, fmt.Errorf("system TUN descriptor requires a mobile VPN host")
	}
	privateFd := int(C.xray_dup_mobile_fd(C.int(*raw.FD)))
	if privateFd < 0 {
		unlock()
		return nil, fmt.Errorf("duplicate system VPN descriptor failed")
	}
	const key = "xray.tun.fd"
	old, exists := os.LookupEnv(key)
	if err := os.Setenv(key, strconv.Itoa(privateFd)); err != nil {
		C.xray_close_mobile_fd(C.int(privateFd))
		unlock()
		return nil, err
	}
	return func() {
		if exists {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
		C.xray_close_mobile_fd(C.int(privateFd))
		unlock()
	}, nil
}
