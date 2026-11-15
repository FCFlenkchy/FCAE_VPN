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
	"fmt"
	"strings"
	"sync"
	"unsafe"

	applog "github.com/xtls/xray-core/app/log"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	xlog "github.com/xtls/xray-core/common/log"
	xcore "github.com/xtls/xray-core/core"
	featurestats "github.com/xtls/xray-core/features/stats"
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

var (
	xrayMu       sync.Mutex
	xrayInstance *xcore.Instance
	// Nil when the running config carries no `stats` app; the core then keeps
	// no traffic totals at all.
	xrayStats featurestats.Manager

	// xrayLogMu guards the host sink and its level gate, and is DELIBERATELY
	// separate from xrayMu: the core logs while xrayMu is held, and Go's
	// sync.Mutex is not reentrant, so a shared lock would deadlock the shim
	// against its own caller.
	xrayLogMu   sync.Mutex
	xrayLogFn   C.xray_log_fn
	xrayLogGate int
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

//export xray_start
func xray_start(config *C.char) *C.char {
	text := C.GoString(config)
	xrayMu.Lock()
	defer xrayMu.Unlock()
	if xrayInstance != nil {
		return C.CString("xray: a core is already running")
	}
	// "json" is the format `main/distro/all` registers through serial.
	// StartInstance starts the instance as well as building it.
	created, err := xcore.StartInstance("json", []byte(text))
	if err != nil {
		return C.CString("xray: " + err.Error())
	}
	xrayInstance = created
	// Absent when the config carries no `stats` app, which is the only way a
	// core keeps traffic totals at all.
	if manager, ok := created.GetFeature(featurestats.ManagerType()).(featurestats.Manager); ok {
		xrayStats = manager
	}
	return nil
}

//export xray_stop
func xray_stop() {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	if xrayInstance == nil {
		return
	}
	_ = xrayInstance.Close()
	xrayInstance = nil
	xrayStats = nil
}

//export xray_running
func xray_running() C.int {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	if xrayInstance == nil || !xrayInstance.IsRunning() {
		return 0
	}
	return 1
}

//export xray_stats
//
// Cumulative tunnelled bytes as (uplink, downlink). Returns 0 when the core
// keeps no counters, which is what a config without the `stats` app or the
// policy flags gets.
func xray_stats(uplink *C.int64_t, downlink *C.int64_t) C.int {
	xrayMu.Lock()
	running := xrayInstance != nil
	manager := xrayStats
	xrayMu.Unlock()
	if !running || manager == nil {
		return 0
	}
	// VisitCounters is on the concrete manager only; the feature interface has
	// no way to enumerate what the handlers registered.
	counters, ok := manager.(*appstats.Manager)
	if !ok {
		return 0
	}
	var inboundUp, inboundDown, outboundUp, outboundDown, inbounds int64
	counters.VisitCounters(func(name string, counter featurestats.Counter) bool {
		switch {
		case strings.HasPrefix(name, "inbound>>>"):
			inbounds++
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
	// inbound, and a native config may leave its listeners untagged -- the
	// outbound counters are then the only totals. The two are never summed: a
	// chained session counts the same bytes once per outbound hop.
	totalUp, totalDown := inboundUp, inboundDown
	if inbounds == 0 {
		totalUp, totalDown = outboundUp, outboundDown
	}
	*uplink = C.int64_t(totalUp)
	*downlink = C.int64_t(totalDown)
	return 1
}

//export xray_set_log
//
// Installs (or clears, with NULL) the host log sink and its level gate: 0
// silences the core, 1..=4 are errors, warnings, info and debug.
func xray_set_log(fn C.xray_log_fn, gate C.int) {
	xrayLogMu.Lock()
	xrayLogFn, xrayLogGate = fn, int(gate)
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
	xrayLogMu.Unlock()
	if fn == nil || level > gate {
		return
	}
	msg := C.CString(strings.TrimRight(text, "\n"))
	defer C.free(unsafe.Pointer(msg))
	C.xray_invoke_log(fn, C.int(level), msg)
}
