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
	"strings"
	"sync"
	"unsafe"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/include"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
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

var (
	sbMu sync.Mutex
	// Non-nil exactly between a successful Start and Close.
	sbInstance *box.Box
	// Router connection tracker behind the byte totals; nil with sbInstance.
	sbTraffic *trafficcontrol.Manager

	// sbLogMu guards the host sink and its level gate, and is DELIBERATELY
	// separate from sbMu: sing-box logs while sbMu is held, and Go's
	// sync.Mutex is not reentrant.
	sbLogMu   sync.Mutex
	sbLogFn   C.sb_log_fn
	sbLogGate int
)

//export sb_start
func sb_start(config *C.char) *C.char {
	text := C.GoString(config)
	sbMu.Lock()
	defer sbMu.Unlock()
	if sbInstance != nil {
		return C.CString("sing-box: a core is already running")
	}
	// include.Context registers every protocol, transport and service this
	// build carries; box.New refuses to run without those registries and fails
	// with "missing ... registry in context" for an empty one.
	//
	// The service registry itself has to exist before box.New too: what the box
	// registers in it has to be readable from this context afterwards, and a
	// registry created inside box.New would not be. include.Context only adds
	// entries to an existing registry, it never clones one.
	ctx := include.Context(service.ContextWithDefaultRegistry(context.Background()))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(text))
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
	created.LogFactory().AttachPlatformWriter(sbPlatformWriter{})
	// Byte totals: the router wraps every connection it dials with the trackers
	// appended here. Same reason as above -- box.New creates a traffic manager
	// of its own only for the clash/API/platform-writer cases.
	traffic := trafficcontrol.NewManager()
	created.Router().AppendTracker(traffic)
	if err = created.Start(); err != nil {
		_ = created.Close()
		return C.CString("sing-box: " + err.Error())
	}
	sbInstance = created
	sbTraffic = traffic
	return nil
}

//export sb_stop
func sb_stop() {
	sbMu.Lock()
	defer sbMu.Unlock()
	if sbInstance == nil {
		return
	}
	_ = sbInstance.Close()
	sbInstance = nil
	sbTraffic = nil
}

//export sb_running
func sb_running() C.int {
	sbMu.Lock()
	defer sbMu.Unlock()
	if sbInstance == nil {
		return 0
	}
	return 1
}

//export sb_stats
//
// Cumulative tunnelled bytes as (uplink, downlink); 0 when no tracker is
// attached.
func sb_stats(uplink *C.int64_t, downlink *C.int64_t) C.int {
	sbMu.Lock()
	traffic := sbTraffic
	sbMu.Unlock()
	if traffic == nil {
		return 0
	}
	up, down := traffic.Total()
	*uplink = C.int64_t(up)
	*downlink = C.int64_t(down)
	return 1
}

//export sb_set_log
//
// Installs (or clears, with NULL) the host log sink and its level gate: 0
// silences the core, 1..=4 are errors, warnings, info and debug.
func sb_set_log(fn C.sb_log_fn, gate C.int) {
	sbLogMu.Lock()
	sbLogFn, sbLogGate = fn, int(gate)
	sbLogMu.Unlock()
}

//export sb_string_free
func sb_string_free(value *C.char) {
	C.free(unsafe.Pointer(value))
}

// sbPlatformWriter forwards sing-box's log lines to the host sink, including
// the ones the console writer filters out by level.
type sbPlatformWriter struct{}

func (sbPlatformWriter) WriteMessage(level sblog.Level, message string) {
	sbEmit(sbLevel(level), message)
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
