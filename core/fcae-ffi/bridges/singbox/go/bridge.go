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

// sbCore is one running instance and the router tracker behind its byte totals.
//
// A session can chain sing-box to sing-box -- two saved configs, two hops -- and
// this shim hosts both. One slot for the process meant the second hop was
// refused with "a core is already running", so instances are kept in a registry
// and every entry point carries the handle a start handed back.
type sbCore struct {
	box *box.Box
	// Nil only if the tracker could not be attached; the core then reports no
	// traffic totals.
	traffic *trafficcontrol.Manager
}

var (
	sbMu     sync.Mutex
	sbCores  = make(map[uint64]*sbCore)
	sbNextID uint64

	// sbLogMu guards the host sink and its level gate, and is DELIBERATELY
	// separate from sbMu: sing-box logs while sbMu is held, and Go's
	// sync.Mutex is not reentrant.
	sbLogMu   sync.Mutex
	sbLogFn   C.sb_log_fn
	sbLogGate int
)

//export sb_start
//
// Brings one instance up and writes its handle to `handle`. The build happens
// outside the registry lock: it parses a config and binds the core's inbounds,
// which is per-instance work that a second hop must not be serialised behind.
func sb_start(config *C.char, handle *C.uint64_t) *C.char {
	text := C.GoString(config)
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
	core := &sbCore{box: created, traffic: traffic}
	sbMu.Lock()
	sbNextID++
	id := sbNextID
	sbCores[id] = core
	sbMu.Unlock()
	engineStarted(engineSingBox)
	*handle = C.uint64_t(id)
	return nil
}

//export sb_stop
//
// Closes one instance. The registry entry goes first, so a stop that races a
// stop of the same handle closes the box exactly once.
func sb_stop(id C.uint64_t) {
	sbMu.Lock()
	core := sbCores[uint64(id)]
	delete(sbCores, uint64(id))
	sbMu.Unlock()
	if core == nil {
		return
	}
	_ = core.box.Close()
	engineStopped(engineSingBox)
}

//export sb_stop_all
//
// The session teardown net: closes every instance this shim still holds,
// including one whose start was abandoned before its handle reached the caller.
func sb_stop_all() {
	sbMu.Lock()
	cores := sbCores
	sbCores = make(map[uint64]*sbCore)
	sbMu.Unlock()
	for _, core := range cores {
		_ = core.box.Close()
		engineStopped(engineSingBox)
	}
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

//export sb_stats
//
// Cumulative tunnelled bytes as (uplink, downlink); 0 when no tracker is
// attached.
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
