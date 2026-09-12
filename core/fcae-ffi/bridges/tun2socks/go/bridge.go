// Package main is the cgo shim that turns xjasonlyu/tun2socks into an
// in-process library instead of a subprocess.
//
// It is compiled with `go build -buildmode=c-archive`, producing
// libtun2socks_bridge.a + .h, which the Rust crate links statically. The Go
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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"unsafe"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	logError = 1
	logWarn  = 2
	logInfo  = 3
	logDebug = 4
)

var (
	mu      sync.Mutex
	running bool
	logFn   C.t2s_log_fn
)

// emit forwards a message to the host logger. Never panics if no callback is
// registered yet.
func emit(level int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	mu.Lock()
	fn := logFn
	mu.Unlock()
	if fn == nil {
		return
	}
	c := C.CString(msg)
	defer C.free(unsafe.Pointer(c))
	C.t2s_invoke_log(fn, C.int(level), c)
}

//export t2s_set_log_callback
//
// Register (or clear, with NULL) the host log sink.
func t2s_set_log_callback(fn C.t2s_log_fn) {
	mu.Lock()
	logFn = fn
	mu.Unlock()
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
	case "socks5", "socks4", "socks4a", "http", "https", "ss", "relay", "direct", "reject":
	default:
		return fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Host == "" && u.Scheme != "direct" && u.Scheme != "reject" {
		return fmt.Errorf("proxy url %q has no host", k.Proxy)
	}
	if k.MTU < 0 || k.MTU > 65535 {
		return fmt.Errorf("mtu %d out of range", k.MTU)
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
	}
	if key.LogLevel == "" {
		key.LogLevel = "info"
	}

	if err := validateKey(key); err != nil {
		emit(logError, "[bridge] invalid configuration: %v", err)
		return -2
	}

	// engine.Start can still log.Fatalf on an unforeseen failure; recover
	// from anything that surfaces as a panic so the host survives.
	var startErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				startErr = fmt.Errorf("panic in engine.Start: %v", r)
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
