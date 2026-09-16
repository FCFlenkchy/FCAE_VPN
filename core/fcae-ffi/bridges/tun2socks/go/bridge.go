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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"runtime"
	"strings"
	"sync"
	"unsafe"
	"time"

    "github.com/xjasonlyu/tun2socks/v2/engine"
    "github.com/xjasonlyu/tun2socks/v2/core"
    "github.com/xjasonlyu/tun2socks/v2/core/device"
    "github.com/xjasonlyu/tun2socks/v2/core/option"
    "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
    "github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
    "github.com/xjasonlyu/tun2socks/v2/dialer"
    "github.com/xjasonlyu/tun2socks/v2/tunnel"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
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

var (
	mu      sync.Mutex
	running bool

	// hostLogLevel caps which of the bridge's OWN diagnostics (the [bridge]
	// lines emitted through emit()) reach the host logger, independent of
	// the zap level that filters tun2socks-core records. The default --
	// matching the configurable "tun2socks log" setting in both UIs -- is
	// errors only: a healthy session logs nothing from this bridge.
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
