// Package main is a C-ABI shim over Psiphon's MobileLibrary/psi.
//
// Why not ClientLibrary?
//
// ClientLibrary exports a ready-made C ABI, which is why the first version of
// this bridge used it. It cannot work on Android: its PsiphonProvider has no
// BindToDevice, so Psiphon's own sockets are routed back into our TUN and the
// tunnel deadlocks trying to reach the internet through itself.
//
// MobileLibrary/psi does expose BindToDevice (via the PsiphonProvider
// interface), which is exactly the VpnService.protect() hook Android needs.
// It is a plain Go package though — gobind, not cgo — so it needs this shim to
// reach C. The same shim is used on desktop with useDeviceBinder=false, so
// both platforms run one code path.
//
// Lifecycle differences from ClientLibrary worth knowing:
//
//   - psi.Start() is NON-BLOCKING. It returns as soon as the controller
//     goroutine is launched; "connected" arrives later as a notice. The Rust
//     side polls psi_state() instead of blocking on start.
//   - Everything interesting (listening ports, connection state, the egress
//     region list) is delivered as JSON notices, so this shim parses them and
//     caches the bits the UI needs.
package main

/*
#include <stdlib.h>

// Host callbacks. protect_cb returns 1 on success, 0 on failure; it is only
// installed on Android, where it maps onto VpnService.protect(fd).
typedef int  (*psi_protect_cb)(int fd);
typedef void (*psi_log_cb)(int level, const char *message);

static int  psi_call_protect(psi_protect_cb cb, int fd)                 { return cb ? cb(fd) : 1; }
static void psi_call_log(psi_log_cb cb, int level, const char *message) { if (cb) cb(level, message); }
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
)

// Log levels, matching the tun2socks bridge's convention.
const (
	logError = 1
	logWarn  = 2
	logInfo  = 3
	logDebug = 4
)

// Connection states reported by psi_state().
const (
	stateStopped   = 0
	stateStarting  = 1
	stateConnected = 2
)

var (
	// mu guards the controller lifecycle (start/stop) and the cached state.
	mu      sync.Mutex
	running bool
	state   = stateStopped

	socksPort int
	httpPort  int

	// regions is the set of egress regions the server reported. Psiphon only
	// sends this after a successful handshake, which is why the UI can offer
	// "Auto" until the first connect completes.
	regions []string

	// logMu is deliberately separate from mu: emit() is called from Psiphon's
	// notice goroutine while mu may be held by start/stop, and sharing one
	// lock deadlocked the tun2socks bridge the same way.
	logMu     sync.Mutex
	logCb     C.psi_log_cb
	protectCb C.psi_protect_cb
)

func emit(level int, format string, args ...interface{}) {
	logMu.Lock()
	cb := logCb
	logMu.Unlock()
	if cb == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	C.psi_call_log(cb, C.int(level), cmsg)
}

// provider implements psi.PsiphonProvider.
//
// Every method is called from Go goroutines inside tunnel-core; none of them
// may take mu, or a notice arriving during start/stop would deadlock.
type provider struct{}

func (p *provider) Notice(noticeJSON string) { handleNotice(noticeJSON) }

// BindToDevice protects a socket from the VPN routes. On Android this calls
// VpnService.protect(fd); without it Psiphon's own connections are captured by
// our TUN and loop forever.
func (p *provider) BindToDevice(fd int) (string, error) {
	logMu.Lock()
	cb := protectCb
	logMu.Unlock()
	if cb == nil {
		// Desktop: nothing to protect against, routes exclude the peer.
		return "", nil
	}
	if C.psi_call_protect(cb, C.int(fd)) == 0 {
		return "", fmt.Errorf("VpnService.protect(%d) failed", fd)
	}
	return "", nil
}

func (p *provider) HasNetworkConnectivity() int          { return 1 }
func (p *provider) GetNetworkID() string                 { return "FCAE" }
func (p *provider) GetDNSServersAsString() string        { return "" }
func (p *provider) IPv6Synthesize(ipv4 string) string    { return "" }
func (p *provider) HasIPv6Route() int                    { return 0 }

// noticeEnvelope is the common shape of every psi notice.
type noticeEnvelope struct {
	NoticeType string          `json:"noticeType"`
	Data       json.RawMessage `json:"data"`
}

func handleNotice(noticeJSON string) {
	var n noticeEnvelope
	if err := json.Unmarshal([]byte(noticeJSON), &n); err != nil {
		return
	}

	switch n.NoticeType {
	case "ListeningSocksProxyPort":
		var d struct {
			Port int `json:"port"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Port > 0 {
			mu.Lock()
			socksPort = d.Port
			mu.Unlock()
			emit(logInfo, "[psiphon] socks proxy on 127.0.0.1:%d", d.Port)
		}

	case "ListeningHttpProxyPort":
		var d struct {
			Port int `json:"port"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Port > 0 {
			mu.Lock()
			httpPort = d.Port
			mu.Unlock()
		}

	case "Tunnels":
		// count>0 means at least one tunnel is established.
		var d struct {
			Count int `json:"count"`
		}
		if json.Unmarshal(n.Data, &d) == nil {
			mu.Lock()
			if d.Count > 0 {
				state = stateConnected
			} else if running {
				state = stateStarting
			}
			mu.Unlock()
			if d.Count > 0 {
				emit(logInfo, "[psiphon] tunnel established")
			}
		}

	case "AvailableEgressRegions":
		// Only sent after a handshake, so this is the moment the UI can stop
		// showing "Auto" as the only choice.
		var d struct {
			Regions []string `json:"regions"`
		}
		if json.Unmarshal(n.Data, &d) == nil && len(d.Regions) > 0 {
			sort.Strings(d.Regions)
			mu.Lock()
			regions = d.Regions
			mu.Unlock()
			emit(logInfo, "[psiphon] %d egress regions available", len(d.Regions))
		}

	case "Error", "Alert":
		var d struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Message != "" {
			emit(logWarn, "[psiphon] %s", d.Message)
		}
	}
}

//export psi_set_log_callback
func psi_set_log_callback(cb C.psi_log_cb) {
	logMu.Lock()
	logCb = cb
	logMu.Unlock()
}

//export psi_set_protect_callback
func psi_set_protect_callback(cb C.psi_protect_cb) {
	logMu.Lock()
	protectCb = cb
	logMu.Unlock()
}

// psi_start launches the controller.
//
//	configJSON  - the Psiphon config, already rendered by the caller
//	embedded    - embedded server entry list ("" to rely on remote fetch)
//	useBinder   - 1 on Android (route BindToDevice through protect_cb)
//
// Returns 0 on success, or:
//
//	-1 already running
//	-2 invalid argument
//	-3 psi.Start failed
//
//export psi_start
func psi_start(configJSON *C.char, embedded *C.char, useBinder C.int) C.int {
	mu.Lock()
	defer mu.Unlock()

	if running {
		emit(logWarn, "[psiphon] start ignored: already running")
		return -1
	}

	cfg := C.GoString(configJSON)
	if cfg == "" {
		emit(logError, "[psiphon] empty config json")
		return -2
	}

	// Reset per-session cached state. Ports and regions belong to the
	// session that reported them; carrying them over would make a failed
	// start look like it had succeeded.
	socksPort = 0
	httpPort = 0
	regions = nil
	state = stateStarting

	err := psi.Start(cfg, C.GoString(embedded), "", &provider{}, useBinder != 0, false, false)
	if err != nil {
		state = stateStopped
		emit(logError, "[psiphon] start failed: %v", err)
		return -3
	}

	running = true
	emit(logInfo, "[psiphon] controller started")
	return 0
}

//export psi_stop
func psi_stop() C.int {
	mu.Lock()
	if !running {
		mu.Unlock()
		return 0
	}
	running = false
	mu.Unlock()

	// psi.Stop() blocks until the controller goroutine has finished, and it
	// takes psi's own mutex. Calling it while holding mu would deadlock
	// against any notice still in flight.
	psi.Stop()

	mu.Lock()
	state = stateStopped
	socksPort = 0
	httpPort = 0
	mu.Unlock()

	emit(logInfo, "[psiphon] controller stopped")
	return 0
}

//export psi_state
func psi_state() C.int {
	mu.Lock()
	defer mu.Unlock()
	return C.int(state)
}

//export psi_socks_port
func psi_socks_port() C.int {
	mu.Lock()
	defer mu.Unlock()
	return C.int(socksPort)
}

//export psi_http_port
func psi_http_port() C.int {
	mu.Lock()
	defer mu.Unlock()
	return C.int(httpPort)
}

// psi_regions returns the available egress regions as a comma-separated list
// of country codes, or "" if the handshake has not produced them yet.
//
// The caller owns the returned buffer and must release it with
// psi_string_free.
//
//export psi_regions
func psi_regions() *C.char {
	mu.Lock()
	list := make([]string, len(regions))
	copy(list, regions)
	mu.Unlock()

	out := ""
	for i, r := range list {
		if i > 0 {
			out += ","
		}
		out += r
	}
	return C.CString(out)
}

//export psi_string_free
func psi_string_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func main() {}
