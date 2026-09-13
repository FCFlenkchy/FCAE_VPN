//go:build ignore

// TEMP: Psiphon is commented out of the Go bridge for now (other bugs first).
// `ignore` keeps this file in the tree but go mod tidy / go build skip it.
// Do not delete. Drop the build tag and restore go.mod / psiphon-live to
// load the library again.

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
//   - Everything interesting (listening ports, connection psiState, the egress
//     region list) is delivered as JSON notices, so this shim parses them and
//     caches the bits the UI needs.
package main

/*
#include <stdlib.h>

// Host callbacks. protect_cb returns 1 on success, 0 on failure; it is only
// installed on Android, where it maps onto VpnService.protect(fd).
typedef int  (*psi_protect_cb)(int fd);
typedef void (*psi_log_cb)(int level, const char *message);

// Network-state callbacks. The host owns the strings it returns and hands
// ownership to Go, which releases them with free(); they must therefore come
// from malloc/strdup, never from a static buffer or a C++ new.
//
// dns_cb returns a comma-delimited list of the resolvers currently in use on
// the underlying network ("8.8.8.8,1.1.1.1"), or NULL when unknown.
// connectivity_cb returns 1 when a usable network exists, 0 otherwise.
// network_id_cb returns an identity for the active network, used by Psiphon
// to key its tactics and dial-parameter caches.
typedef char *(*psi_dns_cb)(void);
typedef int   (*psi_connectivity_cb)(void);
typedef char *(*psi_network_id_cb)(void);

static int  psi_call_protect(psi_protect_cb cb, int fd)                 { return cb ? cb(fd) : 1; }
static void psi_call_log(psi_log_cb cb, int level, const char *message) { if (cb) cb(level, message); }

static char *psi_call_dns(psi_dns_cb cb)                   { return cb ? cb() : NULL; }
static int   psi_call_connectivity(psi_connectivity_cb cb) { return cb ? cb() : 1; }
static char *psi_call_network_id(psi_network_id_cb cb)     { return cb ? cb() : NULL; }
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
)

// Log levels, matching the tun2socks bridge's convention.
const (
	psiLogError = 1
	psiLogWarn  = 2
	psiLogInfo  = 3
	psiLogDebug = 4
)

// Connection states reported by psi_state().
const (
	psiStateStopped   = 0
	psiStateStarting  = 1
	psiStateConnected = 2
)

var (
	// psiMu guards the controller lifecycle (start/stop) and the cached psiState.
	psiMu      sync.Mutex
	psiRunning bool
	psiState   = psiStateStopped

	psiSocksPort int
	psiHttpPort  int

	// psiRegions is the set of egress psiRegions the server reported. Psiphon only
	// sends this after a successful handshake, which is why the UI can offer
	// "Auto" until the first connect completes.
	psiRegions []string

	// psiLogMu is deliberately separate from psiMu: psiEmit() is called from Psiphon's
	// notice goroutine while psiMu may be held by start/stop, and sharing one
	// lock deadlocked the tun2socks bridge the same way.
	psiLogMu     sync.Mutex
	psiLogCb     C.psi_log_cb
	psiProtectCb C.psi_protect_cb

	// Network-state hooks, guarded by psiLogMu for the same reason as the
	// others: tunnel-core calls them from its own goroutines at arbitrary
	// times, including while start/stop holds psiMu.
	psiDnsCb          C.psi_dns_cb
	psiConnectivityCb C.psi_connectivity_cb
	psiNetworkIDCb    C.psi_network_id_cb
)

// psiTakeCString converts a host-allocated C string and releases it.
//
// The host allocates with strdup, so ownership crosses the boundary here and
// the buffer must be freed with free() -- not by any Go allocator.
func psiTakeCString(raw *C.char) string {
	if raw == nil {
		return ""
	}
	out := C.GoString(raw)
	C.free(unsafe.Pointer(raw))
	return out
}

// psiDataRootFromConfig pulls DataRootDirectory out of the config object.
//
// Decoding into a map rather than a struct keeps every other field untouched:
// this shim never rewrites the config, it only needs to read one path.
func psiDataRootFromConfig(configJSON string) string {
	var probe struct {
		DataRootDirectory string `json:"DataRootDirectory"`
	}
	if err := json.Unmarshal([]byte(configJSON), &probe); err != nil {
		return ""
	}
	return probe.DataRootDirectory
}

func psiEmit(level int, format string, args ...interface{}) {
	psiLogMu.Lock()
	cb := psiLogCb
	psiLogMu.Unlock()
	if cb == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	C.psi_call_log(cb, C.int(level), cmsg)
}

// psiProvider implements psi.PsiphonProvider.
//
// Every method is called from Go goroutines inside tunnel-core; none of them
// may take psiMu, or a notice arriving during start/stop would deadlock.
type psiProvider struct{}

func (p *psiProvider) Notice(noticeJSON string) { psiHandleNotice(noticeJSON) }

// BindToDevice protects a socket from the VPN routes. On Android this calls
// VpnService.protect(fd); without it Psiphon's own connections are captured by
// our TUN and loop forever.
func (p *psiProvider) BindToDevice(fd int) (string, error) {
	psiLogMu.Lock()
	cb := psiProtectCb
	psiLogMu.Unlock()
	if cb == nil {
		// Desktop: nothing to protect against, routes exclude the peer.
		return "", nil
	}
	if C.psi_call_protect(cb, C.int(fd)) == 0 {
		return "", fmt.Errorf("VpnService.protect(%d) failed", fd)
	}
	return "", nil
}

// HasNetworkConnectivity reports whether a usable underlying network exists.
//
// Returning a hardcoded 1 made tunnel-core burn through its entire candidate
// list while the device was actually offline, so a Wi-Fi/mobile handover
// looked like a tunnel that was permanently "establishing". With a real
// answer the controller parks and resumes instead.
func (p *psiProvider) HasNetworkConnectivity() int {
	psiLogMu.Lock()
	cb := psiConnectivityCb
	psiLogMu.Unlock()
	return int(C.psi_call_connectivity(cb))
}

// GetNetworkID identifies the underlying network.
//
// Psiphon keys its tactics, server affinity and dial parameters on this
// value. A single constant meant parameters learned on an uncensored Wi-Fi
// network were replayed on a censored mobile carrier and vice versa, so
// every network change started from a poisoned cache.
func (p *psiProvider) GetNetworkID() string {
	psiLogMu.Lock()
	cb := psiNetworkIDCb
	psiLogMu.Unlock()
	if id := psiTakeCString(C.psi_call_network_id(cb)); id != "" {
		return id
	}
	return "UNKNOWN"
}

// GetDNSServersAsString returns the underlying network's resolvers, comma
// delimited.
//
// This is not optional on Android. Once DeviceBinder is configured, upstream
// disables the standard library resolver (it would route inside the VPN), so
// this list is the ONLY source of DNS servers. Returning "" left the resolver
// with an empty server set and every lookup failed with "no DNS servers" --
// no remote server list fetch, no fronted dials, no tunnel, and no error that
// pointed at DNS.
func (p *psiProvider) GetDNSServersAsString() string {
	psiLogMu.Lock()
	cb := psiDnsCb
	psiLogMu.Unlock()
	return psiTakeCString(C.psi_call_dns(cb))
}

func (p *psiProvider) IPv6Synthesize(ipv4 string) string { return "" }
func (p *psiProvider) HasIPv6Route() int                 { return 0 }

// psiNoticeEnvelope is the common shape of every psi notice.
type psiNoticeEnvelope struct {
	NoticeType string          `json:"noticeType"`
	Data       json.RawMessage `json:"data"`
}

func psiHandleNotice(noticeJSON string) {
	var n psiNoticeEnvelope
	if err := json.Unmarshal([]byte(noticeJSON), &n); err != nil {
		return
	}

	switch n.NoticeType {
	case "ListeningSocksProxyPort":
		var d struct {
			Port int `json:"port"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Port > 0 {
			psiMu.Lock()
			psiSocksPort = d.Port
			psiMu.Unlock()
			psiEmit(psiLogInfo, "[psiphon] socks proxy on 127.0.0.1:%d", d.Port)
		}

	case "ListeningHttpProxyPort":
		var d struct {
			Port int `json:"port"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Port > 0 {
			psiMu.Lock()
			psiHttpPort = d.Port
			psiMu.Unlock()
		}

	case "Tunnels":
		// count>0 means at least one tunnel is established.
		var d struct {
			Count int `json:"count"`
		}
		if json.Unmarshal(n.Data, &d) == nil {
			psiMu.Lock()
			if d.Count > 0 {
				psiState = psiStateConnected
			} else if psiRunning {
				psiState = psiStateStarting
			}
			psiMu.Unlock()
			if d.Count > 0 {
				psiEmit(psiLogInfo, "[psiphon] tunnel established")
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
			psiMu.Lock()
			psiRegions = d.Regions
			psiMu.Unlock()
			psiEmit(psiLogInfo, "[psiphon] %d egress regions available", len(d.Regions))
		}

	case "Error", "Alert":
		var d struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Message != "" {
			psiEmit(psiLogWarn, "[psiphon] %s", d.Message)
		}
	}
}

//export psi_set_log_callback
func psi_set_log_callback(cb C.psi_log_cb) {
	psiLogMu.Lock()
	psiLogCb = cb
	psiLogMu.Unlock()
}

//export psi_set_protect_callback
func psi_set_protect_callback(cb C.psi_protect_cb) {
	psiLogMu.Lock()
	psiProtectCb = cb
	psiLogMu.Unlock()
}

// psi_set_network_callbacks installs the host's view of the underlying
// network. Passing NULL for any of them restores the safe default
// (connectivity assumed, no resolvers, unknown network id).
//
//export psi_set_network_callbacks
func psi_set_network_callbacks(
	dns C.psi_dns_cb,
	connectivity C.psi_connectivity_cb,
	networkID C.psi_network_id_cb,
) {
	psiLogMu.Lock()
	psiDnsCb = dns
	psiConnectivityCb = connectivity
	psiNetworkIDCb = networkID
	psiLogMu.Unlock()
}

// psi_start launches the controller.
//
//	configJSON  - the Psiphon config, already rendered by the caller
//	embedded    - embedded server entry list ("" to rely on remote fetch)
//	useBinder   - 1 on Android (route BindToDevice through protect_cb)
//
// Returns 0 on success, or:
//
//	-1 already psiRunning
//	-2 invalid argument
//	-3 psi.Start failed
//
//export psi_start
func psi_start(configJSON *C.char, embedded *C.char, useBinder C.int) C.int {
	psiMu.Lock()

	if psiRunning {
		psiMu.Unlock()
		psiEmit(psiLogWarn, "[psiphon] start ignored: already running")
		return -1
	}

	cfg := C.GoString(configJSON)
	if cfg == "" {
		psiMu.Unlock()
		psiEmit(psiLogError, "[psiphon] empty config json")
		return -2
	}

	// Psiphon creates its datastore *inside* DataRootDirectory with os.Mkdir,
	// which is a single level -- so the root itself has to exist first, or
	// Commit() fails with "failed to create datastore directory". Ours is a
	// fresh subdirectory (filesDir/psiphon, or <exe>/psiphon on desktop) that
	// nothing else creates, so make it here where both platforms share a path.
	if dir := psiDataRootFromConfig(cfg); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			psiMu.Unlock()
			psiEmit(psiLogError, "[psiphon] cannot create data dir %s: %v", dir, err)
			return -2
		}
	}

	// Reset per-session cached psiState. Ports and psiRegions belong to the
	// session that reported them; carrying them over would make a failed
	// start look like it had succeeded.
	psiSocksPort = 0
	psiHttpPort = 0
	psiRegions = nil
	psiState = psiStateStarting
	// Claim the slot before releasing the lock, so a concurrent psi_start
	// still loses the race even though psi.Start() below runs unlocked.
	psiRunning = true
	embeddedList := C.GoString(embedded)
	psiMu.Unlock()

	// psi.Start() is deliberately called WITHOUT psiMu held.
	//
	// It performs the whole datastore open and embedded-server-list import
	// before returning, and it emits notices the entire time. Holding psiMu
	// across it blocked every notice callback, and -- worse -- blocked
	// psi_stop() too, so a cancel arriving during start could not be
	// serviced until start had finished on its own. psi.Start() takes its
	// own controllerMutex upstream, so concurrent entry is still refused
	// there; psiRunning above makes us refuse it earlier and more clearly.
	err := psi.Start(cfg, embeddedList, "", &psiProvider{}, useBinder != 0, false, false)
	if err != nil {
		psiMu.Lock()
		psiRunning = false
		psiState = psiStateStopped
		psiMu.Unlock()
		psiEmit(psiLogError, "[psiphon] start failed: %v", err)
		return -3
	}

	psiEmit(psiLogInfo, "[psiphon] controller started")
	return 0
}

//export psi_stop
func psi_stop() C.int {
	psiMu.Lock()
	if !psiRunning {
		psiMu.Unlock()
		return 0
	}
	psiRunning = false
	psiMu.Unlock()

	// psi.Stop() blocks until the controller goroutine has finished, and it
	// takes psi's own mutex. Calling it while holding psiMu would deadlock
	// against any notice still in flight.
	psi.Stop()

	psiMu.Lock()
	psiState = psiStateStopped
	psiSocksPort = 0
	psiHttpPort = 0
	psiMu.Unlock()

	psiEmit(psiLogInfo, "[psiphon] controller stopped")
	return 0
}

//export psi_state
func psi_state() C.int {
	psiMu.Lock()
	defer psiMu.Unlock()
	return C.int(psiState)
}

//export psi_socks_port
func psi_socks_port() C.int {
	psiMu.Lock()
	defer psiMu.Unlock()
	return C.int(psiSocksPort)
}

//export psi_http_port
func psi_http_port() C.int {
	psiMu.Lock()
	defer psiMu.Unlock()
	return C.int(psiHttpPort)
}

// psi_regions returns the available egress psiRegions as a comma-separated list
// of country codes, or "" if the handshake has not produced them yet.
//
// The caller owns the returned buffer and must release it with
// psi_string_free.
//
//export psi_regions
func psi_regions() *C.char {
	psiMu.Lock()
	list := make([]string, len(psiRegions))
	copy(list, psiRegions)
	psiMu.Unlock()

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

// The combined bridge has one main function in bridge.go.
