// Package main is a C-ABI shim over Psiphon's MobileLibrary/psi.
//
// Desktop only. Android must use the official Psiphon AAR
// (ca.psiphon:psiphontunnel / android/psiphon), not this c-archive.
// Stuffing psi into tun2socks' Go runtime, or loading a second Go
// runtime next to libfcae_go_bridge.so, SIGSEGVs at dlopen.
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

	// Handshake: Tunnels count>0 is not enough — SOCKS can listen and a
	// tunnel can be counted before ConnectedServerRegion. TUN waits on
	// psiStateConnected, which requires both.
	psiTunnelCount int
	psiHaveRegion  bool

	psiSocksPort int
	psiHttpPort  int

	// Effective local-proxy bind IP, derived from ListenInterface ("any" →
	// 0.0.0.0, "" → 127.0.0.1). Session-scoped like the ports; only used so
	// log lines name the address the proxies actually bound.
	psiListenIP = "127.0.0.1"

	// Cumulative tunneled bytes from BytesTransferred notices (deltas --
	// accumulate). Read by psi_bytes() for the UI/notification counters.
	psiBytesUp   uint64
	psiBytesDown uint64


	// psiRegions is the set of egress psiRegions the server reported.
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

func psiUpdateStateLocked() {
	if !psiRunning {
		psiState = psiStateStopped
		return
	}
	if psiTunnelCount > 0 && psiHaveRegion {
		psiState = psiStateConnected
	} else {
		psiState = psiStateStarting
	}
}

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

// psiListenIPFromConfig mirrors the controller's ListenInterface mapping
// ("any" → 0.0.0.0, empty → 127.0.0.1) so log lines name the address the
// local proxies actually bound. Anything else is echoed verbatim.
func psiListenIPFromConfig(configJSON string) string {
	var probe struct {
		ListenInterface string `json:"ListenInterface"`
	}
	if err := json.Unmarshal([]byte(configJSON), &probe); err != nil {
		return "127.0.0.1"
	}
	switch probe.ListenInterface {
	case "any":
		return "0.0.0.0"
	case "":
		return "127.0.0.1"
	default:
		return probe.ListenInterface
	}
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

// psiBootstrapDNS is the resolver set tunnel-core may use for its OWN
// lookups (fronting domains, server-list hosts, tactics). Same list the
// config's DNSResolver*AlternateServers carry; keep them in sync.
const psiBootstrapDNS = "208.67.222.222:5353,9.9.9.9:9953,208.67.220.220:5353"

// GetDNSServersAsString returns the resolvers tunnel-core treats as the
// "system" list, comma delimited.
//
// This is not optional on Android. Once DeviceBinder is configured, upstream
// disables the standard library resolver (it would route inside the VPN), so
// this list is the ONLY source of DNS servers. Returning "" left the resolver
// with an empty server set and every lookup failed with "no DNS servers".
//
// It deliberately never reports the OS or carrier resolvers. tunnel-core
// appends this list behind its preferred alternate server, so the underlying
// network's resolvers were a live path back to an operator-controlled server
// -- the one answering UDP/53 with a bogon on hijacking networks. With the
// same public alternate-port resolvers here, every entry tunnel-core can
// try is one we chose. The host callback (Android) is consulted first and
// is expected to return the same list; desktop has no callback and gets the
// constant, so tunnel-core never falls through to /etc/resolv.conf or the
// adapter DNS.
func (p *psiProvider) GetDNSServersAsString() string {
	psiLogMu.Lock()
	cb := psiDnsCb
	psiLogMu.Unlock()
	if cb != nil {
		if list := psiTakeCString(C.psi_call_dns(cb)); list != "" {
			return list
		}
	}
	return psiBootstrapDNS
}

func (p *psiProvider) OnAccessToken(_ string) {}

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
			listenIP := psiListenIP
			psiMu.Unlock()
			psiEmit(psiLogInfo, "[psiphon] socks proxy on %s:%d", listenIP, d.Port)
		}

	case "ListeningHttpProxyPort":
		var d struct {
			Port int `json:"port"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Port > 0 {
			psiMu.Lock()
			psiHttpPort = d.Port
			listenIP := psiListenIP
			psiMu.Unlock()
			psiEmit(psiLogInfo, "[psiphon] http proxy on %s:%d", listenIP, d.Port)
		}

	case "Tunnels":
		var d struct {
			Count int `json:"count"`
		}
		if json.Unmarshal(n.Data, &d) == nil {
			psiMu.Lock()
			psiTunnelCount = d.Count
			psiUpdateStateLocked()
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
			psiMu.Lock()
			merged := make(map[string]bool)
			for _, r := range psiRegions {
				if r != "" {
					merged[r] = true
				}
			}
			for _, r := range d.Regions {
				if r != "" {
					merged[strings.ToUpper(r)] = true
				}
			}
			list := make([]string, 0, len(merged))
			for r := range merged {
				list = append(list, r)
			}
			sort.Strings(list)
			psiRegions = list
			psiMu.Unlock()
			psiEmit(psiLogInfo, "[psiphon] %d egress regions available", len(list))
		}

	case "ConnectedServerRegion":
		var d struct {
			ServerRegion string `json:"serverRegion"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.ServerRegion != "" {
			reg := strings.ToUpper(d.ServerRegion)
			psiMu.Lock()
			psiHaveRegion = true
			found := false
			for _, r := range psiRegions {
				if r == reg {
					found = true
					break
				}
			}
			if !found {
				psiRegions = append(psiRegions, reg)
				sort.Strings(psiRegions)
			}
			psiUpdateStateLocked()
			psiMu.Unlock()
		}

	case "CandidateServers":
		var d struct {
			Region string `json:"region"`
		}
		if json.Unmarshal(n.Data, &d) == nil && d.Region != "" {
			reg := strings.ToUpper(d.Region)
			psiMu.Lock()
			found := false
			for _, r := range psiRegions {
				if r == reg {
					found = true
					break
				}
			}
			if !found {
				psiRegions = append(psiRegions, reg)
				sort.Strings(psiRegions)
			}
			psiMu.Unlock()
		}

	case "BytesTransferred":
		// Fields are deltas since the previous notice, not totals.
		var d struct {
			Sent     uint64 `json:"sent"`
			Received uint64 `json:"received"`
		}
		if json.Unmarshal(n.Data, &d) == nil && (d.Sent > 0 || d.Received > 0) {
			atomic.AddUint64(&psiBytesUp, d.Sent)
			atomic.AddUint64(&psiBytesDown, d.Received)
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
// (connectivity assumed, the pinned bootstrap resolvers, unknown network id).
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
// Before launching the controller, psi_start guarantees a server-entry
// source by falling back to the legacy public remote server list; see
// psiEnsureServerEntrySource below.
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

	// Reset per-session cached psiState.
	psiSocksPort = 0
	psiHttpPort = 0
	psiTunnelCount = 0
	psiHaveRegion = false
	psiListenIP = psiListenIPFromConfig(cfg)
	atomic.StoreUint64(&psiBytesUp, 0)
	atomic.StoreUint64(&psiBytesDown, 0)
	psiState = psiStateStarting
	// Claim the slot before releasing the lock, so a concurrent psi_start
	// still loses the race even though psi.Start() below runs unlocked.
	psiRunning = true
	embeddedList := C.GoString(embedded)
	if embeddedList != "" {
		re := regexp.MustCompile(`"(?:region|Region)"\s*:\s*"([A-Za-z]{2})"`)
		matches := re.FindAllStringSubmatch(embeddedList, -1)
		if len(matches) > 0 {
			merged := make(map[string]bool)
			for _, r := range psiRegions {
				if r != "" {
					merged[r] = true
				}
			}
			for _, m := range matches {
				if len(m) > 1 && m[1] != "" {
					merged[strings.ToUpper(m[1])] = true
				}
			}
			list := make([]string, 0, len(merged))
			for r := range merged {
				list = append(list, r)
			}
			sort.Strings(list)
			psiRegions = list
		}
	}
	psiMu.Unlock()

	cfg = psiEnsureServerEntrySource(cfg, embeddedList)

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

// Legacy PUBLIC remote server list + signature key, as shipped in the
// open-source Psiphon 3 clients. Bootstrap source for configs without any server-entry
// source; legacy infrastructure that may be retired upstream.
const (
	psiDefaultServerListURL = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	psiDefaultServerListKey = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH" +
		"5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5" +
		"OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot" +
		"LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6" +
		"/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G" +
		"stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O" +
		"geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8" +
		"u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz" +
		"31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal" +
		"KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
)

// Standard ed25519 public key verifying individually signed server entries
// (DSL fetches, server-pushed updates); the same value the open-source
// Psiphon clients embed. Without it every tunneled DSL fetch fails with
// "VerifySignature: missing public key" even after the tunnel is up.
const psiDefaultServerEntrySignatureKey = "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA="

// psiEnsureServerEntrySource returns configJSON with a server-entry source
// guaranteed: an embedded list counts (the caller passes it to Start), and
// otherwise the config is probed for the remote/obfuscated list fields. When
// none is present, the legacy public remote server list is injected so a
// fresh datastore can bootstrap instead of dying on CandidateServers count 0
// ("no capable servers", then "untunneled DSL fetch ... no broker specs" —
// broker specs are derived from server entries). User config always wins.
//
// Independently of the source, the entry-signature key is defaulted when the
// config does not set one, so out-of-band entries verify instead of failing
// with "missing public key".
func psiEnsureServerEntrySource(configJSON, embedded string) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &probe); err != nil {
		return configJSON // psi.Start will report the malformed config
	}

	changed := false
	if _, ok := probe["ServerEntrySignaturePublicKey"]; !ok {
		probe["ServerEntrySignaturePublicKey"] = json.RawMessage(`"` + psiDefaultServerEntrySignatureKey + `"`)
		changed = true
	}

	if embedded == "" {
		hasSource := false
		for _, key := range []string{
			"RemoteServerListUrl", "RemoteServerListURLs",
			"ObfuscatedServerListRootURL", "ObfuscatedServerListRootURLs",
			"TargetServerEntry",
		} {
			if _, ok := probe[key]; ok {
				hasSource = true
				break
			}
		}
		if !hasSource {
			probe["RemoteServerListUrl"] = json.RawMessage(`"` + psiDefaultServerListURL + `"`)
			probe["RemoteServerListSignaturePublicKey"] = json.RawMessage(`"` + psiDefaultServerListKey + `"`)
			changed = true
			psiEmit(psiLogInfo,
				"[psiphon] no server entry source configured; using the built-in legacy public remote server list")
		}
	}

	if !changed {
		return configJSON
	}
	out, err := json.Marshal(probe)
	if err != nil {
		return configJSON
	}
	return string(out)
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
	psiTunnelCount = 0
	psiHaveRegion = false
	psiListenIP = "127.0.0.1"
	atomic.StoreUint64(&psiBytesUp, 0)
	atomic.StoreUint64(&psiBytesDown, 0)
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

// psi_bytes reports cumulative tunneled bytes through the out-params.
//
//export psi_bytes
func psi_bytes(up *C.longlong, down *C.longlong) {
	if up != nil {
		*up = C.longlong(atomic.LoadUint64(&psiBytesUp))
	}
	if down != nil {
		*down = C.longlong(atomic.LoadUint64(&psiBytesDown))
	}
}

//export psi_string_free
func psi_string_free(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// c-archive / c-shared require a main package.
func main() {}
