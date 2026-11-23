//go:build fcae_mihomo

package main

/*
#include <stdint.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
static int mihomo_dup_mobile_fd(int fd) { return fcntl(fd,F_DUPFD_CLOEXEC,3); }
#else
static int mihomo_dup_mobile_fd(int fd) { return -1; }
#endif
typedef void (*mihomo_log_fn)(int level, const char *msg);
static void mihomo_invoke_log(mihomo_log_fn fn, int level, const char *msg) {
    if (fn != NULL) fn(level, msg);
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/config"
	MC "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	mlog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var mihomoMu sync.Mutex
var mihomoID uint64
var mihomoNext uint64
var mihomoHome string
var mihomoTun bool
var mihomoBase *config.Config
var mihomoOverlayID uint64
var mihomoOverlayMode tunnel.TunnelMode
var mihomoOverlayProcess process.FindProcessMode

// Delegate every rule method except matching: TUN policy must never intercept
// the SOCKS listener used by this session's existing protocol/chain.
type mihomoTunRule struct{ MC.Rule }

func (r mihomoTunRule) Match(m *MC.Metadata, h MC.RuleMatchHelper) (bool, string) {
	if m.Type != MC.TUN {
		return false, ""
	}
	return r.Rule.Match(m, h)
}

var mihomoInbounds []coreListener
var mihomoLogMu sync.RWMutex
var mihomoSink C.mihomo_log_fn
var mihomoGate int
var mihomoLogOnce sync.Once

//export mihomo_set_log
func mihomo_set_log(sink C.mihomo_log_fn, gate C.int) {
	mihomoLogMu.Lock()
	mihomoSink = sink
	mihomoGate = int(gate)
	mihomoLogMu.Unlock()
	mihomoLogOnce.Do(func() {
		subscription := mlog.Subscribe()
		go func() {
			for event := range subscription {
				level := 3
				switch event.LogLevel {
				case mlog.ERROR:
					level = 1
				case mlog.WARNING:
					level = 2
				case mlog.DEBUG:
					level = 4
				}
				mihomoLogMu.RLock()
				callback, gate := mihomoSink, mihomoGate
				mihomoLogMu.RUnlock()
				if callback != nil && level <= gate {
					text := C.CString(event.Payload)
					C.mihomo_invoke_log(callback, C.int(level), text)
					C.free(unsafe.Pointer(text))
				}
			}
		}()
	})
}

//export mihomo_set_home
func mihomo_set_home(path *C.char) *C.char {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	home := C.GoString(path)
	if mihomoID != 0 && mihomoHome == home {
		return nil
	}
	if mihomoID != 0 || (mihomoHome != "" && mihomoHome != home) {
		return C.CString("Mihomo home is already owned by this process")
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return C.CString(err.Error())
	}
	MC.SetHomeDir(home)
	mihomoHome = home
	return nil
}

//export mihomo_check
func mihomo_check(text *C.char) (result *C.char) {
	defer func() {
		if err := recover(); err != nil {
			result = C.CString(fmt.Sprintf("Mihomo config: %v", err))
		}
	}()
	if text == nil {
		return C.CString("missing Mihomo config")
	}
	// ParseRawConfig constructs adapters, loads geodata and can download
	// providers. Never call it from the editor, especially during a live VPN.
	if _, err := config.UnmarshalRawConfig([]byte(C.GoString(text))); err != nil {
		return C.CString("Mihomo config: " + err.Error())
	}
	var document struct {
		Proxies []map[string]any `json:"proxies"`
		Groups  []map[string]any `json:"proxy-groups"`
	}
	if err := json.Unmarshal([]byte(C.GoString(text)), &document); err != nil {
		return C.CString(err.Error())
	}
	names := make(map[string]bool)
	for _, proxy := range document.Proxies {
		name, _ := proxy["name"].(string)
		kind, _ := proxy["type"].(string)
		if name == "" || names[name] {
			return C.CString("Mihomo proxy names must be nonempty and unique")
		}
		names[name] = true
		switch kind {
		case "ss", "ssr", "socks5", "http", "vmess", "vless", "snell", "trojan", "hysteria", "hysteria2", "wireguard", "tuic", "shadowquic", "gost-relay", "direct", "dns", "reject", "rematch", "ssh", "mieru", "anytls", "sudoku", "masque", "trusttunnel", "openvpn", "tailscale", "zerotier", "easytier":
		default:
			return C.CString("unknown Mihomo proxy type: " + kind)
		}
	}
	for _, group := range document.Groups {
		name, _ := group["name"].(string)
		kind, _ := group["type"].(string)
		if name == "" || names[name] {
			return C.CString("Mihomo group names must be nonempty and unique")
		}
		names[name] = true
		switch kind {
		case "select", "url-test", "fallback", "load-balance":
		default:
			return C.CString("unsupported Mihomo group type: " + kind + "; relay was removed upstream; use dialer-proxy")
		}
	}
	return nil
}

//export mihomo_start
func mihomo_start(text *C.char, handle *C.uint64_t) *C.char { return mihomoStart(text, handle, false) }

//export mihomo_tun_start
func mihomo_tun_start(text *C.char, handle *C.uint64_t) *C.char {
	return mihomoStart(text, handle, true)
}

func mihomoStart(text *C.char, handle *C.uint64_t, allowTun bool) (result *C.char) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if handle == nil || text == nil {
		return C.CString("invalid Mihomo start arguments")
	}
	*handle = 0
	if mihomoID != 0 && !allowTun {
		return C.CString("Mihomo is already running: repeated Mihomo protocol hops are not supported")
	}
	if allowTun && mihomoOverlayID != 0 {
		return C.CString("Mihomo TUN is already attached")
	}
	defer func() {
		if failure := recover(); failure != nil {
			if mihomoID != 0 && allowTun {
				mihomoDetachTun()
			} else {
				mihomoCleanup()
			}
			result = C.CString(fmt.Sprintf("Mihomo start panic: %v", failure))
		}
	}()
	data := []byte(C.GoString(text))
	parsed, err := config.Parse(data)
	if err != nil {
		return C.CString(err.Error())
	}
	// Never create a controller or change the host's network configuration.
	parsed.General.Tun.Enable = allowTun
	if allowTun {
		var extra struct {
			Addresses []string `json:"fcae-tun-addresses"`
			FD        *int     `json:"fcae-mobile-fd"`
		}
		if err = json.Unmarshal(data, &extra); err != nil {
			return C.CString(err.Error())
		}
		parsed.General.Tun.Inet4Address = nil
		parsed.General.Tun.Inet6Address = nil
		for _, text := range extra.Addresses {
			prefix, e := netip.ParsePrefix(text)
			if e != nil {
				return C.CString(e.Error())
			}
			if prefix.Addr().Is4() {
				parsed.General.Tun.Inet4Address = append(parsed.General.Tun.Inet4Address, prefix)
			} else {
				parsed.General.Tun.Inet6Address = append(parsed.General.Tun.Inet6Address, prefix)
			}
		}
		if len(parsed.General.Tun.Inet4Address) != 1 {
			return C.CString("Mihomo TUN requires one IPv4 address")
		}

		if extra.FD != nil {
			if *extra.FD < 0 || (runtime.GOOS != "android" && runtime.GOOS != "ios") {
				return C.CString("system TUN descriptor requires a mobile VPN host")
			}
			parsed.General.Tun.FileDescriptor = *extra.FD
			parsed.General.Tun.AutoDetectInterface = false
		}
		parsed.General.Tun.AutoRoute = false
		parsed.General.Tun.AutoRedirect = false
	}
	if allowTun && mihomoID != 0 {
		return mihomoAttachTun(parsed, handle)
	}
	parsed.IPTables.Enable = false
	parsed.NTP.Enable = false
	parsed.NTP.WriteToSystem = false
	if allowTun {
		if error := mihomoOwnTunFd(parsed); error != nil {
			return error
		}
	}
	executor.ApplyConfig(parsed, true)
	if allowTun {
		actual := listener.GetTunConf()
		if !actual.Enable || actual.Device != parsed.General.Tun.Device {
			mihomoCleanup()
			return C.CString("Mihomo TUN could not start its requested adapter")
		}
	}
	if tunnel.Status() != tunnel.Running {
		mihomoCleanup()
		return C.CString("Mihomo did not reach running state")
	}
	var raw struct {
		Socks int  `json:"socks-port"`
		HTTP  int  `json:"port"`
		Mixed int  `json:"mixed-port"`
		LAN   bool `json:"allow-lan"`
	}
	if err = json.Unmarshal(data, &raw); err != nil {
		mihomoCleanup()
		return C.CString(err.Error())
	}
	actual := listener.GetPorts()
	if actual.SocksPort != raw.Socks || actual.Port != raw.HTTP || actual.MixedPort != raw.Mixed {
		mihomoCleanup()
		return C.CString("Mihomo could not bind its configured listeners")
	}
	mihomoInbounds = nil
	for _, entry := range []struct {
		proto string
		port  int
	}{{"socks", raw.Socks}, {"http", raw.HTTP}, {"mixed", raw.Mixed}} {
		if entry.port != 0 {
			mihomoInbounds = append(mihomoInbounds, coreListener{proto: entry.proto, port: entry.port, any: raw.LAN})
		}
	}
	statistic.DefaultManager.ResetStatistic()
	mihomoNext++
	mihomoID = mihomoNext
	engineStarted(engineMihomo)
	mihomoTun = allowTun
	mihomoBase = parsed
	*handle = C.uint64_t(mihomoID)
	return nil
}

func mihomoCleanup() {
	wasRunning := mihomoID != 0
	defer func() {
		if wasRunning {
			engineStopped(engineMihomo)
		}
	}()
	mihomoDetachTun()
	mihomoBase = nil
	mihomoTun = false
	tunnel.OnSuspend()
	listener.Cleanup()
	statistic.DefaultManager.Range(func(connection statistic.Tracker) bool { _ = connection.Close(); return true })
	for _, provider := range tunnel.Providers() {
		if closer, ok := provider.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, provider := range tunnel.RuleProviders() {
		if closer, ok := provider.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	// Reset resolvers, providers, profile and background services without
	// terminating the application's shared Go runtime.
	if empty, err := config.Parse([]byte(`{"log-level":"silent","dns":{"enable":false},"profile":{"store-selected":false,"store-fake-ip":false}}`)); err == nil {
		executor.ApplyConfig(empty, true)
		listener.Cleanup()
	}
	tunnel.OnSuspend()
	mihomoID = 0
	mihomoInbounds = nil
}

//export mihomo_stop
func mihomo_stop(id C.uint64_t) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if mihomoID != 0 && mihomoID == uint64(id) {
		mihomoCleanup()
	}
}

//export mihomo_stop_all
func mihomo_stop_all() {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if mihomoID != 0 {
		mihomoCleanup()
	}
}

//export mihomo_running
func mihomo_running(id C.uint64_t) C.int {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if mihomoID != 0 && mihomoID == uint64(id) && tunnel.Status() == tunnel.Running && (!mihomoTun || listener.GetTunConf().Enable) {
		return 1
	}
	return 0
}

//export mihomo_stats
func mihomo_stats(id C.uint64_t, up *C.int64_t, down *C.int64_t) C.int {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if mihomoID == 0 || mihomoID != uint64(id) || up == nil || down == nil {
		return 0
	}
	uploaded, downloaded := statistic.DefaultManager.Total()
	*up = C.int64_t(uploaded)
	*down = C.int64_t(downloaded)
	return 1
}

//export mihomo_listeners
func mihomo_listeners(buf *C.char, capacity C.int) C.int {
	if buf == nil || capacity <= 0 {
		return 0
	}
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	var records []string
	if mihomoID != 0 {
		for _, inbound := range mihomoInbounds {
			records = append(records, coreRecord(mihomoID, "", inbound))
		}
	}
	return writeCoreRecords(buf, capacity, records)
}

//export mihomo_string_free
func mihomo_string_free(value *C.char) { C.free(unsafe.Pointer(value)) }

func mihomoAttachTun(parsed *config.Config, handle *C.uint64_t) *C.char {
	if mihomoBase == nil || mihomoTun {
		return C.CString("Mihomo backend is not attachable")
	}

	proxies := make(map[string]MC.Proxy, len(tunnel.Proxies())+2)
	for name, value := range tunnel.Proxies() {
		proxies[name] = value
	}
	for _, name := range []string{"fcae-tun-exit", "fcae-tun-direct"} {
		if _, exists := proxies[name]; exists {
			return C.CString("reserved Mihomo TUN proxy name is already in use")
		}
		proxy, ok := parsed.Proxies[name]
		if !ok {
			return C.CString("missing Mihomo TUN proxy")
		}
		proxies[name] = proxy
	}
	rules := make([]MC.Rule, 0, len(parsed.Rules)+len(mihomoBase.Rules)+1)
	for _, rule := range parsed.Rules {
		rules = append(rules, mihomoTunRule{rule})
	}
	mihomoOverlayMode = tunnel.Mode()
	mihomoOverlayProcess = tunnel.FindProcessMode()
	switch mihomoOverlayMode {
	case tunnel.Direct:
		rules = append(rules, common.NewMatch("DIRECT"))
	case tunnel.Global:
		rules = append(rules, common.NewMatch("GLOBAL"))
	default:
		rules = append(rules, mihomoBase.Rules...)
	}
	// Publish the handle before modifying shared state so panic rollback can
	// restore the backend without suspending it or closing its listeners.
	mihomoNext++
	mihomoOverlayID = mihomoNext
	tunnel.UpdateProxies(proxies, tunnel.Providers())
	tunnel.UpdateRules(rules, mihomoBase.SubRules, tunnel.RuleProviders())
	tunnel.SetMode(tunnel.Rule)
	if runtime.GOOS != "android" && runtime.GOOS != "ios" {
		tunnel.SetFindProcessMode(parsed.General.FindProcessMode)
	}
	if error := mihomoOwnTunFd(parsed); error != nil {
		mihomoDetachTun()
		return error
	}
	listener.ReCreateTun(parsed.General.Tun, tunnel.Tunnel)
	actual := listener.GetTunConf()
	if !actual.Enable || actual.Device != parsed.General.Tun.Device {
		mihomoDetachTun()
		return C.CString("Mihomo TUN could not attach its requested adapter")
	}
	*handle = C.uint64_t(mihomoOverlayID)
	return nil
}

func mihomoDetachTun() {
	if mihomoOverlayID == 0 {
		return
	}
	mihomoOverlayID = 0
	if mihomoBase == nil {
		return
	}
	off := listener.GetTunConf()
	off.Enable = false
	listener.ReCreateTun(off, tunnel.Tunnel)
	statistic.DefaultManager.Range(func(connection statistic.Tracker) bool {
		if info := connection.Info(); info != nil && info.Metadata != nil && info.Metadata.Type == MC.TUN {
			_ = connection.Close()
		}
		return true
	})
	tunnel.UpdateRules(mihomoBase.Rules, mihomoBase.SubRules, tunnel.RuleProviders())
	tunnel.UpdateProxies(mihomoBase.Proxies, tunnel.Providers())
	tunnel.SetMode(mihomoOverlayMode)
	tunnel.SetFindProcessMode(mihomoOverlayProcess)
}

//export mihomo_tun_stop
func mihomo_tun_stop(id C.uint64_t) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if mihomoOverlayID != 0 && mihomoOverlayID == uint64(id) {
		mihomoDetachTun()
		return
	}
	if mihomoTun && mihomoID != 0 && mihomoID == uint64(id) {
		mihomoCleanup()
	}
}

//export mihomo_tun_running
func mihomo_tun_running(id C.uint64_t) C.int {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if ((mihomoOverlayID != 0 && mihomoOverlayID == uint64(id)) || (mihomoTun && mihomoID != 0 && mihomoID == uint64(id))) && tunnel.Status() == tunnel.Running && listener.GetTunConf().Enable {
		return 1
	}
	return 0
}

func mihomoOwnTunFd(parsed *config.Config) *C.char {
	if (runtime.GOOS == "android" || runtime.GOOS == "ios") && parsed.General.Tun.FileDescriptor >= 0 {
		fd := int(C.mihomo_dup_mobile_fd(C.int(parsed.General.Tun.FileDescriptor)))
		if fd < 0 {
			return C.CString("duplicate system VPN descriptor failed")
		}
		parsed.General.Tun.FileDescriptor = fd
	}
	return nil
}
