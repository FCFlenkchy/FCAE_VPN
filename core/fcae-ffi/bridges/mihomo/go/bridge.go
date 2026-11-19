//go:build fcae_mihomo

package main

/*
#include <stdint.h>
#include <stdlib.h>
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
	"os"
	"sync"
	"unsafe"

	"github.com/metacubex/mihomo/config"
	MC "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	mlog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var mihomoMu sync.Mutex
var mihomoID uint64
var mihomoNext uint64
var mihomoHome string
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

//export mihomo_start
func mihomo_start(text *C.char, handle *C.uint64_t) (result *C.char) {
	mihomoMu.Lock()
	defer mihomoMu.Unlock()
	if handle == nil || text == nil {
		return C.CString("invalid Mihomo start arguments")
	}
	*handle = 0
	if mihomoID != 0 {
		return C.CString("Mihomo is already running: this in-process core supports one instance; repeated Mihomo hops are not supported")
	}
	defer func() {
		if failure := recover(); failure != nil {
			mihomoCleanup()
			result = C.CString(fmt.Sprintf("Mihomo start panic: %v", failure))
		}
	}()
	data := []byte(C.GoString(text))
	parsed, err := config.Parse(data)
	if err != nil {
		return C.CString(err.Error())
	}
	// Never create a controller or change the host's network configuration.
	parsed.General.Tun.Enable = false
	parsed.IPTables.Enable = false
	parsed.NTP.Enable = false
	parsed.NTP.WriteToSystem = false
	executor.ApplyConfig(parsed, true)
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
	*handle = C.uint64_t(mihomoID)
	return nil
}

func mihomoCleanup() {
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
	if mihomoID != 0 && mihomoID == uint64(id) && tunnel.Status() == tunnel.Running {
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
