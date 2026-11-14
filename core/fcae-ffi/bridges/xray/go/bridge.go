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
// own `start`.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"sync"
	"unsafe"

	xcore "github.com/xtls/xray-core/core"
	// Registers the JSON config loader and every inbound/outbound proxy, the
	// same set the `xray` executable carries.
	_ "github.com/xtls/xray-core/main/distro/all"
)

var (
	xrayMu       sync.Mutex
	xrayInstance *xcore.Instance
)

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

//export xray_string_free
func xray_string_free(value *C.char) {
	C.free(unsafe.Pointer(value))
}
