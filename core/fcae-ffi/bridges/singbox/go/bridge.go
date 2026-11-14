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
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"sync"
	"unsafe"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

var (
	sbMu sync.Mutex
	// Non-nil exactly between a successful Start and Close.
	sbInstance *box.Box
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
	// build carries. box.New refuses to run without those registries, and an
	// empty context fails with "missing ... registry in context".
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(text))
	if err != nil {
		return C.CString("sing-box: config: " + err.Error())
	}
	created, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return C.CString("sing-box: " + err.Error())
	}
	if err = created.Start(); err != nil {
		_ = created.Close()
		return C.CString("sing-box: " + err.Error())
	}
	sbInstance = created
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

//export sb_string_free
func sb_string_free(value *C.char) {
	C.free(unsafe.Pointer(value))
}
