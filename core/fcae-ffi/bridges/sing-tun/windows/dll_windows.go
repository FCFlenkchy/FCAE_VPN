//go:build windows

// SPDX-License-Identifier: MIT
// OS-loader replacement for the pinned sing-tun Wintun memory loader.
package wintun

/*
#include <stdint.h>
extern uintptr_t fcae_wintun_load_library(void);
*/
import "C"

import (
	"fmt"
	"golang.org/x/sys/windows"
	"sync"
	"sync/atomic"
)

type lazyDLL struct {
	Name   string
	Base   windows.Handle
	mu     sync.Mutex
	module atomic.Uintptr
}

func newLazyDLL(name string) *lazyDLL            { return &lazyDLL{Name: name} }
func (d *lazyDLL) NewProc(name string) *lazyProc { return &lazyProc{dll: d, Name: name} }
func (d *lazyDLL) Load() error {
	if d.module.Load() != 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module.Load() != 0 {
		return nil
	}
	// The host returns a loader reference to its exact Wintun image. Retain it
	// for this package's process lifetime, as upstream retains its memory image.
	module := uintptr(C.fcae_wintun_load_library())
	if module == 0 {
		return fmt.Errorf("FCAE shared Wintun loader failed; see host log")
	}
	d.Base = windows.Handle(module)
	d.module.Store(module)
	return nil
}

type lazyProc struct {
	Name string
	dll  *lazyDLL
	mu   sync.Mutex
	addr atomic.Uintptr
}

func (p *lazyProc) Find() error {
	if p.addr.Load() != 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr.Load() != 0 {
		return nil
	}
	if err := p.dll.Load(); err != nil {
		return err
	}
	addr, err := windows.GetProcAddress(windows.Handle(p.dll.module.Load()), p.Name)
	if err != nil {
		return fmt.Errorf("Wintun export %s: %w", p.Name, err)
	}
	p.addr.Store(addr)
	return nil
}
func (p *lazyProc) Addr() uintptr {
	if err := p.Find(); err != nil {
		panic(err)
	}
	return p.addr.Load()
}
func (p *lazyProc) Load() error { return p.dll.Load() }
func (p *lazyProc) nameToAddr() (uintptr, error) {
	if err := p.Find(); err != nil {
		return 0, err
	}
	return p.addr.Load(), nil
}
