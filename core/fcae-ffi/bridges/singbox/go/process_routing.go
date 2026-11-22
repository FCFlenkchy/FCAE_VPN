//go:build fcae_singbox

package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef int64_t (*fcae_process_lookup)(uint32_t,const char*,uint16_t,const char*,uint16_t,char*,uint32_t);
static int64_t fcae_find_owner(fcae_process_lookup fn,uint32_t protocol,const char* source,uint16_t sport,const char* destination,uint16_t dport,char* out,uint32_t cap){return fn(protocol,source,sport,destination,dport,out,cap);}
*/
import "C"

import (
	"context"
	stdjson "encoding/json"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// Adapter glue only: socket ownership, retry policy and path normalization
// belong to Rust. The existing engine still owns packet transport.
type appProcessPlatform struct{}

var processLookupMutex sync.RWMutex
var processLookup C.fcae_process_lookup

//export sb_set_process_lookup
func sb_set_process_lookup(callback C.fcae_process_lookup) {
	processLookupMutex.Lock()
	processLookup = callback
	processLookupMutex.Unlock()
}

func appProcessContext(ctx context.Context, text string) (context.Context, error) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return ctx, nil
	}
	var config struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := stdjson.Unmarshal([]byte(text), &config); err != nil {
		return ctx, err
	}
	enabled := false
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "fcae-app-flows" {
			enabled = true
		}
	}
	if !enabled {
		return ctx, nil
	}
	processLookupMutex.RLock()
	ready := processLookup != nil
	processLookupMutex.RUnlock()
	if !ready {
		return ctx, os.ErrInvalid
	}
	return service.ContextWith[adapter.PlatformInterface](ctx, &appProcessPlatform{}), nil
}

func (s *appProcessPlatform) Initialize(networkManager adapter.NetworkManager) error {
	return nil
}

func (s *appProcessPlatform) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}

func (s *appProcessPlatform) AutoDetectInterfaceControl(fd int) error {
	return nil
}

func (s *appProcessPlatform) UsePlatformInterface() bool {
	return false
}

func (s *appProcessPlatform) OpenInterface(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}

func (s *appProcessPlatform) ProcessPlatformOptions(options option.TunPlatformOptions) error {
	return nil
}

func (s *appProcessPlatform) UsePlatformDefaultInterfaceMonitor() bool {
	return false
}

func (s *appProcessPlatform) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return nil
}

func (s *appProcessPlatform) UsePlatformNetworkInterfaces() bool {
	return false
}

func (s *appProcessPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, os.ErrInvalid
}

func (s *appProcessPlatform) UnderNetworkExtension() bool {
	return false
}

func (s *appProcessPlatform) NetworkExtensionIncludeAllNetworks() bool {
	return false
}

func (s *appProcessPlatform) ClearDNSCache() {
}

func (s *appProcessPlatform) RequestPermissionForWIFIState() error {
	return nil
}

func (s *appProcessPlatform) UsePlatformWIFIMonitor() bool {
	return false
}

func (s *appProcessPlatform) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}

func (s *appProcessPlatform) UsePlatformConnectionOwnerFinder() bool { return true }
func (s *appProcessPlatform) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	processLookupMutex.RLock()
	lookup := processLookup
	processLookupMutex.RUnlock()
	if lookup == nil {
		return nil, os.ErrInvalid
	}
	source := C.CString(request.SourceAddress)
	defer C.free(unsafe.Pointer(source))
	destination := C.CString(request.DestinationAddress)
	defer C.free(unsafe.Pointer(destination))
	output := make([]byte, 32769)
	pid := C.fcae_find_owner(lookup, C.uint32_t(request.IpProtocol), source, C.uint16_t(request.SourcePort), destination, C.uint16_t(request.DestinationPort), (*C.char)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)))
	if pid <= 0 || pid > 4294967295 {
		return nil, os.ErrNotExist
	}
	path := C.GoString((*C.char)(unsafe.Pointer(&output[0])))
	if path == "" {
		return nil, os.ErrNotExist
	}
	return &adapter.ConnectionOwner{ProcessID: uint32(pid), ProcessPaths: []string{path}, UserId: -1}, nil
}

func (s *appProcessPlatform) UsePlatformNotification() bool {
	return false
}

func (s *appProcessPlatform) SendNotification(notification *adapter.Notification) error {
	return nil
}

func (s *appProcessPlatform) CancelNotification(identifier string, typeID int32) error {
	return nil
}

// Routes and interface addresses are installed after the packet engine starts.
// Read the current addresses instead of relying on its pre-capture snapshot,
// otherwise local TUN-source flows can be skipped by process attribution.
func (s *appProcessPlatform) MyInterfaceAddress() []netip.Addr {
	addresses, _ := net.InterfaceAddrs()
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			result = append(result, prefix.Addr())
		}
	}
	return result
}

func (s *appProcessPlatform) UsePlatformNeighborResolver() bool {
	return false
}

func (s *appProcessPlatform) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}

func (s *appProcessPlatform) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return nil
}

func (s *appProcessPlatform) UsePlatformShell() bool {
	return false
}

func (s *appProcessPlatform) CheckPlatformShell() error {
	return nil
}

func (s *appProcessPlatform) OpenShellSession(user *adapter.PlatformUser, command string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}

func (s *appProcessPlatform) LookupSFTPServer() (string, error) {
	return "", os.ErrInvalid
}

func (s *appProcessPlatform) ReadSystemSSHHostKey() ([]byte, error) {
	return nil, os.ErrInvalid
}

func (s *appProcessPlatform) TailscaleHostname() string {
	return ""
}

func (s *appProcessPlatform) UsePlatformBridge() bool {
	return false
}

func (s *appProcessPlatform) CreateBridge(options adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

func (s *appProcessPlatform) UsePlatformAutoRedirect() bool {
	return false
}

func (s *appProcessPlatform) CreateAutoRedirect(options adapter.AutoRedirectOptions) (adapter.AutoRedirectSession, error) {
	return nil, os.ErrInvalid
}

func (s *appProcessPlatform) LookupUser(username string) (*adapter.PlatformUser, error) {
	return nil, os.ErrInvalid
}
