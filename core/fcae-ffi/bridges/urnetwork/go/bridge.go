//go:build fcae_urnetwork

package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef int (*ur_protect_fn)(int);
static int ur_invoke_protect(uintptr_t fn, int fd) { return fn ? ((ur_protect_fn)fn)(fd) : -1; }
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/libp2p/go-netroute"
	uc "github.com/urnetwork/connect"
	ur "github.com/urnetwork/sdk"
)

type urRequest struct {
	Op        string `json:"op"`
	Dir       string `json:"data_dir"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Code      string `json:"code"`
	Region    string `json:"region"`
	Transport string `json:"transport"`
	Socks     string `json:"socks"`
	Http      string `json:"http"`
	Proxy     string `json:"proxy"`
	Tun       bool   `json:"tun"`
	ID        uint64 `json:"id"`
}
type urStore struct {
	Email        string                        `json:"email,omitempty"`
	Network      string                        `json:"network,omitempty"`
	Client       string                        `json:"client,omitempty"`
	Instance     string                        `json:"instance,omitempty"`
	Region       string                        `json:"region,omitempty"`
	Transport    string                        `json:"transport,omitempty"`
	Registration *ur.RegisterNetworkClientArgs `json:"registration,omitempty"`
}

var urMu sync.Mutex
var urProtect atomic.Uintptr
var urNext uint64
var urSessions = map[uint64]*urSession{}
var urStores = map[string]*sync.Mutex{}

func urStoreLock(dir string) *sync.Mutex {
	urMu.Lock()
	defer urMu.Unlock()
	m := urStores[dir]
	if m == nil {
		m = &sync.Mutex{}
		urStores[dir] = m
	}
	return m
}
func urPath(dir string) string { return filepath.Join(dir, "urnetwork", "account.json") }
func urLoad(dir string) (urStore, error) {
	var s urStore
	b, e := os.ReadFile(urPath(dir))
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return s, errors.New("cannot read URnetwork account")
	}
	if len(b) > 65536 {
		return s, errors.New("URnetwork account exceeds size limit")
	}
	e = json.Unmarshal(b, &s)
	return s, e
}
func urSave(dir string, s *urStore) error {
	parent := filepath.Dir(urPath(dir))
	if e := os.MkdirAll(parent, 0700); e != nil {
		return errors.New("cannot create URnetwork account directory")
	}
	if e := urPrivate(parent); e != nil {
		return e
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(parent, ".account-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = urPrivate(name); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return errors.New("cannot save URnetwork account")
	}
	return urReplace(name, urPath(dir))
}
func urResult(v any, e error) *C.char {
	if e != nil {
		v = map[string]any{"error": e.Error()}
	}
	b, _ := json.Marshal(v)
	return C.CString(string(b))
}

//export ur_free
func ur_free(p *C.char) { C.free(unsafe.Pointer(p)) }

//export ur_set_protect
func ur_set_protect(fn C.uintptr_t) { urProtect.Store(uintptr(fn)) }

//export ur_call
func ur_call(raw *C.char) (out *C.char) {
	defer func() {
		if recover() != nil {
			out = urResult(nil, errors.New("URnetwork native operation panicked"))
		}
	}()
	var r urRequest
	if raw == nil {
		return urResult(nil, errors.New("empty URnetwork request"))
	}
	if e := json.Unmarshal([]byte(C.GoString(raw)), &r); e != nil {
		return urResult(nil, errors.New("invalid URnetwork request"))
	}
	if r.Op == "stop-all" {
		urMu.Lock()
		all := make(map[uint64]*urSession)
		for id, s := range urSessions {
			all[id] = s
		}
		urMu.Unlock()
		for id, s := range all {
			s.close()
			urMu.Lock()
			delete(urSessions, id)
			urMu.Unlock()
		}
		return urResult(map[string]bool{"ok": true}, nil)
	}
	if r.Op == "stop" || r.Op == "status" {
		urMu.Lock()
		s := urSessions[r.ID]

		urMu.Unlock()
		if s == nil {
			return urResult(map[string]any{"up": false, "alive": false}, nil)
		}
		if r.Op == "stop" {
			s.close()
			urMu.Lock()
			delete(urSessions, r.ID)
			urMu.Unlock()
			return urResult(map[string]bool{"ok": true}, nil)
		}
		return urResult(map[string]any{"up": s.up(), "alive": s.ctx.Err() == nil, "rx": s.rx.Load(), "tx": s.tx.Load()}, nil)
	}
	if r.Dir == "" {
		return urResult(nil, errors.New("URnetwork needs an application data directory"))
	}
	dir, e := filepath.Abs(r.Dir)
	if e != nil {
		return urResult(nil, e)
	}
	r.Dir = dir
	lock := urStoreLock(dir)
	lock.Lock()
	defer lock.Unlock()
	s, e := urLoad(dir)
	if e != nil {
		return urResult(nil, errors.New("cannot load URnetwork account"))
	}
	if r.Op == "load" {
		return urResult(map[string]any{"email": s.Email, "signed_in": s.Network != "", "region": s.Region, "transport": s.Transport}, nil)
	}
	if r.Op == "save" {
		if !urTransportValid(r.Transport) {
			return urResult(nil, errors.New("unsupported URnetwork transport"))
		}
		if r.Region != "" {
			if _, e = ur.ParseId(r.Region); e != nil {
				return urResult(nil, errors.New("invalid URnetwork region"))
			}
		}
		s.Region = r.Region
		s.Transport = r.Transport
		return urResult(map[string]bool{"ok": true}, urSave(dir, &s))
	}
	if r.Op == "logout" {
		urMu.Lock()
		busy := len(urSessions) > 0
		urMu.Unlock()
		if busy {
			return urResult(nil, errors.New("disconnect URnetwork before signing out"))
		}
		s.Network = ""
		s.Client = ""
		s.Email = ""
		s.Instance = ""
		s.Registration = nil
		return urResult(map[string]bool{"ok": true}, urSave(dir, &s))
	}
	urMu.Lock()
	busy := len(urSessions) > 0
	urMu.Unlock()
	if busy {
		return urResult(nil, errors.New("disconnect URnetwork before account or location requests"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	space, e := urSpace(ctx, r.Proxy, r.Tun)
	if e != nil {
		return urResult(nil, e)
	}
	keep := false
	defer func() {
		if !keep {
			space.Close()
		}
	}()
	api := space.GetApi()
	switch r.Op {
	case "login", "verify", "code-login":
		urMu.Lock()
		busy := len(urSessions) > 0
		urMu.Unlock()
		if busy {
			return urResult(nil, errors.New("disconnect URnetwork before signing in"))
		}
		token := ""
		if r.Op == "login" {
			v, err := api.AuthLoginWithPasswordSyncWithContext(ctx, &ur.AuthLoginWithPasswordArgs{UserAuth: r.Email, Password: r.Password, VerifyOtpNumeric: true})
			r.Password = ""
			if err != nil || v == nil {
				return urResult(nil, errors.New("URnetwork sign-in request failed"))
			}
			if v.Error != nil {
				return urResult(nil, errors.New("URnetwork refused sign-in; check your credentials"))
			}
			if v.VerificationRequired != nil {
				return urResult(map[string]any{"verification_required": true, "send_failed": v.VerificationRequired.SendError != nil}, nil)
			}
			if v.Network != nil {
				token = v.Network.ByJwt
			}
		}
		if r.Op == "verify" {
			cb, ch := uc.NewBlockingApiCallback[*ur.AuthVerifyResult](ctx)
			api.AuthVerify(&ur.AuthVerifyArgs{UserAuth: r.Email, VerifyCode: r.Code}, cb)
			select {
			case v := <-ch:
				if v.Error != nil || v.Result == nil || v.Result.Error != nil {
					return urResult(nil, errors.New("URnetwork verification failed"))
				}
				if v.Result.Network != nil {
					token = v.Result.Network.ByJwt
				}
			case <-ctx.Done():
				return urResult(nil, errors.New("URnetwork verification timed out"))
			}
		}
		if r.Op == "code-login" {
			v, err := api.AuthCodeLoginSyncWithContext(ctx, &ur.AuthCodeLoginArgs{AuthCode: r.Code})
			if err != nil || v == nil || v.Error != nil {
				return urResult(nil, errors.New("URnetwork authorization code was refused"))
			}
			token = v.Jwt
		}
		if token == "" {
			return urResult(nil, errors.New("URnetwork did not return an account credential"))
		}
		s.Network = token
		s.Client = ""
		s.Registration = nil
		s.Instance = ""
		s.Email = r.Email
		return urResult(map[string]bool{"signed_in": true}, urSave(dir, &s))
	case "regions":
		if s.Network == "" {
			return urResult(nil, errors.New("sign in to URnetwork first"))
		}
		api.SetByJwt(s.Network)
		cb, ch := uc.NewBlockingApiCallback[*ur.FindLocationsResult](ctx)
		api.GetProviderLocations(cb)
		select {
		case v := <-ch:
			if v.Error != nil || v.Result == nil {
				return urResult(nil, errors.New("cannot load URnetwork provider locations"))
			}
			rows := []map[string]string{}
			if v.Result.Locations != nil {
				for i := 0; i < v.Result.Locations.Len(); i++ {
					l := v.Result.Locations.Get(i)
					if l != nil && l.LocationId != nil && l.ProviderCount > 0 {
						name := l.Name
						if l.Country != "" && l.Country != name {
							name += " · " + l.Country
						}
						rows = append(rows, map[string]string{"id": l.LocationId.String(), "name": name})
					}
				}
			}
			return urResult(map[string]any{"locations": rows}, nil)
		case <-ctx.Done():
			return urResult(nil, errors.New("URnetwork location request timed out"))
		}
	case "start":
		if s.Network == "" {
			return urResult(nil, errors.New("open URnetwork settings and sign in first"))
		}
		api.SetByJwt(s.Network)
		if s.Client == "" {
			if s.Registration == nil {
				var nonce [32]byte
				if _, e = rand.Read(nonce[:]); e != nil {
					return urResult(nil, e)
				}
				scope := sha256.Sum256([]byte("https://api.bringyour.com/network/register-client-v1\x00" + s.Network + "\x00" + dir))
				s.Registration = &ur.RegisterNetworkClientArgs{Schema: ur.NetworkClientRegistrationSchema, RegistrationId: hex.EncodeToString(nonce[:]), ScopeSha256: hex.EncodeToString(scope[:]), DeviceDescription: "FCAE VPN", DeviceSpec: runtime.GOOS + "/" + runtime.GOARCH}
				s.Instance = ur.NewId().String()
				if e = urSave(dir, &s); e != nil {
					return urResult(nil, e)
				}
			}
			v, err := api.RegisterNetworkClientSyncWithContext(ctx, s.Registration)
			if err != nil {
				var unsupported *ur.NetworkClientRegistrationUnsupportedError
				if errors.As(err, &unsupported) {
					return urResult(nil, errors.New("the URnetwork server does not support versioned device registration; no legacy registration was attempted"))
				}
				return urResult(nil, errors.New("URnetwork device registration failed; the original request is saved for a safe retry"))
			}
			if v == nil || v.Error != nil || v.ByClientJwt == "" {
				return urResult(nil, errors.New("URnetwork client registration was refused"))
			}
			s.Client = v.ByClientJwt
			if e = urSave(dir, &s); e != nil {
				return urResult(nil, e)
			}
		}
		instance, e := ur.ParseId(s.Instance)
		if e != nil {
			return urResult(nil, errors.New("invalid saved URnetwork device identity"))
		}
		settings := ur.DefaultDeviceLocalSettings()
		settings.EnableRpc = false
		settings.AllowProvider = false
		settings.DefaultOffline = false
		settings.DefaultRouteLocal = false
		settings.ProvideExtenderEnabled = false
		settings.DefaultProvideExtender = false
		settings.ProvideExtenderWebRtc = false
		settings.DefaultProvideExtenderPortMapping = false
		d, e := ur.NewDeviceLocal(space, s.Client, "FCAE VPN", runtime.GOOS, "FCAE", instance, settings)
		if e != nil {
			return urResult(nil, errors.New("cannot initialize URnetwork device; sign in again if the credential has expired"))
		}
		deviceKept := false
		defer func() {
			if !deviceKept {
				d.Close()
			}
		}()
		ts := ur.DefaultTransportSettings()
		if s.Transport != "" {
			ts.Mode = s.Transport
		}
		d.SetTransportSettings(ts)
		loc := &ur.ConnectLocation{ConnectLocationId: &ur.ConnectLocationId{BestAvailable: true}}
		if s.Region != "" {
			id, err := ur.ParseId(s.Region)
			if err != nil {
				d.Close()
				return urResult(nil, errors.New("invalid saved URnetwork location"))
			}
			loc.ConnectLocationId = &ur.ConnectLocationId{LocationId: id}
		}
		if e = d.SetConnectLocationChecked(loc); e != nil {
			d.Close()
			return urResult(nil, errors.New("cannot select URnetwork exit location"))
		}
		session := newURSession(d, space, dir)
		credentialListener := &urCredentialListener{dir: dir, instance: s.Instance, session: session}
		d.AddJwtRefreshListener(credentialListener)
		credentialListener.JwtRefreshed("")
		d.AddAuthLogoutListener(&urAuthListener{session: session})
		if e = session.listen(r.Socks, r.Http); e != nil {
			session.close()
			return urResult(nil, e)
		}
		// The space has an independent lifetime, owned by this device session.
		keep = true
		urMu.Lock()
		urNext++
		id := urNext
		urSessions[id] = session
		deviceKept = true
		urMu.Unlock()
		return urResult(map[string]any{"id": id, "socks": session.socksAddr, "http": session.httpAddr}, nil)
	default:
		return urResult(nil, errors.New("unknown URnetwork operation"))
	}
}
func urTransportValid(s string) bool {
	switch s {
	case "auto", "h1", "h3", "dns", "dnspump":
		return true
	}
	return false
}
func urSpace(_ context.Context, upstream string, tun bool) (*ur.NetworkSpace, error) {
	settings := uc.DefaultClientStrategySettings()
	// Connect's central egress seam also covers QUIC, DNS and WebRTC sockets.
	uc.SetEgressInterfaceIndex(0, 0)
	var iface *net.Interface
	if tun && upstream == "" && runtime.GOOS != "android" && runtime.GOOS != "ios" {
		router, e := netroute.New()
		if e != nil {
			return nil, errors.New("cannot discover physical URnetwork egress")
		}
		iface, _, _, e = router.Route(net.IPv4(1, 1, 1, 1))
		if e != nil || iface == nil {
			return nil, errors.New("no physical URnetwork egress route")
		}
		uc.SetEgressInterfaceIndex(uint32(iface.Index), uint32(iface.Index))
	}
	uc.SetFCAEEgressControl(func(fd uintptr) error {
		v := int(C.ur_invoke_protect(C.uintptr_t(urProtect.Load()), C.int(fd)))
		if v == 0 {
			return errors.New("URnetwork socket protection refused")
		}
		if v == 1 {
			return nil
		}
		if runtime.GOOS == "android" {
			return errors.New("URnetwork requires VpnService socket protection")
		}
		if tun && iface != nil {
			return urBind(fd, iface.Name)
		}
		return nil
	})
	if upstream != "" {
		p, e := urUpstream(upstream)
		if e != nil {
			return nil, e
		}
		settings.ProxySettings = p
		settings.ConnectSettings.ProxySettings = p
		settings.DialContextSettings = &uc.DialContextSettings{PacketConnFactory: func(ctx context.Context) (net.PacketConn, error) { return urProxyPacket(ctx, p) }}
		settings.ConnectSettings.DialContextSettings = settings.DialContextSettings
	}
	return ur.NewNetworkSpaceWithUrls(context.Background(), "https://api.bringyour.com", "wss://connect.bringyour.com", settings), nil
}
