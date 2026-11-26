//go:build fcae_urnetwork

package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef void (*ur_log_fn)(uint32_t level, const char *message);
static void ur_emit_log(ur_log_fn sink, uint32_t level, const char *message) {
    if (sink) sink(level, message);
}
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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/libp2p/go-netroute"
	uc "github.com/urnetwork/connect"
	ur "github.com/urnetwork/sdk"
)

type urRequest struct {
	AccountID string `json:"account_id"`
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
type urBalance struct {
	Available int64 `json:"available"`
	Start     int64 `json:"start"`
	Pending   int64 `json:"pending"`
	UpdatedAt int64 `json:"updated_at"`
}

func (b *urBalance) display() string {
	if b == nil {
		return ""
	}
	// Match the SDK's used-balance definition. Pending transfers are reserved,
	// not used; the independently sampled values can temporarily exceed start.
	total := b.Start
	if total < 0 {
		total = 0
	}
	used := total
	if b.Available > 0 {
		if b.Available >= used {
			used = 0
		} else {
			used -= b.Available
		}
	}
	if b.Pending > 0 {
		if b.Pending >= used {
			used = 0
		} else {
			used -= b.Pending
		}
	}
	if used < 0 {
		used = 0
	}
	// Start is the server's start-of-day balance, not a fixed quota.
	// Increase precision only when a rounded display would hide remaining data.
	for precision := 1; precision <= 10; precision++ {
		usedText, totalText := urFormatGiB(used, precision), urFormatGiB(total, precision)
		if used == total || usedText != totalText {
			return usedText + " / " + totalText
		}
	}
	return fmt.Sprintf("%d B / %d B", used, total)
}

type urAccount struct {
	ID           string                        `json:"id"`
	Email        string                        `json:"email"`
	Network      string                        `json:"network"`
	Client       string                        `json:"client,omitempty"`
	Instance     string                        `json:"instance,omitempty"`
	Registration *ur.RegisterNetworkClientArgs `json:"registration,omitempty"`
	Usage        *urBalance                    `json:"usage,omitempty"`
}
type urStore struct {
	Selected     string                        `json:"selected,omitempty"`
	Accounts     []urAccount                   `json:"accounts,omitempty"`
	Locations    []map[string]string           `json:"locations,omitempty"`
	LocationsAt  int64                         `json:"locations_at,omitempty"`
	Email        string                        `json:"email,omitempty"`
	Network      string                        `json:"network,omitempty"`
	Client       string                        `json:"client,omitempty"`
	Instance     string                        `json:"instance,omitempty"`
	Region       string                        `json:"region,omitempty"`
	Transport    string                        `json:"transport,omitempty"`
	Registration *ur.RegisterNetworkClientArgs `json:"registration,omitempty"`
}

// NetworkSpace changes a process-global egress seam. Serialize control
// operations across data directories, not just within one account store.
var urControlMu sync.Mutex
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
	if len(b) > 2*1024*1024 {
		return s, errors.New("URnetwork account exceeds size limit")
	}
	e = json.Unmarshal(b, &s)
	if e == nil && s.Network != "" && s.Selected == "" {
		s.Selected = urAccountID(s.Email, s.Network)
		s.remember()
	}
	return s, e
}
func urAccountID(email, token string) string {
	identity := strings.ToLower(strings.TrimSpace(email))
	if identity == "" {
		identity = token
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:16])
}
func (s *urStore) remember() {
	if s.Network == "" || s.Selected == "" {
		return
	}
	a := urAccount{ID: s.Selected, Email: s.Email, Network: s.Network, Client: s.Client, Instance: s.Instance, Registration: s.Registration}
	for i := range s.Accounts {
		if s.Accounts[i].ID == a.ID {
			a.Usage = s.Accounts[i].Usage
			s.Accounts[i] = a
			return
		}
	}
	s.Accounts = append(s.Accounts, a)
}
func (s *urStore) activate(id string) bool {
	for _, a := range s.Accounts {
		if a.ID == id {
			s.Selected, s.Email, s.Network, s.Client, s.Instance, s.Registration = a.ID, a.Email, a.Network, a.Client, a.Instance, a.Registration
			return true
		}
	}
	return false
}
func urSnapshot(s *urStore) map[string]any {
	rows := []map[string]string{}
	for _, a := range s.Accounts {
		row := map[string]string{"id": a.ID, "email": a.Email}
		if a.Usage != nil {
			row["usage"] = a.Usage.display()
			row["usage_updated"] = time.Unix(a.Usage.UpdatedAt, 0).UTC().Format(time.RFC3339)
		}
		rows = append(rows, row)
	}
	return map[string]any{"email": s.Email, "signed_in": s.Network != "", "selected": s.Selected, "accounts": rows, "region": s.Region, "transport": s.Transport, "locations": s.Locations, "locations_stale": time.Now().Unix()-s.LocationsAt >= 900}
}
func urSave(dir string, s *urStore) error {
	s.remember()
	if len(s.Accounts) > 32 {
		return errors.New("URnetwork account limit reached (32)")
	}
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
	if len(b) > 2*1024*1024 {
		return errors.New("URnetwork account store exceeds size limit")
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

//export ur_set_log_level
func ur_set_log_level(level C.uint32_t) { urSetLogLevel(uint32(level)) }

// Android loads this shared Go library before the native host. Never import a
// host logging symbol: the host registers its process-lifetime callback later.
var urLogSinkMu sync.RWMutex
var urLogSink C.ur_log_fn

//export ur_set_log_callback
func ur_set_log_callback(sink C.ur_log_fn) {
	urLogSinkMu.Lock()
	urLogSink = sink
	urLogSinkMu.Unlock()
}

func urWriteLog(level uint32, message string) {
	urLogSinkMu.RLock()
	sink := urLogSink
	urLogSinkMu.RUnlock()
	if sink == nil {
		return
	}
	text := C.CString(message)
	defer C.free(unsafe.Pointer(text))
	C.ur_emit_log(sink, C.uint32_t(level), text)
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
		return urResult(s.status(), nil)
	}
	urControlMu.Lock()
	defer urControlMu.Unlock()
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
		return urResult(urSnapshot(&s), nil)
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
	// Account and preference changes affect future sessions. Existing devices keep
	// their own credentials, location and transport until they are stopped.
	if r.Op == "select" {
		if !s.activate(r.AccountID) {
			return urResult(nil, errors.New("URnetwork account not found"))
		}
		err := urSave(dir, &s)
		return urResult(urSnapshot(&s), err)
	}
	if r.Op == "remove" || r.Op == "logout" {
		id := r.AccountID
		if id == "" {
			id = s.Selected
		}
		found := false
		for i, a := range s.Accounts {
			if a.ID == id {
				s.Accounts = append(s.Accounts[:i], s.Accounts[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return urResult(nil, errors.New("URnetwork account not found"))
		}
		if id == s.Selected {
			s.Selected, s.Email, s.Network, s.Client, s.Instance, s.Registration = "", "", "", "", "", nil
			if len(s.Accounts) > 0 {
				s.activate(s.Accounts[0].ID)
			}
		}
		err := urSave(dir, &s)
		return urResult(urSnapshot(&s), err)
	}
	if r.Op == "regions" && s.LocationsAt > 0 && time.Now().Unix()-s.LocationsAt < 900 {
		return urResult(urSnapshot(&s), nil)
	}
	timeout := 60 * time.Second
	if r.Op == "usage" {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// The egress controls are process-global. Never replace an active device's
	// routing/protection while servicing account requests.
	urMu.Lock()
	active := len(urSessions) > 0
	urMu.Unlock()
	space, e := urSpace(ctx, r.Proxy, r.Tun, !active || r.Op == "start")
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
		if len(s.Accounts) >= 32 {
			id := urAccountID(r.Email, token)
			exists := false
			for _, a := range s.Accounts {
				if a.ID == id {
					exists = true
				}
			}
			if !exists {
				return urResult(nil, errors.New("URnetwork account limit reached (32)"))
			}
		}
		s.Selected = urAccountID(r.Email, token)
		s.Network = token
		s.Client = ""
		s.Registration = nil
		s.Instance = ""
		s.Email = r.Email
		err := urSave(dir, &s)
		return urResult(urSnapshot(&s), err)
	case "verify-send":
		// A one-time code by email: how an account without a password signs
		// in, and the resend for a verification that is already pending. The
		// code is redeemed by "verify".
		email := strings.TrimSpace(r.Email)
		if email == "" {
			return urResult(nil, errors.New("enter the account email first"))
		}
		cb, ch := uc.NewBlockingApiCallback[*ur.AuthVerifySendResult](ctx)
		api.AuthVerifySend(&ur.AuthVerifySendArgs{UserAuth: email, UseNumeric: true, ResultErrors: true}, cb)
		select {
		case v := <-ch:
			if v.Error != nil || v.Result == nil {
				return urResult(nil, errors.New("URnetwork could not send a verification code"))
			}
			if failure := v.Result.Error; failure != nil {
				if failure.RetryAfterSeconds > 0 {
					return urResult(nil, fmt.Errorf("URnetwork sent a code recently; request another in %d seconds", failure.RetryAfterSeconds))
				}
				return urResult(nil, errors.New("URnetwork could not send a verification code"))
			}
			return urResult(map[string]any{"sent": true}, nil)
		case <-ctx.Done():
			return urResult(nil, errors.New("URnetwork verification code request timed out"))
		}
	case "usage":
		id := r.AccountID
		if id == "" {
			id = s.Selected
		}
		index := -1
		for i := range s.Accounts {
			if s.Accounts[i].ID == id {
				index = i
				break
			}
		}
		if index < 0 || s.Accounts[index].Network == "" {
			return urResult(nil, errors.New("URnetwork account not found"))
		}
		api.SetByJwt(s.Accounts[index].Network)
		cb, ch := uc.NewBlockingApiCallback[*ur.SubscriptionBalanceResult](ctx)
		api.SubscriptionBalance(cb)
		select {
		case v := <-ch:
			if v.Error != nil || v.Result == nil {
				return urResult(nil, errors.New("cannot load URnetwork data balance"))
			}
			b := v.Result
			balance := &urBalance{Available: b.BalanceByteCount, Start: b.StartBalanceByteCount,
				Pending: b.OpenTransferByteCount, UpdatedAt: time.Now().Unix()}
			s.Accounts[index].Usage = balance
			if err := urSave(dir, &s); err != nil {
				return urResult(nil, err)
			}
			return urResult(map[string]any{"usage_account": id, "usage": balance.display(),
				"usage_updated": time.Unix(balance.UpdatedAt, 0).UTC().Format(time.RFC3339)}, nil)
		case <-ctx.Done():
			return urResult(nil, errors.New("URnetwork data balance request timed out"))
		}
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
			s.Locations = rows
			s.LocationsAt = time.Now().Unix()
			err := urSave(dir, &s)
			return urResult(urSnapshot(&s), err)
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
		settings.ClientSettings.Log = urHostLogger{}
		settings.DisableLogging = false
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

// Use integer arithmetic so a small remaining balance is not rounded away.
func urFormatGiB(n int64, precision int) string {
	if n < 0 {
		n = 0
	}
	const gib uint64 = 1 << 30
	scale := uint64(1)
	for i := 0; i < precision; i++ {
		scale *= 10
	}
	value := uint64(n)
	return fmt.Sprintf("%d.%0*d GiB", value/gib, precision, (value%gib)*scale/gib)
}

func urSpace(_ context.Context, upstream string, tun, configureEgress bool) (*ur.NetworkSpace, error) {
	settings := uc.DefaultClientStrategySettings()
	settings.Log = urHostLogger{}
	settings.ConnectSettings.Log = urHostLogger{}
	// Connect's central egress seam also covers QUIC, DNS and WebRTC sockets.
	var iface *net.Interface
	if configureEgress {
		uc.SetEgressInterfaceIndex(0, 0)
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
	}
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
