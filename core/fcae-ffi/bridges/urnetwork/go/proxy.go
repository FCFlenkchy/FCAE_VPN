//go:build fcae_urnetwork

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ur "github.com/urnetwork/sdk"
)

type urSession struct {
	udpFlows            atomic.Int32
	udpAssociations     atomic.Int32
	device              *ur.DeviceLocal
	space               *ur.NetworkSpace
	ctx                 context.Context
	cancel              context.CancelFunc
	mu                  sync.Mutex
	closed              bool
	listeners           []net.Listener
	conns               map[io.Closer]struct{}
	socksAddr, httpAddr string
	rx, tx              atomic.Uint64
	rtt                 atomic.Uint32
	probeDone           chan struct{}
	rates               urRates
	once                sync.Once
}

func newURSession(d *ur.DeviceLocal, s *ur.NetworkSpace, dir string) *urSession {
	ctx, cancel := context.WithCancel(context.Background())
	session := &urSession{device: d, space: s, ctx: ctx, cancel: cancel, conns: map[io.Closer]struct{}{}, probeDone: make(chan struct{})}
	engineStarted(engineURnetwork)
	go session.sampleTraffic()
	go session.measureRTT()
	return session
}
func (s *urSession) track(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}
func (s *urSession) forget(c io.Closer) { c.Close(); s.mu.Lock(); delete(s.conns, c); s.mu.Unlock() }
func (s *urSession) close() {
	s.once.Do(func() {
		s.cancel()
		s.mu.Lock()
		s.closed = true
		for _, l := range s.listeners {
			l.Close()
		}
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.device.CloseAndWait(ctx)
		s.space.Close()
		<-s.probeDone
		// Drop retained maps and engine roots before scheduling collection.
		s.mu.Lock()
		s.conns = nil
		s.listeners = nil
		s.mu.Unlock()
		engineStopped(engineURnetwork)
	})
}
func (s *urSession) up() bool {
	return s.ctx.Err() == nil && s.device.GetConnectedProviderLocations().Len() > 0
}
func (s *urSession) listen(socks, httpAddr string) error {
	for _, v := range []struct {
		addr   string
		isHTTP bool
	}{{socks, false}, {httpAddr, true}} {
		if v.addr == "" {
			continue
		}
		l, e := net.Listen("tcp", v.addr)
		if e != nil {
			return fmt.Errorf("cannot open URnetwork listener: %w", e)
		}
		s.listeners = append(s.listeners, l)
		if v.isHTTP {
			s.httpAddr = l.Addr().String()
		} else {
			s.socksAddr = l.Addr().String()
		}
		go s.accept(l, v.isHTTP)
	}
	return nil
}
func (s *urSession) accept(l net.Listener, isHTTP bool) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		s.mu.Lock()
		full := len(s.conns) >= 512
		s.mu.Unlock()
		if full {
			c.Close()
			continue
		}
		if !s.track(c) {
			return
		}
		go func() {
			defer s.forget(c)
			c.SetDeadline(time.Now().Add(30 * time.Second))
			if isHTTP {
				s.http(c)
			} else {
				s.socks(c)
			}
		}()
	}
}
func urReadAddress(r io.Reader) (string, error) {
	var b [1]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return "", e
	}
	var host string
	switch b[0] {
	case 1:
		raw := make([]byte, 4)
		if _, e := io.ReadFull(r, raw); e != nil {
			return "", e
		}
		host = net.IP(raw).String()
	case 4:
		raw := make([]byte, 16)
		if _, e := io.ReadFull(r, raw); e != nil {
			return "", e
		}
		host = net.IP(raw).String()
	case 3:
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return "", e
		}
		if b[0] == 0 {
			return "", errors.New("empty SOCKS address")
		}
		raw := make([]byte, int(b[0]))
		if _, e := io.ReadFull(r, raw); e != nil {
			return "", e
		}
		host = string(raw)
	default:
		return "", errors.New("unsupported SOCKS address")
	}
	var port [2]byte
	if _, e := io.ReadFull(r, port[:]); e != nil {
		return "", e
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}
func urAddress(addr string) ([]byte, error) {
	host, port, e := net.SplitHostPort(addr)
	if e != nil {
		return nil, e
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 0 || p > 65535 {
		return nil, errors.New("invalid port")
	}
	out := []byte{}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		out = append(out, 1)
		out = append(out, ip4...)
	} else if ip != nil {
		out = append(out, 4)
		out = append(out, ip.To16()...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS name too long")
		}
		out = append(out, 3, byte(len(host)))
		out = append(out, host...)
	}
	return append(out, byte(p>>8), byte(p)), nil
}
func urReply(c net.Conn, code byte, addr string) error {
	a, e := urAddress(addr)
	if e != nil {
		return e
	}
	_, e = c.Write(append([]byte{5, code, 0}, a...))
	return e
}
func (s *urSession) socks(c net.Conn) {
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{5, 255})
		return
	}
	if _, e := c.Write([]byte{5, 0}); e != nil {
		return
	}
	var req [3]byte
	if _, e := io.ReadFull(c, req[:]); e != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	addr, e := urReadAddress(c)
	if e != nil {
		return
	}
	if req[1] == 3 {
		s.udp(c)
		return
	}
	if req[1] != 1 {
		urReply(c, 7, "0.0.0.0:0")
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	up, e := s.device.DialContext(ctx, "tcp", addr)
	if e != nil {
		urReply(c, 5, "0.0.0.0:0")
		return
	}
	if !s.track(up) {
		return
	}
	defer s.forget(up)
	if urReply(c, 0, "0.0.0.0:0") != nil {
		return
	}
	c.SetDeadline(time.Time{})
	s.relay(c, up, c)
}

type urCountWriter struct {
	io.Writer
	n *atomic.Uint64
}

func (w urCountWriter) Write(b []byte) (int, error) {
	n, e := w.Writer.Write(b)
	w.n.Add(uint64(n))
	return n, e
}
func (s *urSession) relay(client, up net.Conn, reader io.Reader) {
	done := make(chan struct{})
	go func() { io.Copy(urCountWriter{client, &s.rx}, up); client.Close(); up.Close(); close(done) }()
	_, err := io.Copy(urCountWriter{up, &s.tx}, reader)
	if half, ok := up.(interface{ CloseWrite() error }); err == nil && ok {
		_ = half.CloseWrite()
	} else {
		up.Close()
		client.Close()
	}
	<-done
}
func (s *urSession) http(c net.Conn) {
	reader := bufio.NewReader(c)
	req, e := http.ReadRequest(reader)
	if e != nil {
		return
	}
	defer req.Body.Close()
	target := req.Host
	if _, _, e = net.SplitHostPort(target); e != nil {
		target = net.JoinHostPort(target, "80")
		if req.Method == "CONNECT" {
			target = net.JoinHostPort(req.Host, "443")
		}
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	up, e := s.device.DialContext(ctx, "tcp", target)
	if e != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if !s.track(up) {
		return
	}
	defer s.forget(up)
	if req.Method == "CONNECT" {
		if _, e = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
			return
		}
	} else {
		req.RequestURI = ""
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		req.Close = true
		if e = req.Write(up); e != nil {
			return
		}
	}
	c.SetDeadline(time.Time{})
	s.relay(c, up, reader)
}

// Each UDP association is owned by its TCP control connection. Source pinning,
// idle expiry and a flow cap bound work; no datagram ever uses the host dialer.
func (s *urSession) udp(control net.Conn) {
	if s.udpAssociations.Add(1) > 16 {
		s.udpAssociations.Add(-1)
		urReply(control, 1, "0.0.0.0:0")
		return
	}
	defer s.udpAssociations.Add(-1)
	local := control.LocalAddr().(*net.TCPAddr)
	u, e := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Port: 0})
	if e != nil {
		return
	}
	if !s.track(u) {
		return
	}
	defer s.forget(u)
	if urReply(control, 0, u.LocalAddr().String()) != nil {
		return
	}
	control.SetDeadline(time.Time{})
	go func() { io.Copy(io.Discard, control); u.Close() }()
	peer := control.RemoteAddr().(*net.TCPAddr).IP
	var source *net.UDPAddr
	type flow struct {
		conn net.Conn
		done chan struct{}
	}
	flows := map[string]*flow{}
	defer func() {
		for _, c := range flows {
			c.conn.Close()
		}
	}()
	buf := make([]byte, 65535)
	for {
		u.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, from, e := u.ReadFromUDP(buf)
		if e != nil {
			return
		}
		if !from.IP.Equal(peer) || n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		if source == nil {
			source = from
		}
		if source.Port != from.Port {
			continue
		}
		r := bytes.NewReader(buf[3:n])
		addr, e := urReadAddress(r)
		if e != nil {
			continue
		}
		payload := buf[n-r.Len() : n]
		for key, f := range flows {
			select {
			case <-f.done:
				delete(flows, key)
			default:
			}
		}
		f := flows[addr]
		var up net.Conn
		if f != nil {
			up = f.conn
		}
		if up == nil {
			if len(flows) >= 64 {
				continue
			}
			if s.udpFlows.Add(1) > 64 {
				s.udpFlows.Add(-1)
				continue
			}
			ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
			up, e = s.device.DialContext(ctx, "udp", addr)
			cancel()
			if e != nil {
				s.udpFlows.Add(-1)
				continue
			}
			f = &flow{conn: up, done: make(chan struct{})}
			flows[addr] = f
			dest := *source
			header, _ := urAddress(addr)
			done := f.done
			go func(c net.Conn) {
				defer close(done)
				defer c.Close()
				defer s.udpFlows.Add(-1)
				offset := 3 + len(header)
				b := make([]byte, offset+65535)
				copy(b[3:offset], header)
				for {
					c.SetReadDeadline(time.Now().Add(2 * time.Minute))
					n, e := c.Read(b[offset:])
					if e != nil {
						return
					}
					if _, e = u.WriteToUDP(b[:offset+n], &dest); e != nil {
						return
					}
					s.rx.Add(uint64(n))
				}
			}(up)
		}
		up.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if n, e := up.Write(payload); e == nil {
			s.tx.Add(uint64(n))
		}
	}
}

// Generation ownership prevents late refresh callbacks from reviving an old
// account after sign-out or replacing the token of a new device.
type urCredentialListener struct {
	dir, instance string
	session       *urSession
	generation    atomic.Uint64
}

func (l *urCredentialListener) JwtRefreshed(_ string) {
	generation := l.generation.Add(1)
	go func() {
		lock := urStoreLock(l.dir)
		lock.Lock()
		defer lock.Unlock()
		if generation != l.generation.Load() {
			return
		}
		s, e := urLoad(l.dir)
		if e != nil {
			return
		}
		// A different account may have been selected while this session was
		// running. Refresh only the matching device, never the new selection.
		client := l.session.device.GetClientJwt()
		found := false
		for i := range s.Accounts {
			if s.Accounts[i].Instance == l.instance {
				s.Accounts[i].Client = client
				found = true
				break
			}
		}
		if !found {
			return // The account was removed or reauthenticated.
		}
		if s.Instance == l.instance {
			s.Client = client
		}
		if urSave(l.dir, &s) != nil {
			l.session.cancel()
			l.session.device.Close()
		}
	}()
}

type urAuthListener struct{ session *urSession }

func (l *urAuthListener) AuthLogout() { l.session.cancel() }

// sampleTraffic owns the rate window. Status/health readers only observe it;
// they cannot reset its baseline between telemetry polls.
func (s *urSession) sampleTraffic() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	s.rates.sample(s.rx.Load(), s.tx.Load(), time.Now())
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.rates.sample(s.rx.Load(), s.tx.Load(), now)
		}
	}
}

func (s *urSession) status() map[string]any {
	rx, tx := s.rx.Load(), s.tx.Load()
	rxRate, txRate := s.rates.get()
	return map[string]any{"up": s.up(), "alive": s.ctx.Err() == nil, "rx": rx, "tx": tx,
		"rx_rate": rxRate, "tx_rate": txRate, "rtt_ms": s.rtt.Load()}
}

// Time a real response over the device, including every configured carrier.
// Never time the loopback listener or fall back to the host's network.
func (s *urSession) measureRTT() {
	defer close(s.probeDone)
	transport := &http.Transport{DialContext: s.device.DialContext, DisableKeepAlives: true,
		ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
		}
		if s.up() {
			for _, target := range []string{"http://www.gstatic.com/generate_204", "http://www.msftconnecttest.com/connecttest.txt"} {
				req, err := http.NewRequestWithContext(s.ctx, http.MethodHead, target, nil)
				if err != nil {
					continue
				}
				started := time.Now()
				response, err := client.Do(req)
				if err != nil {
					continue
				}
				elapsed := time.Since(started)
				response.Body.Close()
				if response.StatusCode >= 200 && response.StatusCode < 400 {
					s.rtt.Store(uint32((elapsed + time.Millisecond - 1) / time.Millisecond))
					return
				}
			}
		}
		timer.Reset(10 * time.Second)
	}
}
