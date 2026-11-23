//go:build fcae_urnetwork

package main

import (
	"bytes"
	"context"
	"errors"
	uc "github.com/urnetwork/connect"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

func urUpstream(raw string) (*uc.ProxySettings, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || (u.Scheme != "socks5" && u.Scheme != "socks5h") {
		return nil, errors.New("URnetwork chaining requires a SOCKS5 carrier")
	}
	p := &uc.ProxySettings{Network: "tcp", Address: u.Host}
	if u.User != nil {
		pw, _ := u.User.Password()
		p.Auth = &proxy.Auth{User: u.User.Username(), Password: pw}
	}
	return p, nil
}

type urPacketProxy struct {
	net.PacketConn
	control  net.Conn
	relay    net.Addr
	readMu   sync.Mutex
	readBuf  []byte
	writeMu  sync.Mutex
	writeBuf []byte
}

func (p *urPacketProxy) Close() error { p.control.Close(); return p.PacketConn.Close() }
func (p *urPacketProxy) WriteTo(b []byte, a net.Addr) (int, error) {
	h, e := urAddress(a.String())
	if e != nil {
		return 0, e
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.writeBuf = append(p.writeBuf[:0], 0, 0, 0)
	p.writeBuf = append(p.writeBuf, h...)
	p.writeBuf = append(p.writeBuf, b...)
	_, e = p.PacketConn.WriteTo(p.writeBuf, p.relay)
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
func (p *urPacketProxy) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	if p.readBuf == nil {
		p.readBuf = make([]byte, 65535)
	}
	raw := p.readBuf
	for {
		n, from, e := p.PacketConn.ReadFrom(raw)
		if e != nil {
			return 0, nil, e
		}
		if from.String() != p.relay.String() || n < 4 || raw[0] != 0 || raw[1] != 0 || raw[2] != 0 {
			continue
		}
		r := bytes.NewReader(raw[3:n])
		a, e := urReadAddress(r)
		if e != nil {
			continue
		}
		addr, e := urNumericUDP(a)
		if e != nil {
			continue
		}
		n, _ = r.Read(b)
		return n, addr, nil
	}
}
func urProxyPacket(ctx context.Context, p *uc.ProxySettings) (net.PacketConn, error) {
	d := uc.DefaultConnectSettings().NetDialer()
	c, e := d.DialContext(ctx, "tcp", p.Address)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	stopCancel := context.AfterFunc(ctx, func() { c.Close() })
	defer stopCancel()
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	methods := []byte{5, 1, 0}
	if p.Auth != nil {
		methods = []byte{5, 2, 0, 2}
	}
	if _, e = c.Write(methods); e != nil {
		return nil, e
	}
	var h [2]byte
	if _, e = io.ReadFull(c, h[:]); e != nil || h[0] != 5 {
		return nil, errors.New("invalid carrier SOCKS greeting")
	}
	if h[1] == 2 && p.Auth != nil {
		if len(p.Auth.User) > 255 || len(p.Auth.Password) > 255 {
			return nil, errors.New("carrier SOCKS credentials exceed limit")
		}
		auth := append([]byte{1, byte(len(p.Auth.User))}, []byte(p.Auth.User)...)
		auth = append(auth, byte(len(p.Auth.Password)))
		auth = append(auth, []byte(p.Auth.Password)...)
		if _, e = c.Write(auth); e != nil {
			return nil, e
		}
		if _, e = io.ReadFull(c, h[:]); e != nil || h[1] != 0 {
			return nil, errors.New("carrier SOCKS authentication failed")
		}
	} else if h[1] != 0 {
		return nil, errors.New("carrier SOCKS authentication unsupported")
	}
	if _, e = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return nil, e
	}
	var reply [3]byte
	if _, e = io.ReadFull(c, reply[:]); e != nil || reply[0] != 5 || reply[1] != 0 {
		return nil, errors.New("carrier refused UDP association")
	}
	addr, e := urReadAddress(c)
	if e != nil {
		return nil, e
	}
	relay, e := urNumericUDP(addr)
	if e != nil {
		return nil, e
	}
	if relay.IP.IsUnspecified() {
		relay.IP = c.RemoteAddr().(*net.TCPAddr).IP
	}
	lc := net.ListenConfig{Control: uc.FCAEEgressControl}
	pc, e := lc.ListenPacket(ctx, "udp", ":0")
	if e != nil {
		return nil, e
	}
	c.SetDeadline(time.Time{})
	out := &urPacketProxy{PacketConn: pc, control: c, relay: relay}
	go func() { io.Copy(io.Discard, c); pc.Close() }()
	ok = true
	return out, nil
}

// SOCKS metadata must never trigger host DNS queries for user destinations.
func urNumericUDP(address string) (*net.UDPAddr, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ip := net.ParseIP(host)
	p, e := strconv.Atoi(port)
	if e != nil || ip == nil || p < 0 || p > 65535 {
		return nil, errors.New("carrier must return a numeric UDP address")
	}
	return &net.UDPAddr{IP: ip, Port: p}, nil
}
