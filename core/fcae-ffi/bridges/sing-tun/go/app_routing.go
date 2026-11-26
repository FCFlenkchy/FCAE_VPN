//go:build fcae_sing_tun && fcae_singbox

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	MB "github.com/metacubex/sing/common/buf"
	MM "github.com/metacubex/sing/common/metadata"
	MN "github.com/metacubex/sing/common/network"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	SB "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	SM "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type mtunBoxRouter struct{ core *box.Box }

func mtunNewAppRouter(ctx context.Context, config []byte) (mtunAppRouter, error) {
	ctx = include.Context(service.ContextWithDefaultRegistry(ctx))
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return nil, err
	}
	core, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, err
	}
	// The router is where a flow gets its process and its outbound. Without
	// this its log goes nowhere, and a split that misbehaves shows nothing in
	// the TUN engine log.
	core.LogFactory().AttachPlatformWriter(mtunRouterLog{})
	if err = core.Start(); err != nil {
		_ = core.Close()
		return nil, err
	}
	return &mtunBoxRouter{core}, nil
}

type mtunRouterLog struct{}

func (mtunRouterLog) WriteMessage(level sblog.Level, message string) {
	gate := 4
	switch {
	case level <= sblog.LevelError:
		gate = 1
	case level == sblog.LevelWarn:
		gate = 2
	case level == sblog.LevelInfo:
		gate = 3
	}
	mtunLogf(gate, "router: %s", strings.TrimRight(message, "\n"))
}

func mtunInbound(m MM.Metadata, network string) adapter.InboundContext {
	return adapter.InboundContext{Inbound: "fcae-sing-tun", InboundType: "tun", Network: network,
		Source:      SM.Socksaddr{Addr: m.Source.Addr, Port: m.Source.Port, Fqdn: m.Source.Fqdn},
		Destination: SM.Socksaddr{Addr: m.Destination.Addr, Port: m.Destination.Port, Fqdn: m.Destination.Fqdn}}
}
func (r *mtunBoxRouter) RouteTCP(ctx context.Context, c net.Conn, m MM.Metadata) error {
	return r.core.Router().RouteConnection(ctx, c, mtunInbound(m, "tcp"))
}
func (r *mtunBoxRouter) RouteUDP(ctx context.Context, c MN.PacketConn, m MM.Metadata) error {
	return r.core.Router().RoutePacketConnection(ctx, &mtunPacketBridge{c}, mtunInbound(m, "udp"))
}
func (r *mtunBoxRouter) Close() error { return r.core.Close() }

// The two sing forks have distinct buffer types. Preserve packet destinations
// and ownership explicitly; never reinterpret one fork's buffer as the other.
type mtunPacketBridge struct{ inner MN.PacketConn }

func (c *mtunPacketBridge) ReadPacket(out *SB.Buffer) (SM.Socksaddr, error) {
	b := MB.NewSize(65535)
	defer b.Release()
	addr, err := c.inner.ReadPacket(b)
	if err == nil {
		_, err = out.Write(b.Bytes())
	}
	return SM.Socksaddr{Addr: addr.Addr, Port: addr.Port, Fqdn: addr.Fqdn}, err
}
func (c *mtunPacketBridge) WritePacket(in *SB.Buffer, addr SM.Socksaddr) error {
	defer in.Release()
	if !addr.IsIP() {
		return fmt.Errorf("sing-tun packet replies require a resolved IP destination")
	}
	b := MB.NewSize(in.Len())
	_, _ = b.Write(in.Bytes())
	return c.inner.WritePacket(b, MM.Socksaddr{Addr: addr.Addr, Port: addr.Port, Fqdn: addr.Fqdn})
}
func (c *mtunPacketBridge) Close() error                       { return c.inner.Close() }
func (c *mtunPacketBridge) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *mtunPacketBridge) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *mtunPacketBridge) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *mtunPacketBridge) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
