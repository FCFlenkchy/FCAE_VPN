//go:build with_gvisor

// Deferred TCP accept for the pinned sing-tun gVisor stack, which Mihomo's TUN
// and the sing-tun engine both run on.
//
// The pinned forwarder completes the handshake with the application before the
// handler has opened anything for it. A flow whose outbound then cannot be
// opened was already accepted, so the application sees a connection that is
// established and closed instead of an address it cannot reach, and does not
// go on to the next one. One such flow is a DIRECT one to an IPv6 address on a
// network that has no IPv6: the device offers IPv6, and an application that
// tries the IPv6 address of a site reports a reset or closed connection where
// it would otherwise have gone on to the IPv4 address.
//
// Here the SYN is held until the handler first reads or writes, which it does
// once its outbound is open, and a handler that closes before that refuses the
// connection. sing-box's own stacks behave this way.
//
// Mihomo reads earlier than that: while it dials it looks, for 200 ms, for
// data the application may already have sent, to hand it to the outbound with
// the handshake. With the SYN held there is none to find, and that look must
// not be what commits the connection, so the first read is allowed to be such
// a peek: bounded by a deadline no further away than fcaeEarlyPeek, it waits
// for the deadline and reports it. The build checks Mihomo's 200 ms.
package tun

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	M "github.com/metacubex/sing/common/metadata"
)

const fcaeEarlyPeek = 250 * time.Millisecond

// Forward stands in for the pinned forwarder, which the build keeps as
// fcaeEagerForward.
func (f *TCPForwarder) Forward(r *tcp.ForwarderRequest) {
	id := r.ID()
	// The addresses gonet reports for the endpoint once it exists.
	local := &net.TCPAddr{IP: net.IP(id.LocalAddress.AsSlice()), Port: int(id.LocalPort)}
	remote := &net.TCPAddr{IP: net.IP(id.RemoteAddress.AsSlice()), Port: int(id.RemotePort)}
	conn := &fcaeDeferredConn{ctx: f.ctx, request: r, local: local, remote: remote, settled: make(chan struct{}), deadlineChanged: make(chan struct{})}
	var metadata M.Metadata
	metadata.Source = M.SocksaddrFromNet(remote)
	metadata.Destination = M.SocksaddrFromNet(local)
	if err := f.handler.NewConnection(f.ctx, conn, metadata); err != nil {
		conn.abort()
	}
}

type fcaeDeferredConn struct {
	ctx     context.Context
	request *tcp.ForwarderRequest
	local   net.Addr
	remote  net.Addr

	access sync.Mutex
	// The request is completed exactly once: answered marks who does it.
	answered bool
	// final: conn, endpoint and err no longer change. settled is closed after.
	final    bool
	settled  chan struct{}
	conn     *gonet.TCPConn
	endpoint tcpip.Endpoint
	err      error
	// Deadlines set while the SYN is held apply once the connection exists.
	readDeadline     time.Time
	writeDeadline    time.Time
	readDeadlineSet  bool
	writeDeadlineSet bool
	// Closed and replaced whenever a held read deadline changes.
	deadlineChanged chan struct{}
	// The first read was looked at: only that one may be an early peek.
	peeked bool
}

// accept answers the held SYN. Every caller gets the one result.
func (c *fcaeDeferredConn) accept() (*gonet.TCPConn, error) {
	c.access.Lock()
	if c.answered {
		c.access.Unlock()
		<-c.settled
		return c.conn, c.err
	}
	c.answered = true
	c.access.Unlock()

	var wq waiter.Queue
	var cancel context.CancelFunc
	if parentDone := c.ctx.Done(); parentDone != nil {
		var handshakeCtx context.Context
		handshakeCtx, cancel = context.WithCancel(context.Background())
		go func() {
			select {
			case <-parentDone:
				wq.Notify(wq.Events())
			case <-handshakeCtx.Done():
			}
		}()
	}
	endpoint, err := c.request.CreateEndpoint(&wq)
	if cancel != nil {
		cancel()
	}

	c.access.Lock()
	if err != nil {
		c.request.Complete(true)
		c.err = &net.OpError{Op: "accept", Net: "tcp", Source: c.remote, Addr: c.local, Err: errors.New(err.String())}
	} else {
		c.request.Complete(false)
		endpoint.SocketOptions().SetKeepAlive(true)
		keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
		endpoint.SetSockOpt(&keepAliveIdle)
		keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
		endpoint.SetSockOpt(&keepAliveInterval)
		c.endpoint = endpoint
		c.conn = gonet.NewTCPConn(&wq, endpoint)
		if c.readDeadlineSet {
			_ = c.conn.SetReadDeadline(c.readDeadline)
		}
		if c.writeDeadlineSet {
			_ = c.conn.SetWriteDeadline(c.writeDeadline)
		}
	}
	c.final = true
	c.access.Unlock()
	close(c.settled)
	return c.conn, c.err
}

// refuse answers a SYN nobody accepted with a reset, and reports whether it
// was still held.
func (c *fcaeDeferredConn) refuse() bool {
	c.access.Lock()
	if c.answered {
		c.access.Unlock()
		return false
	}
	c.answered = true
	c.err = net.ErrClosed
	c.final = true
	c.access.Unlock()
	c.request.Complete(true)
	close(c.settled)
	return true
}

// abort is what the pinned forwarder does when the handler reports an error.
func (c *fcaeDeferredConn) abort() {
	if c.refuse() {
		return
	}
	<-c.settled
	if c.endpoint != nil {
		c.endpoint.Abort()
	}
}

// earlyPeek reports whether this read was a peek that ran to its deadline with
// the SYN still held. Anything else is a read that answers it.
func (c *fcaeDeferredConn) earlyPeek() bool {
	c.access.Lock()
	if c.answered || c.peeked {
		c.access.Unlock()
		return false
	}
	c.peeked = true
	for !c.answered {
		if !c.readDeadlineSet || c.readDeadline.IsZero() {
			break
		}
		wait := time.Until(c.readDeadline)
		if wait > fcaeEarlyPeek {
			break
		}
		if wait <= 0 {
			c.access.Unlock()
			return true
		}
		changed := c.deadlineChanged
		c.access.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-changed:
		case <-c.settled:
		}
		timer.Stop()
		c.access.Lock()
	}
	c.access.Unlock()
	return false
}

func (c *fcaeDeferredConn) Read(b []byte) (int, error) {
	if c.earlyPeek() {
		return 0, os.ErrDeadlineExceeded
	}
	conn, err := c.accept()
	if err != nil {
		return 0, err
	}
	return conn.Read(b)
}

func (c *fcaeDeferredConn) Write(b []byte) (int, error) {
	conn, err := c.accept()
	if err != nil {
		return 0, err
	}
	return conn.Write(b)
}

// Close before the first read or write refuses the connection: nothing was
// promised to the application yet.
func (c *fcaeDeferredConn) Close() error {
	if c.refuse() {
		return nil
	}
	<-c.settled
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *fcaeDeferredConn) CloseRead() error {
	conn, err := c.accept()
	if err != nil {
		return err
	}
	return conn.CloseRead()
}

func (c *fcaeDeferredConn) CloseWrite() error {
	conn, err := c.accept()
	if err != nil {
		return err
	}
	return conn.CloseWrite()
}

func (c *fcaeDeferredConn) LocalAddr() net.Addr  { return c.local }
func (c *fcaeDeferredConn) RemoteAddr() net.Addr { return c.remote }

// A deadline does not answer the SYN: handlers set them before they dial.
func (c *fcaeDeferredConn) setDeadline(read bool, write bool, t time.Time) error {
	c.access.Lock()
	if !c.final {
		if read {
			c.readDeadline, c.readDeadlineSet = t, true
		}
		if write {
			c.writeDeadline, c.writeDeadlineSet = t, true
		}
		if read {
			close(c.deadlineChanged)
			c.deadlineChanged = make(chan struct{})
		}
		c.access.Unlock()
		return nil
	}
	conn, err := c.conn, c.err
	c.access.Unlock()
	if conn == nil {
		return err
	}
	switch {
	case read && write:
		return conn.SetDeadline(t)
	case read:
		return conn.SetReadDeadline(t)
	default:
		return conn.SetWriteDeadline(t)
	}
}

func (c *fcaeDeferredConn) SetDeadline(t time.Time) error      { return c.setDeadline(true, true, t) }
func (c *fcaeDeferredConn) SetReadDeadline(t time.Time) error  { return c.setDeadline(true, false, t) }
func (c *fcaeDeferredConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(false, true, t) }
