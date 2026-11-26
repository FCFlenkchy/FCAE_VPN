package tun

// Installed into a copy of Xray's proxy/tun by the build, next to the pinned
// TCP stack it changes (buildtools: defer_xray_tcp_accept).
//
// The pinned stack answers a connection as soon as its SYN arrives and gives
// it to the handler once the application has acknowledged that. A flow whose
// outbound then cannot be opened reaches the application as a connection that
// was established and then reset, so it does not go on to its next address:
// an application that leaves around the VPN, on a network without IPv6, fails
// on every site that has an IPv6 address as well.
//
// Here the handler gets the connection when its SYN arrives, and the SYN is
// answered when the handler first reads from the connection or writes to it,
// which an outbound does once it is open. A handler that closes it before
// that refuses it, as a port nobody listens on does.

import "time"

// fcaeHold gives a connection whose SYN has just arrived to the handler
// without answering it.
func (c *tcpConn) fcaeHold() {
	c.mu.Lock()
	c.fcaeHeld, c.fcaeHandled = true, true
	c.mu.Unlock()
	go c.stack.handle(c, c.dst)
}

// fcaeAnswer answers the SYN of a held connection. c.mu is held
func (c *tcpConn) fcaeAnswer() {
	if !c.fcaeHeld || c.err != nil || c.closed {
		return
	}
	c.fcaeHeld = false
	// the answer is timed from here, not from the SYN that waited for it
	c.timedAt = time.Now()
	c.sendSyn()
	c.arm(tcpTick)
}

// fcaeWritable answers a held connection and waits until the application has
// acknowledged that: nothing is sent to it before. c.mu is held
func (c *tcpConn) fcaeWritable() {
	c.fcaeAnswer()
	for !c.established && c.err == nil && !c.closed {
		c.writable.Wait()
	}
}

// fcaeEstablished is called when the application has acknowledged the answer
// to its SYN. c.mu is held
func (c *tcpConn) fcaeEstablished() {
	c.fcaeHeld = false
	if c.fcaeHandled {
		// the handler has it already, and may be waiting to write
		c.writable.Broadcast()
		return
	}
	c.fcaeHandled = true
	go c.stack.handle(c, c.dst)
}
