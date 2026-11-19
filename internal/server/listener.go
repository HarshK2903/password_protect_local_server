package server

import (
	"net"
	"sync"
	"sync/atomic"
)

// LimitedListener bounds even idle connections and connections stuck in TLS
// negotiation. Excess connections are closed without allocating HTTP state.
type LimitedListener struct {
	net.Listener
	slots  chan struct{}
	closed atomic.Bool
}

func LimitListener(l net.Listener, max int) *LimitedListener {
	return &LimitedListener{Listener: l, slots: make(chan struct{}, max)}
}
func (l *LimitedListener) Close() error { l.closed.Store(true); return l.Listener.Close() }
func (l *LimitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.closed.Load() {
			_ = c.Close()
			return nil, net.ErrClosed
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
