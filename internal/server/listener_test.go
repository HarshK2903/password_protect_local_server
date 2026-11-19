package server

import (
	"net"
	"testing"
	"time"
)

func TestConnectionCapacityAndRelease(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := LimitListener(raw, 1)
	defer l.Close()
	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	excess, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	excess.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := excess.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess connection was not closed")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection retained resources")
	}
	first.Close()
	first.Close()
	next, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("connection slot not released")
	}
}
