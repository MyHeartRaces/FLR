package socks

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialConsumesFragmentedReplyWithoutEatingPayload(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		defer c.Close()
		b := make([]byte, 3)
		io.ReadFull(c, b)
		c.Write([]byte{5, 0})
		b = make([]byte, 10)
		io.ReadFull(c, b)
		for _, v := range []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1} {
			c.Write([]byte{v})
		}
		c.Write([]byte("payload"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := DialContext(ctx, l.Addr().String(), "8.8.8.8:443")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	b := make([]byte, 7)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "payload" {
		t.Fatal("SOCKS parser corrupted TCP stream", e)
	}
}
func TestUDPFrameRejectsFragmentsAndTruncation(t *testing.T) {
	for _, b := range [][]byte{{0, 0, 1, 1, 1, 1, 1, 1, 0, 53}, {0, 0, 0, 1, 1}} {
		if _, _, e := DecodeUDP(b); e == nil {
			t.Fatal("malformed UDP relay frame accepted")
		}
	}
}
