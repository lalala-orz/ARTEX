package traffic

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Helpers shared by the egress/SOCKS5 tests. Reconstructed after they were lost
// with an edit to the test files they used to live in; keep them here so a single
// file owns the plumbing.

// startEchoTarget serves a TCP echo target that answers one payload with banner.
func startEchoTarget(t *testing.T, banner string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write([]byte(banner))
			}(c)
		}
	}()
	return ln
}

func portOf(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// freeAddr returns a 127.0.0.1 address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待监听 %s 超时", addr)
}

// startCountingUpstream runs a minimal SOCKS5 proxy and counts accepted
// connections, so a test can prove which egress the traffic really took.
func startCountingUpstream(t *testing.T) (string, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var hits int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&hits, 1)
			go serveCountingSocks5(c)
		}
	}()
	return ln.Addr().String(), &hits
}

func serveCountingSocks5(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))

	dst, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dst.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dst, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, dst); done <- struct{}{} }()
	<-done
}

// socks5RoundTrip sends payload through the listener's SOCKS5 ingress to
// host:port and asserts the echo target answered with wantBanner.
func socks5RoundTrip(t *testing.T, proxyAddr, host string, port int, payload, wantBanner string) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 握手失败: %v", reply)
	}
	socks5Connect(t, c, host, port)
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(wantBanner))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("读取回显: %v", err)
	}
	if string(got) != wantBanner {
		t.Fatalf("回显 = %q，想要 %q", got, wantBanner)
	}
}

// waitLedgerRow waits for the ledger row of this destination port, with the
// expected via_upstream verdict. Recording finishes off the request path, so the
// row appears shortly after the round trip.
func waitLedgerRow(t *testing.T, tr *Traffic, port int, viaUpstream bool) Socks5Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rows, _, err := tr.Socks5Conns("", 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.DstPort == port && r.ViaUpstream == viaUpstream {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待端口 %d 的账本行（via_upstream=%v）超时", port, viaUpstream)
	return Socks5Conn{}
}
