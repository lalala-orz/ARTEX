package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startStubSOCKS5 起一个最小 SOCKS5 服务端：按 needAuth 决定要不要用户名密码，握手完成后
// 把连接当成回显管道 —— 测试关心的是"握手对不对、流量有没有穿过去"。
func startStubSOCKS5(t *testing.T, needAuth bool, wantUser, wantPass string) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	seen := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		head := make([]byte, 2)
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		methods := make([]byte, int(head[1]))
		_, _ = io.ReadFull(br, methods)
		if needAuth {
			_, _ = c.Write([]byte{0x05, 0x02})
			ver := make([]byte, 2)
			if _, err := io.ReadFull(br, ver); err != nil {
				return
			}
			u := make([]byte, int(ver[1]))
			_, _ = io.ReadFull(br, u)
			pl := make([]byte, 1)
			_, _ = io.ReadFull(br, pl)
			p := make([]byte, int(pl[0]))
			_, _ = io.ReadFull(br, p)
			seen <- fmt.Sprintf("auth:%s:%s", u, p)
			if string(u) != wantUser || string(p) != wantPass {
				_, _ = c.Write([]byte{0x01, 0x01})
				return
			}
			_, _ = c.Write([]byte{0x01, 0x00})
		} else {
			_, _ = c.Write([]byte{0x05, 0x00})
		}
		req := make([]byte, 4)
		if _, err := io.ReadFull(br, req); err != nil {
			return
		}
		host := ""
		if req[3] == 0x03 {
			l := make([]byte, 1)
			_, _ = io.ReadFull(br, l)
			h := make([]byte, int(l[0]))
			_, _ = io.ReadFull(br, h)
			host = string(h)
		}
		port := make([]byte, 2)
		_, _ = io.ReadFull(br, port)
		seen <- fmt.Sprintf("connect:%s:%d", host, int(port[0])<<8|int(port[1]))
		_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		// 回显：证明拿到的 conn 是可用的双向流。
		_, _ = io.Copy(c, br)
	}()
	return ln.Addr().String(), seen
}

// startStubConnect 起一个最小 HTTP CONNECT 代理：回 200 之后立刻说话 —— 专门用来验证
// "bufio 多读的字节不能丢"这个经典坑。
func startStubConnect(t *testing.T, greeting string) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	seen := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		var lines []string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				break
			}
			lines = append(lines, strings.TrimSpace(line))
		}
		seen <- strings.Join(lines, " | ")
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n" + greeting))
		_, _ = io.Copy(c, br)
	}()
	return ln.Addr().String(), seen
}

// 代理端点作为任务出口：socks5 走通、凭据会发、目标以域名交给代理（socks5h 语义）。
func TestProxyDialerSocks5WithAuth(t *testing.T) {
	addr, seen := startStubSOCKS5(t, true, "u", "p")
	d, err := NewProxyDialer(context.Background(), "socks5://u:p@"+addr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Describe(), "u:p") || strings.Contains(d.Describe(), "@") {
		t.Fatalf("描述里不能有凭据：%q", d.Describe())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.Dial(ctx, "target.example:3306")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("回显读失败：%v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("回显 = %q", buf)
	}
	got := []string{<-seen, <-seen}
	if got[0] != "auth:u:p" {
		t.Fatalf("凭据没按 RFC1929 发出去：%v", got)
	}
	if got[1] != "connect:target.example:3306" {
		t.Fatalf("CONNECT 目标不对：%v", got)
	}
	_ = d.Close()
}

// HTTP CONNECT：回 200 之后对端立刻发的字节必须能被上层读到（bufio 里多读的那些不能丢）。
func TestProxyDialerHTTPConnectKeepsEarlyBytes(t *testing.T) {
	addr, seen := startStubConnect(t, "EARLY-BYTES")
	d, err := NewProxyDialer(context.Background(), "http://user:secret@"+addr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Describe(), "secret") {
		t.Fatalf("描述里不能有密码：%q", d.Describe())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.Dial(ctx, "10.0.0.5:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, len("EARLY-BYTES"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("CONNECT 之后紧跟的字节丢了（bufio 多读没吐回来）：%v", err)
	}
	if string(buf) != "EARLY-BYTES" {
		t.Fatalf("读到 %q", buf)
	}
	head := <-seen
	if !strings.Contains(head, "CONNECT 10.0.0.5:80") {
		t.Fatalf("CONNECT 行不对：%q", head)
	}
	want := base64.StdEncoding.EncodeToString([]byte("user:secret"))
	if !strings.Contains(head, "Proxy-Authorization: Basic "+want) {
		t.Fatalf("没带代理认证：%q", head)
	}
}

// 不支持的协议/坏地址要给出清楚错误（别等运行期才发现）。
func TestProxyDialerRejectsUnsupported(t *testing.T) {
	for _, raw := range []string{"", "ftp://1.2.3.4:21", "socks5://"} {
		if _, err := NewProxyDialer(context.Background(), raw); err == nil {
			t.Fatalf("%q 应当被拒绝", raw)
		}
	}
}
