package server

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/tunnel"
)

// countingDialer 只负责返回一个可关闭的连接，用来观察闸门行为。
type countingDialer struct{ dials atomic.Int64 }

func (d *countingDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d.dials.Add(1)
	c, _ := net.Pipe()
	return c, nil
}
func (d *countingDialer) Describe() string { return "counting" }
func (d *countingDialer) Close() error     { return nil }

var _ tunnel.Dialer = (*countingDialer)(nil)

// 并发闸门：到顶必须**立刻**失败（保护载荷与目标站点），连接关闭后名额要归还。
//
// 为什么需要它：真机实测 PHP 载荷在 2 路并发下干净利落（0.3s），4 路并发就把载荷和目标站点
// 一起打到不可用（见 docs/tunnel/LIMITS.md §8）。没有闸门时，agent 或批量工具很容易顺手
// 开出更多并发。
func TestTunnelConcurrencyCapFailsFast(t *testing.T) {
	fd := &countingDialer{}
	var h atomic.Pointer[tunnelHealth]
	g := &guardedDialer{name: "test", egress: fd, health: &h, sem: make(chan struct{}, 2)}
	ctx := context.Background()

	c1, err := g.Dial(ctx, "127.0.0.1:80")
	if err != nil {
		t.Fatalf("第 1 条连接不该被拒: %v", err)
	}
	c2, err := g.Dial(ctx, "127.0.0.1:80")
	if err != nil {
		t.Fatalf("第 2 条连接不该被拒: %v", err)
	}

	start := time.Now()
	_, err = g.Dial(ctx, "127.0.0.1:80")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrTunnelBusy) {
		t.Fatalf("第 3 条连接的错误 = %v，想要 ErrTunnelBusy", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("到顶后用了 %v 才失败，应当立刻失败", elapsed)
	}
	if got := fd.dials.Load(); got != 2 {
		t.Fatalf("闸门到顶后仍然拨号了 %d 次（应为 2）", got)
	}

	// 关掉一条，名额必须归还。
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	c3, err := g.Dial(ctx, "127.0.0.1:80")
	if err != nil {
		t.Fatalf("释放名额后仍被拒: %v", err)
	}
	_ = c2.Close()
	_ = c3.Close()

	// 重复 Close 不能把名额还两次（否则闸门会越来越宽）。
	c4, err := g.Dial(ctx, "127.0.0.1:80")
	if err != nil {
		t.Fatalf("幂等 Close 之后不该被拒: %v", err)
	}
	_ = c4.Close()
}

// 并发上限按载荷类型取值：PHP 一条隧道连接就占一个 worker（实测 3 稳、4 崩），其它载荷没这个
// 约束（Go 是进程+goroutine、Java/.NET 有真线程）可以放宽。拿不准时按最保守的 PHP 值。
func TestTunnelConnLimit(t *testing.T) {
	cases := []struct {
		url      string
		override int
		want     int
	}{
		{"http://t/tunnel.php", 0, tunnelMaxConnsPHP},
		{"http://t/TUNNEL.PHP", 0, tunnelMaxConnsPHP},
		{"http://t/x.phtml", 0, tunnelMaxConnsPHP},
		{"http://t/tunnel.php?a=1&b=2", 0, tunnelMaxConnsPHP},
		{"http://t:8080/tunnel.jsp", 0, tunnelMaxConnsOther},
		{"http://t/tunnel.jspx", 0, tunnelMaxConnsOther},
		{"http://t/tunnel.aspx", 0, tunnelMaxConnsOther},
		{"http://t/tunnel.ashx", 0, tunnelMaxConnsOther},
		{"http://t/tunnel.go", 0, tunnelMaxConnsOther},
		{"http://t/tunnel.js", 0, tunnelMaxConnsOther},
		// 没有扩展名（Go 载荷常跑在 / 上）：保守取 PHP 值，需要时用 override 放宽。
		{"http://t/", 0, tunnelMaxConnsPHP},
		{"http://t", 0, tunnelMaxConnsPHP},
		{"://bad url", 0, tunnelMaxConnsPHP},
		// 显式覆盖永远优先。
		{"http://t/", 32, 32},
		{"http://t/tunnel.php", 8, 8},
	}
	for _, c := range cases {
		if got := tunnelConnLimit(c.url, c.override); got != c.want {
			t.Errorf("tunnelConnLimit(%q, override=%d) = %d，想要 %d", c.url, c.override, got, c.want)
		}
	}
}

// 并发上限必须真的落到**建成的那条隧道**上（不只是有个算上限的函数）：走一遍 OpenTunnel，
// 看闸门容量。这样 .php→3、其它→16、显式覆盖优先这三条链路都是端到端验过的。
func TestOpenTunnelAppliesConnLimit(t *testing.T) {
	cases := []struct {
		url      string
		maxConns int
		want     int
	}{
		{"http://10.1.1.5/tunnel.php", 0, tunnelMaxConnsPHP},
		{"http://10.1.1.5/tunnel.jsp", 0, tunnelMaxConnsOther},
		{"http://10.1.1.5/tunnel.aspx", 0, tunnelMaxConnsOther},
		{"http://10.1.1.5/tunnel.php", 8, 8},
		{"http://10.1.1.5/", 0, tunnelMaxConnsPHP},
	}
	for i, c := range cases {
		m, _, _ := newTunnelTestManager(t)
		fake := &fakeTunnel{desc: "regeorg:" + c.url}
		m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) { return fake, nil }
		taskID := int64(100 + i)
		tun, err := m.OpenTunnel(context.Background(), TunnelRequest{
			TaskID: taskID, ServerURL: c.url, MaxConns: c.maxConns,
		})
		if err != nil {
			t.Fatalf("第 %d 例建隧道失败: %v", i, err)
		}
		got := cap(tun.guarded.sem)
		if got != c.want {
			t.Fatalf("第 %d 例（%s, override=%d）闸门容量 = %d，想要 %d", i, c.url, c.maxConns, got, c.want)
		}
		m.ForgetTaskRuntime(strconv.FormatInt(taskID, 10))
	}
}
