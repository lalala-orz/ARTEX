package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/tunnel"
)

type fakeTunnelDialer struct {
	calls int32
	fail  error
}

func (f *fakeTunnelDialer) Describe() string { return "fake-tunnel" }
func (f *fakeTunnelDialer) Close() error     { return nil }
func (f *fakeTunnelDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.fail != nil {
		return nil, f.fail
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

var _ tunnel.Dialer = (*fakeTunnelDialer)(nil)

// 隧道名额是"保护载荷与目标站点"的闸门：满了必须【立刻】失败（让调用方稍后重试），
// 而且任何一条路径——连接关闭、拨号失败、不健康拒绝——都不能把名额漏掉。
// 漏一个名额就少一条并发，漏满三个就等于"隧道坏了"（A1 就是这类症状）。
func TestGuardedDialerSlotBudget(t *testing.T) {
	h := &atomic.Pointer[tunnelHealth]{}
	h.Store(&tunnelHealth{ok: true, at: time.Now()})
	fake := &fakeTunnelDialer{}
	g := &guardedDialer{name: "test", egress: fake, health: h, sem: make(chan struct{}, 2)}
	ctx := context.Background()

	c1, err := g.Dial(ctx, "10.0.0.1:80")
	if err != nil {
		t.Fatalf("第 1 条应当成功: %v", err)
	}
	c2, err := g.Dial(ctx, "10.0.0.1:80")
	if err != nil {
		t.Fatalf("第 2 条应当成功: %v", err)
	}
	if _, err := g.Dial(ctx, "10.0.0.1:80"); !errors.Is(err, ErrTunnelBusy) {
		t.Fatalf("第 3 条应当立刻报忙（ErrTunnelBusy），实际 %v", err)
	}
	// 关闭即归还，且幂等：多关几次不能把名额"还多"。
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dial(ctx, "10.0.0.1:80"); err != nil {
		t.Fatalf("关闭一条后应当腾出名额: %v", err)
	}
	if err := c2.Close(); err != nil {
		t.Fatal(err)
	}
	// 拨号失败必须归还名额，否则失败会"吃掉"并发。
	fake.fail = errors.New("boom")
	if _, err := g.Dial(ctx, "10.0.0.1:80"); err == nil {
		t.Fatal("应当把拨号错误透出来")
	}
	fake.fail = nil
	if _, err := g.Dial(ctx, "10.0.0.1:80"); err != nil {
		t.Fatalf("拨号失败后名额必须归还: %v", err)
	}
	// 不健康 ⇒ 明确拒绝（绝不退回直连），并且不占名额。
	h.Store(&tunnelHealth{ok: false, err: "探活失败", at: time.Now()})
	if _, err := g.Dial(ctx, "10.0.0.1:80"); !errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("不健康时应当 ErrTunnelUnavailable，实际 %v", err)
	}
}

// 类型层面就要保证"死隧道不会退回直连"：nil 出口才是直连，guardedDialer 永远返回错误。
func TestGuardedDialerNeverFallsBackToDirect(t *testing.T) {
	h := &atomic.Pointer[tunnelHealth]{}
	h.Store(&tunnelHealth{ok: false, err: "probe failed", at: time.Now()})
	g := &guardedDialer{name: "dead", egress: &fakeTunnelDialer{}, health: h, sem: make(chan struct{}, 1)}
	conn, err := g.Dial(context.Background(), "10.0.0.1:80")
	if conn != nil || err == nil {
		t.Fatal("不健康时不能返回连接（那等于静默直连）")
	}
	if !g.TunnelEgress() {
		t.Fatal("必须被识别为槽位受限出口，否则连接池会吃掉名额")
	}
}
