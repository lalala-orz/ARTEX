package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/artex/tunnel"
)

// fakeTunnel 冒充一条隧道：探活与拨号都走它，好把门禁与健康判定的逻辑单独测出来，
// 不用真的架一个 suo5 服务端。
type fakeTunnel struct {
	desc string

	mu        sync.Mutex
	dialCount int
	lastAddr  string
	fail      bool
	closed    bool
}

func (f *fakeTunnel) Dial(ctx context.Context, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialCount++
	f.lastAddr = addr
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return nil, errors.New("目标不可达")
	}
	// 探活只要求拿到一条连接再关掉，net.Pipe 足够。
	c, peer := net.Pipe()
	_ = peer.Close()
	return c, nil
}

func (f *fakeTunnel) Describe() string { return f.desc }

func (f *fakeTunnel) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeTunnel) setFail(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}

func (f *fakeTunnel) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeTunnel) probeAddr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAddr
}

func (f *fakeTunnel) dials() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dialCount
}

// newTunnelTestManager 起一个真的记录监听器（traffic.Open），但隧道用假的：身份路由、
// 门禁、健康判定都是真实代码路径。
func newTunnelTestManager(t *testing.T) (*Manager, *traffic.Traffic, string) {
	t.Helper()
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	tr, err := traffic.Open(dir, addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = tr.Start() }()
	waitListener(t, addr)
	t.Cleanup(func() { tr.Close() })
	return &Manager{dir: dir, traffic: tr, trafficOn: true}, tr, addr
}

func waitListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("记录监听器 %s 未就绪", addr)
}

func waitTunnelUnhealthy(t *testing.T, m *Manager, taskID int64) TunnelInfo {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if list := m.Tunnels(taskID); len(list) == 1 && !list[0].Healthy {
			return list[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("隧道未在预期时间内被判定为不可用")
	return TunnelInfo{}
}

// ctxBoundTunnel 模拟 suo5 的关键性质：它的连接工厂挂在**建立时收到的那个 ctx** 上。
type ctxBoundTunnel struct {
	ctx  context.Context
	desc string
}

func (f *ctxBoundTunnel) Dial(context.Context, string) (net.Conn, error) {
	if err := f.ctx.Err(); err != nil {
		return nil, fmt.Errorf("factory has stopped: %w", err)
	}
	c, peer := net.Pipe()
	_ = peer.Close()
	return c, nil
}

func (f *ctxBoundTunnel) Describe() string { return f.desc }
func (f *ctxBoundTunnel) Close() error     { return nil }

// 隧道必须活过它的"建立阶段"。HTTP 请求或 agent 工具调用一返回，调用方的 ctx 就被取消，
// 而 suo5 的连接工厂挂在 ctx 上——曾经因此出现"探活通过、之后每次连接立刻 factory has
// stopped"。隧道属于注册表，不属于发起它的那一次调用。
func TestTunnelOutlivesItsSetupContext(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	var tunnelCtx context.Context
	m.tunnelOpener = func(ctx context.Context, _ TunnelRequest) (tunnel.Dialer, error) {
		tunnelCtx = ctx
		return &ctxBoundTunnel{ctx: ctx, desc: "suo5:http://10.1.1.5/x.php"}, nil
	}
	setup, cancelSetup := context.WithCancel(context.Background())
	tun, err := m.OpenTunnel(setup, TunnelRequest{TaskID: 7, ServerURL: "http://10.1.1.5/x.php"})
	if err != nil {
		t.Fatal(err)
	}
	cancelSetup() // 调用方结束：HTTP 响应已写、或工具调用已返回
	time.Sleep(50 * time.Millisecond)
	if err := tunnelCtx.Err(); err != nil {
		t.Fatalf("隧道被调用方的 ctx 取消了（探活会过、之后每次连接都会失败）: %v", err)
	}
	conn, err := tun.guarded.Dial(context.Background(), "127.0.0.1:9998")
	if err != nil {
		t.Fatalf("调用方结束后隧道不可用: %v", err)
	}
	_ = conn.Close()
	if got := tr.IdentityEgressLabel("task7"); got == "" {
		t.Fatal("隧道绑定丢了")
	}
	// 回收时必须真的取消，否则隧道生命周期泄漏。
	m.ReclaimTaskTunnels(7)
	deadline := time.Now().Add(2 * time.Second)
	for tunnelCtx.Err() == nil {
		if time.Now().After(deadline) {
			t.Fatal("回收后隧道的生命周期 ctx 仍未取消")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// 探活不过就绝不能绑定：任务必须继续走原来的出口，而且隧道不能留在那儿占资源。
func TestOpenTunnelProbeGateRefusesUnusableTunnel(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	fake := &fakeTunnel{desc: "suo5:http://10.1.1.5/x.php", fail: true}
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) { return fake, nil }

	_, err := m.OpenTunnel(context.Background(), TunnelRequest{
		TaskID: 7, ServerURL: "http://10.1.1.5/x.php",
	})
	if err == nil {
		t.Fatal("探活失败却绑定成功了")
	}
	if !strings.Contains(err.Error(), "探活失败") {
		t.Fatalf("错误没有说明是探活失败：%v", err)
	}
	if got := tr.IdentityEgressLabel("task7"); got != "" {
		t.Fatalf("探活失败却绑定了出口 %q", got)
	}
	if !fake.isClosed() {
		t.Fatal("探活失败后没有关闭隧道（连接泄漏）")
	}
	if list := m.Tunnels(7); len(list) != 0 {
		t.Fatalf("探活失败却登记了 %d 条隧道", len(list))
	}
}

// 探活通过才绑定，并且默认探活目标就是载荷 URL 的 host:port：那条连接由载荷所在主机
// 去连它自己，能连上才证明"控制通道 + 中继"整条路通。
func TestOpenTunnelBindsAfterProbe(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	fake := &fakeTunnel{desc: "suo5:http://10.1.1.5:8080/x.php"}
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) { return fake, nil }

	tun, err := m.OpenTunnel(context.Background(), TunnelRequest{
		TaskID: 7, ServerURL: "http://10.1.1.5:8080/x.php",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := tr.IdentityEgressLabel("task7"); got != fake.desc {
		t.Fatalf("绑定的出口 = %q，想要 %q", got, fake.desc)
	}
	if got := fake.probeAddr(); got != "10.1.1.5:8080" {
		t.Fatalf("默认探活目标 = %q，想要 10.1.1.5:8080", got)
	}
	list := m.Tunnels(7)
	if len(list) != 1 || !list[0].Healthy {
		t.Fatalf("隧道登记状态不对：%+v", list)
	}
	if list[0].TaskID != 7 || list[0].Egress != fake.desc {
		t.Fatalf("隧道信息不对：%+v", list[0])
	}

	// 一个任务只有一条出口，所以第二条隧道必须被拒。
	if _, err := m.OpenTunnel(context.Background(), TunnelRequest{
		TaskID: 7, ServerURL: "http://10.1.1.6/x.php",
	}); err == nil {
		t.Fatal("同一任务的第二条隧道被接受了")
	}

	// 回收：隧道关掉、出口回到默认，凭据也一并清掉。
	m.ForgetTaskRuntime("7")
	if !fake.isClosed() {
		t.Fatal("回收后隧道没有关闭")
	}
	if got := tr.IdentityEgressLabel("task7"); got != "" {
		t.Fatalf("回收后仍绑着出口 %q", got)
	}
	if list := m.Tunnels(7); len(list) != 0 {
		t.Fatalf("回收后仍登记着 %d 条隧道", len(list))
	}
	if _, _, ok := m.taskCredFor(7); ok {
		t.Fatal("回收后凭据仍在")
	}
	_ = tun
}

// 这是 fail-closed 的正面证明：隧道被判定不可用后，绑定的出口必须【拒绝】连接，而不是
// 悄悄退回直连 —— 退回直连会把本机真实地址暴露给内网目标。
func TestUnhealthyTunnelRefusesInsteadOfDirect(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	m.tunnelProbeEvery = 20 * time.Millisecond
	m.tunnelProbeFailures = 1
	fake := &fakeTunnel{desc: "suo5:http://10.1.1.5:8080/x.php"}
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) { return fake, nil }

	tun, err := m.OpenTunnel(context.Background(), TunnelRequest{
		TaskID: 7, ServerURL: "http://10.1.1.5:8080/x.php",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 隧道断了：探活开始失败，巡检应把它标成不可用。
	fake.setFail(true)
	info := waitTunnelUnhealthy(t, m, 7)
	if !strings.Contains(info.Reason, "不可达") {
		t.Fatalf("不可用原因没有带上探活错误：%q", info.Reason)
	}

	// 关键断言：拒绝，而不是直连。nil 错误就意味着"悄悄直连了"。
	conn, err := tun.guarded.Dial(context.Background(), "10.0.0.9:3306")
	if err == nil {
		conn.Close()
		t.Fatal("隧道不可用时仍然建立了连接（fail-open：真实地址已暴露）")
	}
	if !errors.Is(err, ErrTunnelUnavailable) {
		t.Fatalf("错误类型 = %v，想要 ErrTunnelUnavailable", err)
	}
	if !strings.Contains(err.Error(), "拒绝") {
		t.Fatalf("错误信息没有说明是拒绝：%v", err)
	}

	// 探活恢复后应自动恢复可用（否则一次抖动就要人工重建隧道）。
	fake.setFail(false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if list := m.Tunnels(7); len(list) == 1 && list[0].Healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if list := m.Tunnels(7); !list[0].Healthy {
		t.Fatal("探活恢复后隧道没有自动恢复")
	}
}

// 控制通道指向本机监听器就是自环：流量绕回来再进隧道，无限套娃。
func TestOpenTunnelRefusesSelfLoop(t *testing.T) {
	m, _, addr := newTunnelTestManager(t)
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) {
		t.Fatal("自环检查必须先于建立隧道")
		return nil, nil
	}
	for _, raw := range []string{
		"http://" + addr + "/x.php",
		"http://localhost:" + strings.Split(addr, ":")[1] + "/x.php",
	} {
		if _, err := m.OpenTunnel(context.Background(), TunnelRequest{TaskID: 7, ServerURL: raw}); err == nil {
			t.Fatalf("自环地址 %q 没有被拒绝", raw)
		} else if !strings.Contains(err.Error(), "自环") {
			t.Fatalf("自环地址 %q 的报错不对：%v", raw, err)
		}
	}
}

// 捕获关闭时没有监听器可以绑定，必须明确拒绝而不是建一条没人用的隧道。
func TestOpenTunnelRequiresCapture(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	m.trafficOn = false
	m.tunnelOpener = func(context.Context, TunnelRequest) (tunnel.Dialer, error) {
		t.Fatal("捕获关闭时不该建立隧道")
		return nil, nil
	}
	if _, err := m.OpenTunnel(context.Background(), TunnelRequest{
		TaskID: 7, ServerURL: "http://10.1.1.5/x.php",
	}); err == nil || !strings.Contains(err.Error(), "流量捕获未开启") {
		t.Fatalf("捕获关闭时的错误不对：%v", err)
	}
}

// 控制通道默认跟随全局代理：载荷站点就是目标，属于目标流量，不该绕开平台出口直连。
func TestOpenTunnelControlChannelFollowsGlobalProxy(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	m.mu.Lock()
	m.globalProxy = "socks5://127.0.0.1:1080"
	m.mu.Unlock()

	var got string
	m.tunnelOpener = func(_ context.Context, req TunnelRequest) (tunnel.Dialer, error) {
		got = req.Upstream
		return &fakeTunnel{desc: "suo5:http://10.1.1.5:8080/x.php"}, nil
	}
	if _, err := m.OpenTunnel(context.Background(), TunnelRequest{
		TaskID: 7, ServerURL: "http://10.1.1.5:8080/x.php",
	}); err != nil {
		t.Fatal(err)
	}
	if got != "socks5://127.0.0.1:1080" {
		t.Fatalf("控制通道上游 = %q，想要全局代理", got)
	}
}

func TestSameHostPort(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"127.0.0.1:8788", "127.0.0.1:8788", true},
		{"localhost:8788", "127.0.0.1:8788", true},
		{"0.0.0.0:8788", "localhost:8788", true},
		{"[::1]:8788", "127.0.0.1:8788", true},
		{"127.0.0.1:8788", "127.0.0.1:80", false},
		{"10.1.1.5:8788", "127.0.0.1:8788", false},
		{"10.1.1.5:80", "10.1.1.5:80", true},
	}
	for _, c := range cases {
		if got := sameHostPort(c.a, c.b); got != c.want {
			t.Errorf("sameHostPort(%q,%q) = %v，想要 %v", c.a, c.b, got, c.want)
		}
	}
}
