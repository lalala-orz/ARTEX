package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tunnel"
)

// 一个任务只有一条出口：traffic 的身份→出口绑定就是一对一，所以每个任务最多一条隧道。
// 将来若要一个任务多条隧道（不同网段各一条），给每条隧道一个独立身份（task7-t1）即可，
// 下面的模型不用改。
const maxTunnelsPerTask = 1

const (
	// 探活必须在一个上限内出结论，否则一次卡死会把 tunnel_up 拖成挂起。
	tunnelProbeTimeout = 8 * time.Second
	// 健康巡检间隔与"连续失败几次才判定不可用"。判定要保守：目标端口关闭也会让 Dial
	// 失败，而那是目标的正常状态，不是隧道坏了。
	tunnelProbeInterval  = 15 * time.Second
	tunnelProbeFailLimit = 2
)

// ErrTunnelUnavailable 是隧道不可用时拒绝连接的错误。
//
// 它必须是一个"拒绝"，绝不能退化成直连：绑定了隧道的任务，流量从本机真实地址发出去
// 比直接失败更糟 —— 那会把真实来源暴露给内网目标。
var ErrTunnelUnavailable = errors.New("隧道不可用")

// ErrTunnelBusy 表示这条隧道已达到并发上限。它与"隧道不可用"不同：隧道是好的，只是这一波
// 并发太多，稍后重试即可。之所以要这个上限：载荷（尤其 PHP，一条连接占一个 worker）扛不住
// 无限并发——真机实测 4 路并发就能把目标站点一起打到不可用（见 docs/tunnel/LIMITS.md）。
var ErrTunnelBusy = errors.New("隧道并发已达上限")

// 每条隧道的并发上限按**载荷类型**取值，依据是真机实测：
//
//	PHP（.php/.phtml/…）  一条隧道连接 = 一个 PHP worker 被占满整条连接的生命周期（PHP 没有
//	                      线程，CONNECT 请求本身就是泵）。实测 3 并发连续 18 次请求全 200、
//	                      靶站全程健康 ✓；4 并发立刻把载荷和目标站点一起打挂（worker 耗尽）✗。
//	其它载荷（.go/.js/.jsp/.aspx/.cs/.java…）  没有这个约束：Go 是独立进程 + goroutine、
//	                      Java/.NET 有真线程，一个进程扛几十条连接毫无压力 ✓，所以放宽。
//
// 拿不准时（URL 没有扩展名等）按**最保守的 PHP 值**处理——宁可慢，也不要把目标站点拖挂。
const (
	tunnelMaxConnsPHP   = 3
	tunnelMaxConnsOther = 16
)

// tunnelConnLimit 决定这条隧道允许同时在跑的连接数。override > 0 时以调用方为准
// （agent/人明确知道载荷类型时可以覆盖，例如把 Go 载荷的 / 路径放宽）。
func tunnelConnLimit(serverURL string, override int) int {
	if override > 0 {
		return override
	}
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return tunnelMaxConnsPHP
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht":
		return tunnelMaxConnsPHP
	case "":
		return tunnelMaxConnsPHP
	default:
		return tunnelMaxConnsOther
	}
}

// tunnelOpener 建立隧道本身。生产用内嵌的 suo5 客户端；测试注入假实现。
type tunnelOpener func(ctx context.Context, req TunnelRequest) (tunnel.Dialer, error)

// TunnelRequest 描述一条要建立的隧道。
type TunnelRequest struct {
	TaskID int64
	// Backend 选后端："" 或 "regeorg" 走 Neo-reGeorg。留着这个字段是为了让"载荷与后端
	// 配对"有地方表达（文件库清单里每个条目都带 backend），将来加后端不用改协议。
	Backend string
	// ServerURL 是载荷 URL；ServerURLs 可以再给几个（Neo-reGeorg 支持多 URL 分散请求）。
	ServerURL  string
	ServerURLs []string
	Probe      string // 探活目标 host:port；默认取载荷 URL 的 host:port
	Upstream   string // 控制通道自己的出口：""=跟随 global_proxy、"direct"=直连、其它=代理 URL
	MaxConns   int    // 并发上限；0=按载荷类型自动（PHP 3、其它 16）
	Debug      bool
	// ControlLog 由 OpenTunnel 注入（只有它同时知道 Manager 和解析后的 upstream），
	// 用来把控制通道的关键事件写进流量库。测试里自带的 opener 忽略它即可。
	ControlLog func(tunnel.ControlEvent)
}

// tunnelHealth 是隧道最近一次探活结论。
type tunnelHealth struct {
	ok  bool
	err string
	at  time.Time
}

// Tunnel 是一条在册的隧道。
type Tunnel struct {
	ID        string
	TaskID    int64
	ServerURL string // 已脱敏，可进日志与账本
	Describe  string // 出口标签（已脱敏）
	Probe     string
	OpenedAt  time.Time

	health  atomic.Pointer[tunnelHealth]
	egress  tunnel.Dialer
	guarded *guardedDialer
	stop    chan struct{}
	stopOne sync.Once
	// cancel ends the tunnel's own lifecycle context (see OpenTunnel: the parent ctx is
	// owned by the registry, not by whoever asked for the tunnel).
	cancel context.CancelFunc
}

// Health 返回最近一次探活结论。
func (t *Tunnel) Health() (ok bool, reason string, at time.Time) {
	if h := t.health.Load(); h != nil {
		return h.ok, h.err, h.at
	}
	return false, "尚未探活", time.Time{}
}

// guardedDialer 把"隧道健康"这道门放在流量路径上：健康时走隧道，不健康时【拒绝】。
//
// 它是绑给 traffic 的那个 Dialer。注意它从不返回"直连"——nil 出口才是直连，而这里
// 永远是一个明确的错误，所以"死隧道退回直连"在类型上就不可能发生。
type guardedDialer struct {
	name   string
	egress tunnel.Dialer
	health *atomic.Pointer[tunnelHealth]
	// sem 是并发闸门：拿到名额才允许拨号，连接关闭时归还。满了就**立刻**失败，
	// 让调用方（或它的重试）稍后再来，而不是把载荷压垮、连带拖挂目标站点。
	sem chan struct{}
}

// limitedConn 在连接关闭时归还并发名额（幂等）。
type limitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func (g *guardedDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if h := g.health.Load(); h != nil && !h.ok {
		log.Printf("[tunnel] 拒绝连接 %s：隧道已标记不可用（%s）", addr, h.err)
		return nil, fmt.Errorf("%w：%s（最近探活失败：%s，%s）—— 已拒绝该连接，而不是退回直连",
			ErrTunnelUnavailable, g.name, h.err, h.at.Format(time.RFC3339))
	}
	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
		default:
			log.Printf("[tunnel] 拒绝连接 %s：%s 并发已达上限 %d（保护载荷与目标站点）", addr, g.name, cap(g.sem))
			return nil, fmt.Errorf("%w：%s 并发已达上限 %d，稍后重试", ErrTunnelBusy, g.name, cap(g.sem))
		}
	}
	conn, err := g.egress.Dial(ctx, addr)
	if err != nil {
		if g.sem != nil {
			<-g.sem
		}
		log.Printf("[tunnel] 经隧道连接 %s 失败: %v", addr, err)
		return nil, err
	}
	if g.sem == nil {
		return conn, nil
	}
	return &limitedConn{Conn: conn, release: func() { <-g.sem }}, nil
}

func (g *guardedDialer) Describe() string { return g.name }

// TunnelEgress marks this egress as slot-limited: the listener must not pool
// upstream connections on it, or idle ones keep slots until the peer times out.
func (g *guardedDialer) TunnelEgress() bool { return true }

// resolveUpstream 决定这条隧道的**控制通道**（平台→载荷）走哪里。
//
//	""        跟随平台的 global_proxy（现状，最常用）
//	"direct"  强制直连（也接受 none/off）
//	其它      当作代理 URL 用
//
// 需要 "direct" 的场景很具体：载荷部署在**私有网段**时，对外的代理通常拒绝转发私有目标
// （实测 ProxyCat 就拒绝 192.168/10/172.16），于是探活直接失败在代理那一跳。
func resolveUpstream(requested, globalProxy string) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "direct", "none", "off":
		return ""
	case "":
		return globalProxy
	default:
		return strings.TrimSpace(requested)
	}
}

// isProxyBackend 判断这条绑定是不是"用户已有的隧道/代理"（不是平台去投放载荷）。
// 判据与 defaultTunnelOpener 一致：显式声明，或者给了 socks5/socks5h 地址。
func isProxyBackend(req TunnelRequest) bool {
	switch strings.ToLower(strings.TrimSpace(req.Backend)) {
	case "proxy", "socks", "http", "https":
		return true
	}
	if b := strings.ToLower(strings.TrimSpace(req.Backend)); b != "" && b != "regeorg" && b != "neo" && b != "neoreg" {
		return false
	}
	if u, err := url.Parse(strings.TrimSpace(req.ServerURL)); err == nil {
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h":
			return true
		}
	}
	return false
}

// defaultTunnelOpener 建隧道。当前唯一的后端是 Neo-reGeorg：它的 PHP 载荷为"单 Session 多
// TCP 连接"而写，实测在真实 Apache 站点上连续多次请求全部成功，载荷只有 5.7KB。
//
// Backend 字段留着：它让"载荷与后端配对"这件事有地方表达（清单里每个条目都带 backend），
// 将来加第二个后端时不用改协议。
func defaultTunnelOpener(ctx context.Context, req TunnelRequest) (tunnel.Dialer, error) {
	backend := strings.ToLower(strings.TrimSpace(req.Backend))
	// 已经存在的隧道/代理端点（自己跑的 ssh -D / chisel / frp / suo5 客户端…）：平台直拨它，
	// 不经过 global_proxy。也给"只丢了一个 socks5 地址"的调用方一个好用的默认：看到
	// socks5/socks5h 就按代理出口处理，不必额外声明 backend。
	if backend == "" || backend == "regeorg" || backend == "neo" || backend == "neoreg" {
		if u, err := url.Parse(strings.TrimSpace(req.ServerURL)); err == nil {
			switch strings.ToLower(u.Scheme) {
			case "socks5", "socks5h":
				backend = "proxy"
			}
		}
	}
	switch backend {
	case "proxy", "socks", "http", "https":
		// 注意：这里用 ServerURL 原样（含凭据）；描述里会脱敏。
		return tunnel.NewProxyDialer(ctx, req.ServerURL)
	case "", "regeorg", "neo", "neoreg":
		urls := make([]string, 0, len(req.ServerURLs)+1)
		if strings.TrimSpace(req.ServerURL) != "" {
			urls = append(urls, req.ServerURL)
		}
		urls = append(urls, req.ServerURLs...)
		return tunnel.NewRegeorg(ctx, tunnel.RegeorgConfig{
			ServerURLs: urls,
			Upstream:   req.Upstream,
			Debug:      req.Debug,
			// 控制通道（平台 → 载荷）也入库：隧道为什么不通，以前只能翻日志。
			ControlLog: req.ControlLog,
		})
	default:
		return nil, fmt.Errorf("未知隧道后端 %q（当前只支持 regeorg）", req.Backend)
	}
}

// OpenTunnel 建立一条隧道，**端到端探活通过后才绑定**给该任务，并把它的出口登记进
// traffic 的身份路由。任何一步失败都不会留下已绑定的出口：任务继续走原来的出口。
//
// 门禁是必须的，不是保险：上游不可达时 MITM 会回一个假的空 200（见
// docs/tunnel/FINDING-upstream-fail-open），agent 会把假成功记成证据。所以"建好了"
// 必须由一次真实的隧道内连接证明，而不是由建连调用没报错来推断。
func (m *Manager) OpenTunnel(ctx context.Context, req TunnelRequest) (*Tunnel, error) {
	if req.TaskID <= 0 {
		return nil, errors.New("隧道必须属于一个任务")
	}
	// 已结束的任务不能再绑隧道：它已经没有 agent 会去用它，绑上只会在目标上留一个永远
	// 没人回收的载荷。这条门禁**必须放在管理器里**：agent 的 tunnel_up 与 HTTP 接口共用
	// 这里，只写在 handler 里会让 agent 路径漏过去（实测就是这样漏的）。
	if status := m.TaskStatus(strconv.FormatInt(req.TaskID, 10)); status != "" && pgdb.IsTerminal(status) {
		return nil, fmt.Errorf("任务 %d 已结束（%s），不能再建隧道", req.TaskID, status)
	}
	raw := strings.TrimSpace(req.ServerURL)
	if raw == "" {
		return nil, errors.New("服务端载荷 URL 不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("隧道地址无效：%q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// 载荷 URL，或者 HTTP CONNECT 型代理。
	case "socks5", "socks5h":
		if !isProxyBackend(req) {
			return nil, fmt.Errorf("socks5 地址请走代理出口（backend=proxy）：%q", raw)
		}
	default:
		return nil, fmt.Errorf("隧道地址只支持 http/https（载荷）或 socks5/socks5h/http（已有代理）：%q", raw)
	}
	if m.traffic == nil || !m.TrafficEnabled() {
		return nil, errors.New("流量捕获未开启：没有监听器可以绑定隧道")
	}
	// 控制通道（client → 载荷站点）默认跟随全局代理：它去的就是目标站点，属于目标流量，
	// 理应和别的目标流量走同一个出口。调用方可以指定别的上游，但"忘了传"不会变成直连。
	if isProxyBackend(req) {
		// 已有的隧道/代理：**没有控制通道**，所以不去碰 global_proxy —— 目标流量直接经它出去。
		req.Upstream = ""
	} else {
		req.Upstream = resolveUpstream(req.Upstream, m.GlobalProxy())
	}
	probe := strings.TrimSpace(req.Probe)
	if probe == "" {
		if isProxyBackend(req) {
			// 代理型没有载荷地址可当默认探活目标：拿一个"从代理那侧应该能连到"的公网地址。
			// 专供内网的代理连不上它，需要显式填探活目标（探活不过就不绑定，这是刻意的）。
			probe = "1.1.1.1:80"
		} else {
			probe = defaultProbeAddr(u)
		}
	}
	// 防自环：控制通道若指向我们自己的监听器，隧道就会把自己当目标，流量绕回来再进
	// 隧道，无限套娃。
	if addr := m.selfListenerAddr(); addr != "" {
		if sameHostPort(u.Host, addr) || sameHostPort(probe, addr) {
			return nil, fmt.Errorf("拒绝自环：%s 就是本机记录监听器地址（%s）", u.Host, addr)
		}
	}
	if _, _, err := net.SplitHostPort(probe); err != nil {
		return nil, fmt.Errorf("探活目标必须是 host:port，得到 %q", probe)
	}

	// 控制通道事件入库（记录策略见 tunnel_control_log.go）。放在这里而不是 opener 里：
	// 只有这里同时知道 Manager 与**解析后**的 upstream（出口标签要写真实的那个）。
	if !isProxyBackend(req) {
		req.ControlLog = m.tunnelControlLog(req.TaskID, req.Upstream)
	}

	m.tunnelMu.Lock()
	if m.tunnels == nil {
		m.tunnels = make(map[string]*Tunnel)
	}
	if m.tunnelsByTask == nil {
		m.tunnelsByTask = make(map[int64][]string)
	}
	if n := len(m.tunnelsByTask[req.TaskID]); n >= maxTunnelsPerTask {
		m.tunnelMu.Unlock()
		return nil, fmt.Errorf("任务 %d 已有 %d 条隧道（上限 %d），请先关闭：一个任务只有一条出口",
			req.TaskID, n, maxTunnelsPerTask)
	}
	m.tunnelMu.Unlock()

	open := m.tunnelOpener
	if open == nil {
		open = defaultTunnelOpener
	}
	// 隧道**不能**用调用方的 ctx 当父：suo5 的连接工厂挂在 ctx 上，而 HTTP 请求或 agent
	// 的工具调用一返回，调用方 ctx 就被取消——隧道会当场死掉，症状是"探活通过、之后每次
	// 连接立刻失败：factory has stopped"。所以父 ctx 由注册表持有，只在关闭/回收时取消。
	// 调用方的 ctx 只用来约束**建立阶段**（下面的探活会因为调用方消失而中止）。
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	egress, err := open(tunnelCtx, req)
	if err != nil {
		tunnelCancel()
		return nil, fmt.Errorf("建立隧道失败：%w", err)
	}
	t := &Tunnel{
		ID:        fmt.Sprintf("t%d-%d", req.TaskID, tunnelSeq.Add(1)),
		TaskID:    req.TaskID,
		ServerURL: redactURL(u),
		Describe:  egress.Describe(),
		Probe:     probe,
		OpenedAt:  time.Now(),
		egress:    egress,
		stop:      make(chan struct{}),
		cancel:    tunnelCancel,
	}
	limit := tunnelConnLimit(req.ServerURL, req.MaxConns)
	t.guarded = &guardedDialer{
		name:   t.Describe,
		egress: egress,
		health: &t.health,
		sem:    make(chan struct{}, limit),
	}
	log.Printf("[tunnel] 任务 %d 隧道出口已就绪：%s（并发上限 %d）", t.TaskID, t.Describe, limit)

	// 门禁：端到端探活。走【真实隧道】而不是 guarded，否则第一次探活会被自己的
	// "尚未探活"状态挡掉。
	pctx, cancel := context.WithTimeout(context.Background(), tunnelProbeTimeout)
	conn, perr := egress.Dial(pctx, probe)
	cancel()
	if perr != nil {
		_ = egress.Close()
		tunnelCancel()
		return nil, fmt.Errorf("隧道探活失败（%s）：%w —— 已拒绝绑定，该任务仍走原出口", probe, perr)
	}
	_ = conn.Close()
	t.health.Store(&tunnelHealth{ok: true, at: time.Now()})

	identity, token := m.TaskIdentity(req.TaskID)
	if identity == "" {
		_ = egress.Close()
		tunnelCancel()
		return nil, errors.New("无法为该任务生成代理凭据，拒绝绑定")
	}
	m.traffic.SetIdentityEgress(identity, token, req.TaskID, t.guarded)

	m.tunnelMu.Lock()
	m.tunnels[t.ID] = t
	m.tunnelsByTask[req.TaskID] = append(m.tunnelsByTask[req.TaskID], t.ID)
	m.tunnelMu.Unlock()

	go m.tunnelHealthLoop(t)
	log.Printf("[tunnel] 任务 %d 隧道已建立并绑定：%s（探活 %s 通过）", req.TaskID, t.Describe, probe)
	return t, nil
}

// tunnelSeq 给隧道编个进程内唯一号，只用于日志与句柄。
var tunnelSeq atomic.Uint64

// tunnelHealthLoop 定期探活。连续失败到上限才判定不可用：目标端口关闭也会让 Dial 失败，
// 那是目标的正常状态，不是隧道坏了，所以一次失败不改状态。判定为不可用后，guardedDialer
// 会立刻拒绝新连接；之后探活再成功则自动恢复。
func (m *Manager) tunnelHealthLoop(t *Tunnel) {
	every := m.tunnelProbeEvery
	if every <= 0 {
		every = tunnelProbeInterval
	}
	limit := m.tunnelProbeFailures
	if limit <= 0 {
		limit = tunnelProbeFailLimit
	}
	tk := time.NewTicker(every)
	defer tk.Stop()
	fails := 0
	cycle := 0
	for {
		select {
		case <-t.stop:
			return
		case <-tk.C:
			// 分层巡检：每轮先做便宜的"载荷还在吗"，端到端真拨号降到每 fullProbeEvery 轮一次。
			// 理由是实测出来的：真拨号每次都会在载荷上留一个 CONNECT 泵，而它的清理要等载荷
			// 察觉——攒几个就把 worker 占满，之后请求开始排队（表现为"越跑越容易卡"）。
			cycle++
			var err error
			if cycle%tunnelFullProbeEvery == 0 {
				err = m.fullProbeTunnel(t)
			} else {
				err = m.lightProbeTunnel(t)
			}
			if err == nil {
				fails = 0
				t.health.Store(&tunnelHealth{ok: true, at: time.Now()})
				continue
			}
			fails++
			if fails >= limit {
				t.health.Store(&tunnelHealth{ok: false, err: err.Error(), at: time.Now()})
				log.Printf("[tunnel] 任务 %d 隧道探活连续失败 %d 次，标记为不可用：该任务的新连接将被拒绝（不会退回直连）：%v",
					t.TaskID, fails, err)
			}
		}
	}
}

// tunnelFullProbeEvery：每多少轮巡检做一次端到端真拨号（其余轮只问载荷是否还在）。
const tunnelFullProbeEvery = 8

// tunnelPinger 是隧道后端可选的"便宜存活检查"能力。
type tunnelPinger interface {
	Ping(ctx context.Context) error
}

// lightProbeTunnel 只问"载荷还在按约定应答吗"，不占载荷的会话与 worker。后端不支持就退回真拨号。
// RecheckTaskTunnels 现场重探某个任务的隧道（界面「测连通性」用）：不改绑定，只把最新结论
// 写回健康状态并回给调用方。返回 (是否健康, 原因, 隧道条数)。
func (m *Manager) RecheckTaskTunnels(taskID int64) (bool, string, int) {
	m.tunnelMu.Lock()
	ids := append([]string(nil), m.tunnelsByTask[taskID]...)
	list := make([]*Tunnel, 0, len(ids))
	for _, id := range ids {
		if tn := m.tunnels[id]; tn != nil {
			list = append(list, tn)
		}
	}
	m.tunnelMu.Unlock()
	if len(list) == 0 {
		return false, "该任务当前没有隧道（隧道活在进程里，重启即失效）", 0
	}
	var errs []string
	for _, tn := range list {
		if err := m.fullProbeTunnel(tn); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return false, strings.Join(errs, "；"), len(list)
	}
	return true, "", len(list)
}
func (m *Manager) lightProbeTunnel(t *Tunnel) error {
	p, ok := t.egress.(tunnelPinger)
	if !ok {
		return m.fullProbeTunnel(t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), tunnelProbeTimeout)
	defer cancel()
	return p.Ping(ctx)
}

// fullProbeTunnel 经隧道真连一次探活目标：这是唯一能证明"整条路真的通"的检查。
func (m *Manager) fullProbeTunnel(t *Tunnel) error {
	ctx, cancel := context.WithTimeout(context.Background(), tunnelProbeTimeout)
	defer cancel()
	conn, err := t.egress.Dial(ctx, t.Probe)
	if err != nil {
		return err
	}
	return conn.Close()
}

// CloseTunnel 关闭一条隧道并把该任务放回默认出口。
func (m *Manager) CloseTunnel(id string) error {
	m.tunnelMu.Lock()
	t := m.tunnels[id]
	if t != nil {
		delete(m.tunnels, id)
		m.removeTaskTunnelLocked(t.TaskID, id)
	}
	m.tunnelMu.Unlock()
	if t == nil {
		return fmt.Errorf("隧道 %s 不存在", id)
	}
	m.unbindTunnel(t)
	return nil
}

// ReclaimTaskTunnels 关闭某任务的全部隧道。任务结束、删除、归档时调用，避免对目标留下
// 悬空的长连接。
// ReclaimFinishedTasks 兜底清扫：关掉那些"任务已经结束"的隧道。
//
// 正常回收挂在任务状态跃迁上（引擎跑完任务时调 ReclaimTaskTunnels），但只要有一次漏掉
// —— agent 在收尾阶段建的、或状态是被别的路径写成终态的 —— 隧道就会一直留在进程里，
// 现象就是"任务都结束了，还能在列表里查到隧道"。所以列表接口每次先扫一遍：完成任务的
// 隧道当场关闭，并写日志说明关了谁的。
func (m *Manager) ReclaimFinishedTasks() []int64 {
	m.tunnelMu.Lock()
	tasks := make(map[int64]bool, len(m.tunnels))
	for _, t := range m.tunnels {
		tasks[t.TaskID] = true
	}
	m.tunnelMu.Unlock()
	var closed []int64
	for taskID := range tasks {
		if taskID <= 0 {
			// 无归属的桶（task 0）：正常建不出来（OpenTunnel 拒绝），真出现了也不猜它的
			// 生命周期，留给人工处理，别误杀。
			continue
		}
		if pgdb.IsTerminal(m.TaskStatus(strconv.FormatInt(taskID, 10))) {
			m.ReclaimTaskTunnels(taskID)
			closed = append(closed, taskID)
		}
	}
	if len(closed) > 0 {
		log.Printf("[tunnel] 清扫已结束任务的隧道: %v", closed)
	}
	return closed
}
func (m *Manager) ReclaimTaskTunnels(taskID int64) {
	m.tunnelMu.Lock()
	ids := append([]string(nil), m.tunnelsByTask[taskID]...)
	tunnels := make([]*Tunnel, 0, len(ids))
	for _, id := range ids {
		if t := m.tunnels[id]; t != nil {
			tunnels = append(tunnels, t)
			delete(m.tunnels, id)
		}
	}
	delete(m.tunnelsByTask, taskID)
	m.tunnelMu.Unlock()
	for _, t := range tunnels {
		m.unbindTunnel(t)
	}
}

// ReclaimTaskTunnelsByString 是 ReclaimTaskTunnels 的 API 层入口：任务在 API 与 Task
// 里都是字符串 id，非数字 id 名下不会有隧道。
func (m *Manager) ReclaimTaskTunnelsByString(id string) {
	n, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if err != nil {
		return
	}
	m.ReclaimTaskTunnels(n)
}

// unbindTunnel 关闭隧道并把它从身份上摘掉，回到默认出口。
//
// 摘绑用 SetIdentityEgress(..., nil) 而不是 ClearIdentityEgress：后者会把身份一起删掉，
// 于是该任务其余流量的凭据全部失效。nil 出口才是"已认证、走默认出口"。
func (m *Manager) unbindTunnel(t *Tunnel) {
	t.stopOne.Do(func() { close(t.stop) })
	if t.cancel != nil {
		t.cancel()
	}
	if err := t.egress.Close(); err != nil {
		log.Printf("[tunnel] 任务 %d 关闭隧道出错: %v", t.TaskID, err)
	}
	if m.traffic != nil {
		// 只读查找：任务删除时凭据可能已经清掉，这里绝不能重新生成。
		if identity, token, ok := m.taskCredFor(t.TaskID); ok && identity != "" {
			m.traffic.SetIdentityEgress(identity, token, t.TaskID, nil)
		}
	}
	log.Printf("[tunnel] 任务 %d 隧道 %s 已关闭，回到默认出口", t.TaskID, t.ID)
}

// removeTaskTunnelLocked 从任务的隧道列表里摘掉一条。调用方必须持有 tunnelMu。
func (m *Manager) removeTaskTunnelLocked(taskID int64, id string) {
	ids := m.tunnelsByTask[taskID]
	kept := ids[:0]
	for _, v := range ids {
		if v != id {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		delete(m.tunnelsByTask, taskID)
		return
	}
	m.tunnelsByTask[taskID] = kept
}

// TunnelInfo 是隧道的对外快照（给 API 与工具用）。
type TunnelInfo struct {
	ID        string    `json:"id"`
	TaskID    int64     `json:"task_id"`
	ServerURL string    `json:"server_url"`
	Egress    string    `json:"egress"`
	Probe     string    `json:"probe"`
	OpenedAt  time.Time `json:"opened_at"`
	Healthy   bool      `json:"healthy"`
	Reason    string    `json:"reason,omitempty"`
	ProbedAt  time.Time `json:"probed_at,omitempty"`
}

// Tunnels 列出在册隧道；taskID > 0 时只列该任务的。
func (m *Manager) Tunnels(taskID int64) []TunnelInfo {
	m.tunnelMu.Lock()
	all := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		if taskID <= 0 || t.TaskID == taskID {
			all = append(all, t)
		}
	}
	m.tunnelMu.Unlock()
	out := make([]TunnelInfo, 0, len(all))
	for _, t := range all {
		ok, reason, at := t.Health()
		out = append(out, TunnelInfo{
			ID: t.ID, TaskID: t.TaskID, ServerURL: t.ServerURL, Egress: t.Describe,
			Probe: t.Probe, OpenedAt: t.OpenedAt, Healthy: ok, Reason: reason, ProbedAt: at,
		})
	}
	return out
}

// selfListenerAddr 是本机记录监听器的 host:port（""=捕获关闭）。
func (m *Manager) selfListenerAddr() string {
	if m.traffic == nil || !m.TrafficEnabled() {
		return ""
	}
	raw := m.traffic.ProxyAddr() // http://host:port
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// sameHostPort 比较两个 host:port 是否指向同一处，把本机各种写法（localhost/127.0.0.1/
// 0.0.0.0/[::1]/省略端口）都算作同一处：自环检查宁可多拦，不可放过。
func sameHostPort(a, b string) bool {
	ah, ap := splitHostPortLoose(a)
	bh, bp := splitHostPortLoose(b)
	if ap != bp {
		return false
	}
	return isLoopbackName(ah) && isLoopbackName(bh) || strings.EqualFold(ah, bh)
}

func splitHostPortLoose(hostport string) (host, port string) {
	hostport = strings.TrimSpace(hostport)
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(hostport, "[]"), ""
}

func isLoopbackName(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "":
		return true
	}
	return false
}

// defaultProbeAddr 取载荷 URL 的 host:port 作默认探活目标：这条连接会经隧道由载荷所在
// 主机去连它自己，能连上就证明"控制通道 + 中继"整条路是通的。
func defaultProbeAddr(u *url.URL) string {
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return u.Host
	}
	port := "80"
	if u.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// redactURL 去掉 URL 里的 userinfo：隧道地址会进日志、账本和 API。
func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	return c.String()
}
