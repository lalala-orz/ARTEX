package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/regeorg"
)

// RegeorgConfig 描述一条 Neo-reGeorg 隧道。
type RegeorgConfig struct {
	// ServerURLs 是载荷 URL，可以给多个（上游支持多 URL 分散请求），每次请求随机选一个。
	ServerURLs []string
	// Upstream 是控制通道自己的出口（平台里的 global_proxy）；空=直连。
	Upstream string
	// Timeout 是单次 HTTP 请求超时（秒），<=0 用 30。
	Timeout int
	// ExtraHeader 追加到每个请求上（例如 Cookie/Authorization）。
	ExtraHeader []string
	// ReadBuffKB 是单次 FORWARD 最多携带的数据量（KB），默认 7，上限 50。
	ReadBuffKB int
	// MaxRetry 是建立阶段（hello / CONNECT）单次请求的重试次数，默认 10。
	MaxRetry int
	// DataTimeoutMS / DataRetries 只作用于**数据路径**（READ/FORWARD/DISCONNECT）。
	// 轮询协议的正常往返是几十毫秒级，所以这里要短得多：默认 8s / 2 次。设长了的下场是
	// 载荷一旦卡住，我的请求会一直等（30s × 重试次数），而上层（agent 的 curl）早就放弃了，
	// 表现成"挂 25 秒无响应"。
	DataTimeoutMS int
	DataRetries   int
	// ReadIntervalMS / WriteIntervalMS 是空闲时的轮询间隔（毫秒），默认 300 / 200。
	ReadIntervalMS  int
	WriteIntervalMS int
	// LocalDNS=true 时由客户端解析域名；默认 false，交给服务端在目标侧解析
	// （内网域名只有那边能解，这一点和平台其它出口的语义一致）。
	LocalDNS bool
	// AsyncConnect 对 PHP 载荷必须开：CONNECT 是长轮询，发出去就不等响应了。
	// 留空时按 URL 里是否带 .php 自动判断。
	AsyncConnect *bool
	// AsyncWaitMS / AsyncPollMS 是异步 CONNECT 之后"确认会话真的建立"的总时长与轮询间隔
	// （毫秒）。默认 6000 / 120；测试会调小。
	AsyncWaitMS int
	AsyncPollMS int
	Debug       bool
	// ControlLog 是"控制通道请求"回调：每发一次请求（hello/CONNECT/READ/FORWARD/…）都会被
	// 调用一次。它跑在请求路径上，所以必须快速返回；记哪些、怎么去重由调用方决定
	// （server 侧只记首次成功与传输层失败，成功的长轮询不记 —— 见 tunnel_control_log.go）。
	// 为空表示不记录。
	ControlLog func(ControlEvent)
	LogWriter  io.Writer
}

// ControlEvent 描述控制通道的一次请求。URL 刻意只到路径：regeorg 把载荷协议的数据放在查询串
// 里，整条 URL 记进流量库等于把载荷通信内容抄一份，没必要。
type ControlEvent struct {
	At      int64
	Method  string
	Host    string
	Path    string
	URL     string
	Status  int
	ReqLen  int
	RespLen int
	// Err 非空表示这次请求在传输层就失败了（超时、连不上、被代理拒绝）。
	Err string
}

// controlTransport 只做一件事：把每一次控制通道请求的形状交给回调，然后原样返回结果。
// 回调 panic 也被吞掉 —— 记录永远不能影响隧道本身能不能用。
type controlTransport struct {
	base http.RoundTripper
	log  func(ControlEvent)
}

func (c *controlTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if c.log != nil {
		ev := ControlEvent{
			At:     time.Now().Unix(),
			Method: req.Method,
			Host:   req.URL.Host,
			Path:   req.URL.Path,
			URL:    req.URL.Scheme + "://" + req.URL.Host + req.URL.Path,
			ReqLen: int(req.ContentLength),
		}
		if ev.ReqLen < 0 {
			ev.ReqLen = 0
		}
		if err != nil {
			ev.Err = err.Error()
		} else if resp != nil {
			ev.Status = resp.StatusCode
			if resp.ContentLength > 0 {
				ev.RespLen = int(resp.ContentLength)
			}
		}
		func() {
			defer func() { _ = recover() }()
			c.log(ev)
		}()
	}
	return resp, err
}

// CloseIdleConnections 让上层继续能按接口收起空闲连接（包装之后不再是 *http.Transport）。
func (c *controlTransport) CloseIdleConnections() {
	if closer, ok := c.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Regeorg 是一条 Neo-reGeorg 隧道，实现 Dialer。
//
// 与载荷的约定（见 regeorg 包）：请求体是"变形 base64 包着的 BLV 字段"，命令有四个——
// CONNECT（载荷那边开 TCP 并进入泵循环）、READ（把目标→客户端的数据取回来）、
// FORWARD（把客户端→目标的数据推过去）、DISCONNECT。PHP 没有线程，所以 CONNECT 就是那个
// 泵本身，客户端发完不等响应；java/.net/go 这些载荷自己开线程，所以能同步拿到 STATUS。
type Regeorg struct {
	cfg    RegeorgConfig
	urls   []string
	client *http.Client
	desc   string

	// ctx 是隧道自己的生命周期（由上层注册表持有），每次 Dial 的 ctx 只约束建立阶段。
	ctx    context.Context
	cancel context.CancelFunc

	seq   atomic.Uint64
	conns atomic.Int64

	// ckMu/ck 保存载荷下发的会话 cookie（整条隧道共用；载荷在 CONNECT 上会剥掉 Set-Cookie，
	// 所以会话只能由 hello 建立、之后一直复用）。
	ckMu sync.Mutex
	ck   string

	// reqMu 让**整条隧道**同一时刻只有一个短请求在飞。粒度必须是隧道而不是连接：载荷在
	// CONNECT 分支里剥掉 Set-Cookie，于是整条隧道共用一个 PHP 会话（见 Dial），PHP 的
	// session 文件锁会让所有连接的 READ/FORWARD 互相排队——实测表现为双路各约一半超时。
	// 注意：异步 CONNECT（长轮询，PHP）**不**走这把锁，否则它会一直占着直到连接关闭。
	reqMu sync.Mutex

	mu     sync.Mutex
	closed bool
}

// NewRegeorg 建立一条隧道：解析参数、做一次探活确认载荷在位，失败不留半开状态。
func NewRegeorg(parent context.Context, cfg RegeorgConfig) (*Regeorg, error) {
	if parent == nil {
		parent = context.Background()
	}
	urls := make([]string, 0, len(cfg.ServerURLs))
	for _, raw := range cfg.ServerURLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("regeorg: 载荷 URL 无效（只支持 http/https）：%q", raw)
		}
		urls = append(urls, raw)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("regeorg: 至少需要一个载荷 URL")
	}
	cfg = withDefaults(cfg)
	tr := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	if up := strings.TrimSpace(cfg.Upstream); up != "" {
		u, err := parseUpstream(up)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "socks5" || u.Scheme == "socks5h" || u.Scheme == "http" || u.Scheme == "https" {
			tr.Proxy = http.ProxyURL(u)
		} else {
			return nil, fmt.Errorf("regeorg: 控制通道上游只支持 http/https/socks5，得到 %q", u.Scheme)
		}
	}

	// cookie jar 不是可选项：PHP 载荷靠 $_SESSION 在多个请求之间交接状态（CONNECT 写下
	// $run，READ/FORWARD 再读它）。客户端不带会话 cookie 的话，每个请求都是新会话，READ
	// 只会一直回 "TCP session is closed"——上游 Python 用 requests.Session() 就是这个原因。
	// 这里**故意不挂 cookie jar**：会话 cookie 由我们自己收、自己发（见 send / rememberCookies）。
	// 原因是实测出来的——Go 的 cookiejar 会静默丢弃它认为不合规的 cookie，于是 hello 下发的
	// PHPSESSID 没被保存，CONNECT 与 READ 落到**不同的 PHP 会话**里，载荷一律回
	// "TCP session is closed"（真实靶站上就是这样，而手工 curl 带 jar 反而正常）。
	ctx, cancel := context.WithCancel(parent)
	r := &Regeorg{
		cfg:    cfg,
		urls:   urls,
		client: &http.Client{Transport: &controlTransport{base: tr, log: cfg.ControlLog}},
		desc:   safeURL(mustURL(urls[0])),
		ctx:    ctx,
		cancel: cancel,
	}
	// 探活：载荷对"看不懂的请求"会吐一个约定好的串，拿不到就说明载荷不在位或参数不符，
	// 此时宁可建不起来，也不要留一条永远连不通的隧道。
	if err := r.hello(); err != nil {
		cancel()
		tr.CloseIdleConnections()
		return nil, err
	}
	return r, nil
}

// withDefaults 填上所有"未显式设置"的旋钮。
//
// 单独抽出来不只是为了整洁：这些取值都是实测调出来的（尤其是数据路径的 10s×3），
// 集中在一处才可能被单测钉住，避免以后被无意改回去——那种改动编译照过、别的测试照绿，
// 只在真机上表现为"偶发卡 30 秒"。
func withDefaults(cfg RegeorgConfig) RegeorgConfig {
	if cfg.ReadBuffKB <= 0 {
		cfg.ReadBuffKB = 7
	}
	if cfg.ReadBuffKB > 50 {
		cfg.ReadBuffKB = 50
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30
	}
	if cfg.MaxRetry <= 0 {
		cfg.MaxRetry = 10
	}
	if cfg.ReadIntervalMS <= 0 {
		// 空转间隔。串行化之后所有连接共用这一个请求槽，间隔越大整页越慢，所以默认收紧到 100ms。
		cfg.ReadIntervalMS = 100
	}
	if cfg.WriteIntervalMS <= 0 {
		cfg.WriteIntervalMS = 200
	}
	if cfg.DataTimeoutMS <= 0 {
		// 10s × 3 次重试：轮询协议的单次往返本是几十毫秒级，但控制通道常常要穿过一个上游代理
		// （平台的 global_proxy），而实测那类代理会偶发卡顿几十秒。对照实验（清空 global_proxy
		// 后双路 10/10）证明抖动来自上游而不是隧道本身，所以这里的选择是**耐心撑过去**，
		// 而不是快速失败——一次 hiccup 不该让整条隧道连接作废。
		cfg.DataTimeoutMS = 10000
	}
	if cfg.DataRetries <= 0 {
		cfg.DataRetries = 3
	}
	if cfg.AsyncWaitMS <= 0 {
		cfg.AsyncWaitMS = 6000
	}
	if cfg.AsyncPollMS <= 0 {
		cfg.AsyncPollMS = 120
	}
	return cfg
}

// Describe 返回脱敏后的出口描述。
func (r *Regeorg) Describe() string { return "regeorg:" + r.desc }

// Close 关掉隧道：取消生命周期、断开空闲连接。
func (r *Regeorg) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	if tr, ok := r.client.Transport.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
	return nil
}

// Hello 相关的探活实现。
func (r *Regeorg) hello() error { return r.helloCtx(r.ctx) }

func (r *Regeorg) helloCtx(ctx context.Context) error {
	if ctx == nil {
		ctx = r.ctx
	}
	body, err := r.send(r.client, ctx, "", time.Duration(r.cfg.Timeout)*time.Second, r.cfg.MaxRetry)
	if err != nil {
		return fmt.Errorf("regeorg: 探活请求失败（载荷不可达？）: %w", err)
	}
	want := regeorg.HelloBytes()
	if len(want) == 0 {
		// fail-closed：期望值为空时 bytes.Contains 恒为真，校验会形同虚设。
		return fmt.Errorf("regeorg: 探活串解不出内容（协议参数与载荷不一致）")
	}
	if !bytes.Contains(body, want) {
		return fmt.Errorf("regeorg: 载荷未按约定应答（会不会是参数不匹配、或载荷已被删？）: %q", truncate(body, 60))
	}
	return nil
}

// Dial 打开一条经隧道的连接。ctx 只约束"建立"这一步，之后连接的存活交给隧道本身。
func (r *Regeorg) Dial(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("regeorg: 目标地址必须是 host:port，得到 %q: %w", addr, err)
	}
	if r.cfg.LocalDNS {
		// 客户端解析：把域名换成 IP 再交给载荷（默认不这么做，内网域名只有那边能解）。
		if ip, err := net.DefaultResolver.LookupHost(ctx, host); err == nil && len(ip) > 0 {
			host = ip[0]
		}
	}
	mark := randomMark()
	local, peer := net.Pipe()
	// 整条隧道**共用一个 cookie jar**（也就是共用一个 PHP 会话）——这不是疏忽，是载荷的要求：
	// 它的 CONNECT 分支里有 @header_remove('set-cookie')，故意不下发 cookie，所以"每连接一个
	// 会话"的客户端拿不到该会话的 cookie，后续 READ/FORWARD 会落到全新的空会话上，全部
	// "TCP session is closed"（实测 0/8）。会话必须由 hello 先建立，之后一直复用。
	client := r.client

	connect := map[byte][]byte{
		regeorg.FieldCmd:  []byte(regeorg.CmdConnect),
		regeorg.FieldMark: []byte(mark),
		regeorg.FieldIP:   []byte(host),
		regeorg.FieldPort: []byte(port),
	}
	// PHP（或显式要求）：CONNECT 就是泵本身，发出去不等响应；其余载荷会立刻返回 STATUS。
	if r.asyncConnect() {
		// 关键：这个请求是**长轮询**，它要在整条连接的生命周期里一直挂着（泵就跑在它里面）。
		//
		//   * 所以绑的是**隧道自己的 ctx**（r.ctx），不是调用方传进来的 ctx：调用方的 ctx 往往
		//     只覆盖"那一次拨号/那一个 HTTP 请求"，Dial 一返回就被 cancel，于是客户端撒手；
		//   * 也不要给它短超时。曾经这里写死 500ms，实测的后果是：
		//       Apache + mod_php   客户端断开后 PHP 照跑，泵还活着 → 一直好用；
		//       nginx + php-fpm    客户端一断，nginx 关掉上游连接 → php-fpm 杀掉 worker →
		//                          泵死 → 后续 READ 全部 "TCP session is closed"。
		//     也就是说这是"PHP 载荷在 nginx 上不可用"的根因。
		go func() {
			// 超时给一个实际等于「不超时」的值：真正的边界是 r.ctx（隧道关闭即取消）。
			_, _ = r.post(client, r.ctx, connect, 24*time.Hour, 1)
		}()
		// 异步 CONNECT 拿不到 STATUS，所以"究竟连上了没有"必须由后续的 READ 回答：载荷是先
		// fsockopen、成功了才把会话标成 running，于是 READ 回 OK 就是连上了、回 FAIL
		// （"TCP session is closed"）就是目标没连上。不确认的话，上层门禁探活就是假的——
		// 目标根本不可达也会被当成"隧道可用"。
		var lastErr string
		deadline := time.Now().Add(time.Duration(r.cfg.AsyncWaitMS) * time.Millisecond)
		for {
			if time.Now().After(deadline) {
				_ = local.Close()
				_ = peer.Close()
				if lastErr == "" {
					lastErr = "等待会话建立超时"
				}
				return nil, fmt.Errorf("regeorg: CONNECT %s 未确认: %s", addr, lastErr)
			}
			if ctx != nil && ctx.Err() != nil {
				_ = local.Close()
				_ = peer.Close()
				return nil, ctx.Err()
			}
			time.Sleep(time.Duration(r.cfg.AsyncPollMS) * time.Millisecond)
			info, err := r.post(client, nil, map[byte][]byte{
				regeorg.FieldCmd:  []byte(regeorg.CmdRead),
				regeorg.FieldMark: []byte(mark),
			}, time.Duration(r.cfg.DataTimeoutMS)*time.Millisecond, r.cfg.DataRetries)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			if string(info[regeorg.FieldStatus]) == regeorg.StatusOK {
				break
			}
			lastErr = string(info[regeorg.FieldError])
		}
	} else {
		info, err := r.post(client, ctx, connect, time.Duration(r.cfg.Timeout)*time.Second, r.cfg.MaxRetry)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			return nil, fmt.Errorf("regeorg: CONNECT %s 失败: %w", addr, err)
		}
		if string(info[regeorg.FieldStatus]) != regeorg.StatusOK {
			_ = local.Close()
			_ = peer.Close()
			return nil, fmt.Errorf("regeorg: CONNECT %s 被拒绝: %s", addr, string(info[regeorg.FieldError]))
		}
	}

	c := &regeorgConn{
		tunnel: r,
		client: client,
		mark:   mark,
		target: addr,
	}
	r.conns.Add(1)
	go c.reader(peer)
	go c.writer(peer)

	go func() {
		<-r.ctx.Done()
		_ = local.Close()
	}()
	// 包一层：Close 时先做确定性收尾（DISCONNECT），而不是等 reader/writer 自己发现管道没了。
	return &regeorgClientConn{
		netConn: &netConn{
			ReadWriteCloser: local,
			local:           stringAddr("regeorg:" + r.desc),
			remote:          stringAddr(addr),
		},
		conn: c,
		peer: peer,
	}, nil
}

// asyncConnect 判断是否要用"发完不等"的 CONNECT。默认按载荷是不是 PHP 判断。
func (r *Regeorg) asyncConnect() bool {
	if r.cfg.AsyncConnect != nil {
		return *r.cfg.AsyncConnect
	}
	return strings.Contains(strings.ToLower(r.urls[0]), ".php")
}

// send 发一次 HTTP 请求并返回**原始正文**，带重试。
//
// 重试只针对传输错误与格式错误：载荷明确回 FAIL（比如"TCP session is closed"）是**结论**，
// 重试 10 次只会白等——上游也是这么做的。
func (r *Regeorg) send(client *http.Client, ctx context.Context, payload string, timeout time.Duration, retries int) ([]byte, error) {
	if timeout <= 0 {
		timeout = time.Duration(r.cfg.Timeout) * time.Second
	}
	if retries <= 0 {
		retries = r.cfg.MaxRetry
	}
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		if err := r.ctx.Err(); err != nil {
			return nil, err
		}
		// 建立阶段可以被调用方放弃；运行中的循环由隧道自己的 ctx 约束。
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		reqCtx, cancel := context.WithTimeout(r.ctx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.pickURL(), strings.NewReader(payload))
		if err != nil {
			cancel()
			return nil, err
		}
		// 必须是表单类型，不能是 application/octet-stream。原因（真机定位）：
		// PHP 5.6 在 always_populate_raw_post_data 打开时，只要请求体的类型不是表单类型，就会先
		// 输出一段 "Deprecated: Automatically populating $HTTP_RAW_POST_DATA" 的 HTML 警告；
		// 一旦有输出，响应头就已经发出去了，于是载荷的 @session_start() **再也发不出 Set-Cookie**。
		// 结果是客户端拿不到会话 id、CONNECT 与 READ 落在不同的 PHP 会话里，一切都在回
		// "TCP session is closed"（nginx + PHP 5.6 上实测如此；Apache 那台因为该选项是关的，所以
		// 一直没暴露）。表单类型不触发这段警告，而 php://input 对表单类型依然可读，载荷照常工作。
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		for _, h := range r.cfg.ExtraHeader {
			if k, v, ok := strings.Cut(h, ":"); ok {
				req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
		if ck := r.sessionCookie(); ck != "" {
			req.Header.Set("Cookie", ck)
		}
		if r.cfg.Debug {
			log.Printf("[regeorg] → %s body=%d ct=%q cookie=%q", req.URL.String(), len(payload),
				req.Header.Get("Content-Type"), req.Header.Get("Cookie"))
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		r.rememberCookies(resp.Cookies())
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("重试 %d 次仍未成功", retries)
	}
	return nil, lastErr
}

// post 发一次协议请求：编码 → POST → 解码。ctx 只用于建立阶段，运行中的循环传 nil。
func (r *Regeorg) post(client *http.Client, ctx context.Context, fields map[byte][]byte, timeout time.Duration, retries int) (map[byte][]byte, error) {
	if fields == nil {
		fields = map[byte][]byte{}
	}
	body, err := r.send(client, ctx, regeorg.EncodeBody(fields), timeout, retries)
	if err != nil {
		return nil, err
	}
	if r.cfg.Debug {
		log.Printf("[regeorg] %s → %d 字节: %s", cmdName(fields), len(body), snippet(body))
	}
	info, err := regeorg.DecodeBody(string(body))
	if err != nil {
		// 把原始应答的开头带上：协议不符时，这是唯一能看见"对方到底回了什么"的地方
		// （例如载荷其实回了自己的 hello 串、或 nginx/PHP 插了一页错误输出）。
		return nil, fmt.Errorf("%w（应答 %d 字节，开头: %s）", err, len(body), snippet(body))
	}
	return info, nil
}

// pickURL 在多个载荷 URL 之间轮转（上游用它把请求摊到多个路径上）。
func (r *Regeorg) pickURL() string {
	n := int(r.seq.Add(1) - 1)
	return r.urls[n%len(r.urls)]
}

// regeorgConn 是一条隧道内连接的收发状态。
type regeorgConn struct {
	tunnel *Regeorg
	client *http.Client
	mark   string
	// mu 让同一连接内同一时刻只有一个协议请求在飞：载荷把状态放在 $_SESSION 里，PHP 的
	// session 文件锁会让并发请求互相排队（实测表现为偶发卡到超时）。读写交替不影响可用性
	// ——隧道本来就是"推一段/拉一段"。
	mu     sync.Mutex
	target string
	closed atomic.Bool
	once   sync.Once
}

// reader 把目标侧的数据取回来（READ 轮询）。
func (c *regeorgConn) reader(peer net.Conn) {
	defer c.finish(peer)
	interval := time.Duration(c.tunnel.cfg.ReadIntervalMS) * time.Millisecond
	for {
		if c.closed.Load() || c.tunnel.ctx.Err() != nil {
			return
		}
		c.tunnel.reqMu.Lock()
		info, err := c.tunnel.post(c.client, nil, map[byte][]byte{
			regeorg.FieldCmd:  []byte(regeorg.CmdRead),
			regeorg.FieldMark: []byte(c.mark),
		}, time.Duration(c.tunnel.cfg.DataTimeoutMS)*time.Millisecond, c.tunnel.cfg.DataRetries)
		c.tunnel.reqMu.Unlock()
		if err != nil {
			return
		}
		if string(info[regeorg.FieldStatus]) != regeorg.StatusOK {
			return
		}
		data := info[regeorg.FieldData]
		if len(data) == 0 {
			// 只有**真空转**才歇：之前还写了"小于 500 字节就歇"，那等于在数据正在流动时节流
			// 自己——取一个 35KB 的整页会被切成很多小段，每段都罚 300ms，实测直接超时。
			time.Sleep(interval)
			continue
		}
		if _, err := peer.Write(data); err != nil {
			return
		}
	}
}

// writer 把客户端的数据推过去（FORWARD）。
func (c *regeorgConn) writer(peer net.Conn) {
	defer c.finish(peer)
	bufSize := c.tunnel.cfg.ReadBuffKB * 1024
	idle := time.Duration(c.tunnel.cfg.WriteIntervalMS) * time.Millisecond
	buf := make([]byte, bufSize)
	for {
		if c.closed.Load() || c.tunnel.ctx.Err() != nil {
			return
		}
		n, err := peer.Read(buf)
		if n > 0 {
			c.tunnel.reqMu.Lock()
			info, perr := c.tunnel.post(c.client, nil, map[byte][]byte{
				regeorg.FieldCmd:  []byte(regeorg.CmdForward),
				regeorg.FieldMark: []byte(c.mark),
				regeorg.FieldData: append([]byte(nil), buf[:n]...),
			}, time.Duration(c.tunnel.cfg.DataTimeoutMS)*time.Millisecond, c.tunnel.cfg.DataRetries)
			c.tunnel.reqMu.Unlock()
			if perr != nil || string(info[regeorg.FieldStatus]) != regeorg.StatusOK {
				return
			}
		}
		if err != nil {
			return
		}
		if n < bufSize {
			time.Sleep(idle)
		}
	}
}

// finish 收尾：关掉本地对端并告诉载荷断开（尽力而为）。
func (c *regeorgConn) finish(peer net.Conn) {
	c.once.Do(func() {
		c.closed.Store(true)
		// **先同步告诉载荷断开，再关本地管道**。反过来的话，载荷那边的 CONNECT 泵可能继续
		// 占着 worker 直到它自己发现管道没了——健康巡检每次都会留下一个这样的泵，攒几个就把
		// worker 占满，后续请求开始排队（实测"越跑越越容易卡"就是这么来的）。
		c.tunnel.reqMu.Lock()
		_, _ = c.tunnel.post(c.client, nil, map[byte][]byte{
			regeorg.FieldCmd:  []byte(regeorg.CmdDisconnect),
			regeorg.FieldMark: []byte(c.mark),
		}, time.Duration(c.tunnel.cfg.DataTimeoutMS)*time.Millisecond, 1)
		c.tunnel.reqMu.Unlock()
		c.tunnel.conns.Add(-1)
		_ = peer.Close()
	})
}

// regeorgClientConn 在 netConn 之上把 Close 变成确定性收尾（见 finish）。
type regeorgClientConn struct {
	*netConn
	conn *regeorgConn
	peer net.Conn
}

func (x *regeorgClientConn) Close() error {
	x.conn.finish(x.peer) // 幂等
	return x.netConn.Close()
}

// Ping 只问"载荷还在按约定应答吗"：便宜，不占载荷的会话与 worker。端到端能不能通由 Dial 回答。
// 平台的分层健康巡检用它做每轮的轻量检查。
func (r *Regeorg) Ping(ctx context.Context) error { return r.helloCtx(ctx) }

// sessionCookie 返回要带给载荷的 Cookie 头（空表示还没有会话）。
func (r *Regeorg) sessionCookie() string {
	r.ckMu.Lock()
	defer r.ckMu.Unlock()
	return r.ck
}

// rememberCookies 记下会话 cookie。整条隧道共用一个（载荷把状态放在 $_SESSION 里，靠它认领），
// 所以后到的覆盖先到的——正常情况下只有 hello 会下发新的 PHPSESSID。
func (r *Regeorg) rememberCookies(cs []*http.Cookie) {
	if len(cs) == 0 {
		return
	}
	r.ckMu.Lock()
	defer r.ckMu.Unlock()
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		if c == nil || c.Name == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	if len(parts) > 0 {
		r.ck = strings.Join(parts, "; ")
	}
}

// snippet 把应答开头做成可读文本，塞进错误里——协议不符时这是唯一能看见"对方到底回了什么"的地方。
func snippet(b []byte) string {
	const max = 120
	s := fmt.Sprintf("%q", b)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// cmdName 让 debug 日志里能看出是哪个命令。
func cmdName(fields map[byte][]byte) string {
	if c, ok := fields[regeorg.FieldCmd]; ok {
		return string(c)
	}
	return "hello"
}

// randomMark 造一个会话标记（上游用 uuid4 的 base64 去掉尾部）。
func randomMark() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("m%d", time.Now().UnixNano())
	}
	return strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=")
}

func mustURL(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
