package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyDialer 把"一条已经存在的隧道/代理端点"当成任务的出口。
//
// 与 Regeorg 的差别只有一个，但很关键：**没有控制通道**。平台不去投放/驱动任何载荷，而是
// 直拨用户给的这个代理（自己的 ssh -D / chisel / frp / suo5 客户端都算），目标流量就是纯
// 粹地经它出去 —— 因此**不会经过 global_proxy**。其余一切与隧道同等待遇：探活门禁、健康
// 状态、任务结束回收、流量里的出口标签。
//
// 支持 socks5/socks5h（含用户名密码）与 http/https（CONNECT 隧道）。
type ProxyDialer struct {
	// 已脱敏的原始地址（日志/账本/API 用）；连接时用 raw 那份。
	desc     string
	scheme   string
	hostPort string
	user     string
	pass     string
	hasAuth  bool

	timeout time.Duration

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	opened atomic.Int64
}

// NewProxyDialer 校验并构造一个直拨代理的出口。只接受 socks5/socks5h/http/https。
func NewProxyDialer(_ context.Context, raw string) (*ProxyDialer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("代理地址不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("代理地址无效：%q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "http", "https":
	default:
		return nil, fmt.Errorf("不支持的代理类型 %q（支持 socks5/socks5h/http/https）", u.Scheme)
	}
	d := &ProxyDialer{
		desc:     redactProxyURL(u),
		scheme:   strings.ToLower(u.Scheme),
		hostPort: u.Host,
		timeout:  20 * time.Second,
		conns:    map[net.Conn]struct{}{},
	}
	if u.User != nil {
		d.user = u.User.Username()
		d.pass, _ = u.User.Password()
		// 只给用户名也算凭据：有些代理用空密码。
		d.hasAuth = true
	}
	return d, nil
}

// Describe 是出口标签，进流量库与 API，所以凭据一律去掉。
func (d *ProxyDialer) Describe() string { return d.desc }

// Dial 直拨代理再连目标：**不经过 global_proxy**，这正是"我自己有隧道"的语义。
func (d *ProxyDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if addr == "" {
		return nil, errors.New("目标地址为空")
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, errors.New("代理出口已关闭")
	}
	d.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	var nd net.Dialer
	conn, err := nd.DialContext(dialCtx, "tcp", d.hostPort)
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s 失败：%w", d.hostPort, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
	}
	var wrapped net.Conn = conn
	switch d.scheme {
	case "socks5", "socks5h":
		if err := d.socks5Handshake(conn, addr); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case "http", "https":
		wrapped, err = d.httpConnect(conn, addr)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	d.opened.Add(1)
	return d.track(wrapped), nil
}

// Close 断开这条出口上的所有连接（任务结束/回收时用）。
func (d *ProxyDialer) Close() error {
	d.mu.Lock()
	d.closed = true
	conns := make([]net.Conn, 0, len(d.conns))
	for c := range d.conns {
		conns = append(conns, c)
	}
	d.conns = map[net.Conn]struct{}{}
	d.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

// track 把连接登记进表（Close 时统一断开）。注意是**包一层 conn**，而不是起个 goroutine
// 去读它 —— 读连接会把数据从上层手里偷走，那种"探测关闭"的写法在这里是致命的。
func (d *ProxyDialer) track(c net.Conn) net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		_ = c.Close()
		return c
	}
	tc := &trackedProxyConn{Conn: c, owner: d}
	d.conns[tc] = struct{}{}
	return tc
}

func (d *ProxyDialer) untrack(c net.Conn) {
	d.mu.Lock()
	delete(d.conns, c)
	d.mu.Unlock()
}

// trackedProxyConn 只是让上层 Close 时能把自己从出口的表里摘掉。
type trackedProxyConn struct {
	net.Conn
	owner *ProxyDialer
	once  sync.Once
}

func (c *trackedProxyConn) Close() error {
	c.once.Do(func() { c.owner.untrack(c) })
	return c.Conn.Close()
}

// socks5Handshake 走一遍 SOCKS5（RFC1928/1929）：方法协商 → 可选用户密码 → CONNECT。
// 目标以**域名**形式交给代理（socks5h 语义）：内网域名只有目标侧能解析，这点和平台其它
// 出口一致。
func (d *ProxyDialer) socks5Handshake(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("目标地址必须是 host:port，得到 %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("目标端口无效：%q", portStr)
	}
	greeting := []byte{0x05, 0x01, 0x00}
	if d.hasAuth {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("SOCKS5 握手失败：%w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("SOCKS5 读取方法协商失败：%w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("代理不是 SOCKS5（版本字节 %d）", reply[0])
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		if !d.hasAuth {
			return errors.New("代理要求用户名密码，但地址里没有")
		}
		req := []byte{0x01, byte(len(d.user))}
		req = append(req, d.user...)
		req = append(req, byte(len(d.pass)))
		req = append(req, d.pass...)
		if _, err := conn.Write(req); err != nil {
			return fmt.Errorf("SOCKS5 发送凭据失败：%w", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			return fmt.Errorf("SOCKS5 读取认证结果失败：%w", err)
		}
		if authReply[1] != 0x00 {
			return errors.New("代理认证失败（用户名或密码不对）")
		}
	case 0xFF:
		return errors.New("代理不接受我们的认证方式")
	default:
		return fmt.Errorf("代理选择了不支持的认证方式 %d", reply[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("SOCKS5 发送 CONNECT 失败：%w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("SOCKS5 读取 CONNECT 响应失败：%w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("代理拒绝连接 %s：%s", addr, socks5Error(head[1]))
	}
	// 吃掉绑定地址：类型 + 地址 + 端口。
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("SOCKS5 读取绑定地址失败：%w", err)
		}
		skip = int(l[0]) + 2
	default:
		return fmt.Errorf("SOCKS5 响应里的地址类型无法识别：%d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
		return fmt.Errorf("SOCKS5 读取绑定地址失败：%w", err)
	}
	return nil
}

func socks5Error(code byte) string {
	switch code {
	case 0x01:
		return "代理内部错误"
	case 0x02:
		return "规则不允许"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "目标不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 超时"
	case 0x07:
		return "命令不支持"
	case 0x08:
		return "地址类型不支持"
	}
	return "未知原因(" + strconv.Itoa(int(code)) + ")"
}

// httpConnect 用 HTTP CONNECT 建隧道。返回的 conn 会先把 bufio 里可能多读到的字节吐出来，
// 否则那几十个字节（对端可能已经开说话了）会被丢掉 —— 这是 CONNECT 实现最经典的坑。
func (d *ProxyDialer) httpConnect(conn net.Conn, addr string) (net.Conn, error) {
	var head strings.Builder
	fmt.Fprintf(&head, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if d.hasAuth {
		token := base64.StdEncoding.EncodeToString([]byte(d.user + ":" + d.pass))
		fmt.Fprintf(&head, "Proxy-Authorization: Basic %s\r\n", token)
	}
	head.WriteString("\r\n")
	if _, err := conn.Write([]byte(head.String())); err != nil {
		return nil, fmt.Errorf("发送 CONNECT 失败：%w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := httpReadResponse(br)
	if err != nil {
		return nil, fmt.Errorf("读取 CONNECT 响应失败：%w", err)
	}
	if resp.status != 200 {
		return nil, fmt.Errorf("代理拒绝 CONNECT %s：%d %s", addr, resp.status, resp.reason)
	}
	return &prefixConn{Conn: conn, r: br}, nil
}

type proxyResponse struct {
	status int
	reason string
}

func httpReadResponse(br *bufio.Reader) (proxyResponse, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return proxyResponse{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return proxyResponse{}, fmt.Errorf("不是 HTTP 响应：%q", strings.TrimSpace(line))
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return proxyResponse{}, fmt.Errorf("状态码无法解析：%q", parts[1])
	}
	reason := ""
	if len(parts) == 3 {
		reason = parts[2]
	}
	// 读到空行为止。
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return proxyResponse{}, err
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	return proxyResponse{status: code, reason: reason}, nil
}

// prefixConn 让"bufio 已经多读的字节"重新排在真正 conn 之前。
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// redactProxyURL 去掉 userinfo：这个标签会进日志、账本、流量库与 API。
func redactProxyURL(u *url.URL) string {
	clone := *u
	clone.User = nil
	return clone.String()
}
