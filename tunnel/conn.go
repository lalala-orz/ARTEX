package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// Dialer 是一条隧道出口：按地址拨号、自我描述（进日志与账本）、可关闭。
//
// 它刻意与 traffic.Dialer 保持结构一致（Dial + Describe），所以任何实现都能直接绑给记录
// 监听器当上游——平台侧因此完全不需要知道后端是哪种隧道。
type Dialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Describe() string
	Close() error
}

// 本文件放隧道实现共用的连接包装与上游解析。
//
// 这些原本和 suo5 适配器放在一起；suo5 已从平台移除（它的 PHP 载荷在多连接上不可靠），
// 但 regeorg 客户端仍然需要它们，所以单独留了下来。

// parseUpstream 解析上游代理地址（平台里的 global_proxy）。只校验形状：具体怎么走交给
// net/http 的 Transport.Proxy，它支持 http/https/socks5。
func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("隧道上游代理地址无效 %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("隧道上游代理只支持 http/https/socks5，得到 %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("隧道上游代理缺少主机 %q", raw)
	}
	return u, nil
}

// safeURL 去掉 userinfo，避免口令进日志与账本。
func safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	return c.String()
}

// netConn 把隧道的 ReadWriteCloser 补成 net.Conn。
//
// **deadline 故意是 no-op**。隧道没有内核 deadline，而它的数据是靠"轮询对方"搬运的：一次
// 读可能要等一个轮询周期（默认 300ms）才有字节。早期实现把 deadline 做成"到点即关"，于是
// 上层的 net/http Transport 一设 deadline（MITM 那条路径就会设），这条隧道连接就被直接
// 关掉——实测表现为：SOCKS5 裸 TCP 路径正常，而经 MITM 的 HTTP 路径挂到超时。
//
// 超时该由隧道自己兜底：每个协议请求都有自己的超时，隧道关闭/生命周期结束会取消 ctx，
// 两者都会让阻塞中的读写返回错误。这里再叠一层"到点关连接"只会把正常的长轮询误杀。
type netConn struct {
	io.ReadWriteCloser
	local, remote net.Addr
}

func (c *netConn) LocalAddr() net.Addr  { return c.local }
func (c *netConn) RemoteAddr() net.Addr { return c.remote }

func (c *netConn) SetDeadline(time.Time) error      { return nil }
func (c *netConn) SetReadDeadline(time.Time) error  { return nil }
func (c *netConn) SetWriteDeadline(time.Time) error { return nil }

func (c *netConn) Close() error { return c.ReadWriteCloser.Close() }

// stringAddr 让 net.Conn 的地址有可读表示（隧道连接没有真实地址）。
type stringAddr string

func (a stringAddr) Network() string { return "tunnel" }
func (a stringAddr) String() string  { return string(a) }
