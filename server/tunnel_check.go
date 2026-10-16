package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/tunnel"
)

// defaultProbeSite 是"测试连通性"默认访问的网站。
//
// 为什么是访问网站而不是 TCP 探活：TCP 连得上只说明**代理愿意转发**，不等于它真能上网
// （代理可能只放行部分目标，或被上游策略挡掉）。而"经这条代理取回一个网页"才是这个出口
// 有没有用的直接证据。
const defaultProbeSite = "http://www.baidu.com/"

// checkTaskTunnel 现场重探某个任务已绑的隧道（界面上的「测连通性」）。
//
// 健康状态本来就由后台周期性探活维护，但"我怀疑它现在不通"时需要立刻要一个答案 ——
// 这个端点就是干这个：不改绑定，只把最新结论写回健康状态并回给调用方。
//
// POST /api/tasks/{id}/tunnel/check
func (s *Server) checkTaskTunnel(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "task id 必须是数字")
		return
	}
	ok, reason, count := s.m.RecheckTaskTunnels(n)
	writeJSON(w, http.StatusOK, map[string]any{
		"healthy": ok,
		"reason":  reason,
		"tunnels": count,
	})
}

// probeTunnelAddress 只测连通性、**不绑定**：给「建立隧道」表单和「新建任务」表单里的
// 「测试连通性」用 —— 先确认这条代理真能访问网站，再决定要不要绑/建。
//
// 做法是**经这条代理发一次真实 HTTP GET**（而不是只 dial 一个 host:port）：只有把网页
// 取回来，才说明这个出口真能用来干活。
//
// POST /api/tunnels/probe {"url":"socks5://user:pass@host:port","test_url":"http://www.baidu.com/"}
func (s *Server) probeTunnelAddress(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelRequestBytes)
	var req struct {
		URL string `json:"url"`
		// TestURL 是想访问的网站；留空用 defaultProbeSite。
		TestURL string `json:"test_url"`
		// Probe 是旧的 host:port 探活目标：现在只当作"用户想测的站点"的兜底来源
		// （写了 http:// 前缀就用它），不再单独做 TCP 探活。
		Probe string `json:"probe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	raw := strings.TrimSpace(req.URL)
	if raw == "" {
		writeErr(w, http.StatusBadRequest, "代理地址不能为空")
		return
	}
	site := siteForProbe(req.TestURL, req.Probe)

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	// 这里刻意只走"已有隧道/代理"这一路：建隧道/建任务时最需要先验的就是它。
	d, err := tunnel.NewProxyDialer(ctx, raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer d.Close()

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			// 关键：所有连接都从这条代理出去。没有别的出口可退，所以不存在"其实测的是直连"
			// 这种假阳性 —— 这正是这个按钮存在的意义。
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return d.Dial(ctx, addr)
			},
			DisableKeepAlives: true,
		},
	}
	start := time.Now()
	resp, err := client.Get(site)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "site": site, "latency_ms": latency,
			"reason": "经这条代理访问网站失败：" + err.Error(),
		})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "site": site, "status": resp.StatusCode, "latency_ms": latency,
			"reason": "代理要求认证（407）：地址里的用户名或密码不对",
		})
		return
	}
	// 拿到任何 HTTP 响应都算"这条代理能上网"：403/404 说明请求确实到了对端。
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "site": site, "status": resp.StatusCode,
		"bytes": len(body), "latency_ms": latency,
	})
}

// siteForProbe 决定"测试连通性"访问哪个网站：优先用显式填的 test_url；如果用户在探活目标
// 里直接写了 URL（带 http:// 前缀），就用它 —— 那样比只给 host:port 有用得多。
func siteForProbe(testURL, probe string) string {
	for _, raw := range []string{testURL, probe} {
		s := strings.TrimSpace(raw)
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			return s
		}
	}
	return defaultProbeSite
}

// replaceTaskTunnel 给某个任务**换一条隧道**（界面上的「更换」）：旧的那条先关掉，再按新的
// 类型/地址建一条。
//
// 顺序是刻意的（一个任务只允许一条出口，见 maxTunnelsPerTask）：先建新的会被上限挡住，所以
// 只能"先关旧、再建新"。代价是**新建失败时该任务会退回 global_proxy** —— 所以这里把结果说
// 清楚，绝不静默。
//
// POST /api/tasks/{id}/tunnel/replace {"kind":"regeorg|proxy","url":"...","probe":"","upstream":""}
func (s *Server) replaceTaskTunnel(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "task id 必须是数字")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelRequestBytes)
	var req struct {
		Kind     string `json:"kind"`
		URL      string `json:"url"`
		Probe    string `json:"probe"`
		Upstream string `json:"upstream"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeErr(w, http.StatusBadRequest, "新隧道地址不能为空")
		return
	}
	// 先关旧的（隧道活在进程里，关掉就没了）。记下原来有几条，好在回执里说清替换了什么。
	had := 0
	for _, t := range s.m.Tunnels(n) {
		if t.TaskID == n {
			had++
		}
	}
	s.m.ReclaimTaskTunnels(n)
	tun, err := s.m.OpenTunnel(r.Context(), TunnelRequest{
		TaskID:    n,
		Backend:   normalizeEgressKind(req.Kind),
		ServerURL: strings.TrimSpace(req.URL),
		Probe:     strings.TrimSpace(req.Probe),
		Upstream:  req.Upstream,
	})
	if err != nil {
		// 关键的一句：旧隧道已经关了，新隧道没建起来 —— 必须让操作者知道现在走的是全局代理。
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("旧隧道已关闭（%d 条），新隧道未能建立：%v —— 该任务现在退回 global_proxy，请重新绑定", had, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"replaced": had, "id": tun.ID, "task_id": n, "egress": tun.Describe,
		"server_url": tun.ServerURL, "probe": tun.Probe, "healthy": true,
	})
}
