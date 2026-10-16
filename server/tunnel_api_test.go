package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/payloads"
	"github.com/Autumn-27/artex/regeorg"
	"github.com/Autumn-27/artex/tunnel"
)

// tunnelAPITestMux wires just the tunnel/payload routes, so the handlers are
// exercised through a real router (including {id} path parsing) without needing the
// full server or PostgreSQL.
func tunnelAPITestMux(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tunnels", s.listTunnels)
	mux.HandleFunc("POST /api/tasks/{id}/tunnel", s.createTaskTunnel)
	mux.HandleFunc("DELETE /api/tasks/{id}/tunnel", s.deleteTaskTunnel)
	mux.HandleFunc("GET /api/payloads", s.listPayloads)
	mux.HandleFunc("GET /api/payloads/download", s.downloadPayload)
	return mux
}

func TestTunnelAPIListCreateDelete(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	m.tasks = map[string]*Task{"7": {ID: "7"}}
	s := &Server{m: m}
	mux := tunnelAPITestMux(s)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var reader *strings.Reader
		if body == "" {
			reader = strings.NewReader("")
		} else {
			reader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// 初始为空，并给出文件库路径。
	rec := do("GET", "/api/tunnels", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "\"tunnels\":[]") {
		t.Fatalf("空列表响应不对: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "payload_dir") {
		t.Fatalf("响应缺少 payload_dir: %s", rec.Body)
	}

	// 不存在的任务 → 404。
	if rec := do("POST", "/api/tasks/999/tunnel", `{"url":"http://10.1.1.5/x.php"}`); rec.Code != 404 {
		t.Fatalf("不存在的任务应 404，得到 %d %s", rec.Code, rec.Body)
	}
	// 非数字 id → 400。
	if rec := do("POST", "/api/tasks/abc/tunnel", `{"url":"http://10.1.1.5/x.php"}`); rec.Code != 400 {
		t.Fatalf("非数字任务 id 应 400，得到 %d %s", rec.Code, rec.Body)
	}
	// 缺少 url → 400（由 OpenTunnel 校验后回原样错误）。
	if rec := do("POST", "/api/tasks/7/tunnel", `{}`); rec.Code != 400 {
		t.Fatalf("缺 url 应 400，得到 %d %s", rec.Code, rec.Body)
	}

	// 建隧道：探活通过 → 绑定本任务。
	fake := &fakeTunnel{desc: "suo5:http://10.1.1.5:8080/x.php"}
	var gotReq TunnelRequest
	m.tunnelOpener = func(_ context.Context, req TunnelRequest) (tunnel.Dialer, error) {
		gotReq = req
		return fake, nil
	}
	// backend 必须能从 API 传进来：否则清单里的 backend 字段不可执行（将来加第二个后端时
	// agent 就选不了）。
	rec = do("POST", "/api/tasks/7/tunnel", `{"url":"http://10.1.1.5:8080/x.php","backend":"regeorg","probe":"127.0.0.1:80","upstream":"direct"}`)
	// 注意断言的是**解析后**的值：API 传 "direct" ⇒ OpenTunnel 把它解析成 ""（即这条隧道的控制通道直连，不跟 global_proxy）。
	if gotReq.Backend != "regeorg" || gotReq.Probe != "127.0.0.1:80" || gotReq.Upstream != "" {
		t.Fatalf("API 没有把 backend/probe 传下去: %+v", gotReq)
	}
	if rec.Code != 200 {
		t.Fatalf("建隧道失败: %d %s", rec.Code, rec.Body)
	}
	if got := tr.IdentityEgressLabel("task7"); got != fake.desc {
		t.Fatalf("API 建隧道后 task7 的出口 = %q，想要 %q", got, fake.desc)
	}
	var created struct {
		ID     string `json:"id"`
		Egress string `json:"egress"`
		Probe  string `json:"probe"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("建隧道响应不是 JSON: %v", err)
	}
	// 显式传了 probe，响应里就该回显它（证明探活目标确实按请求走，而不是总用默认值）。
	if created.ID == "" || created.Egress != fake.desc || created.Probe != "127.0.0.1:80" {
		t.Fatalf("建隧道响应内容不对: %+v", created)
	}

	// 列表能看到它，并按任务过滤。
	rec = do("GET", "/api/tunnels?task=7", "")
	if !strings.Contains(rec.Body.String(), fake.desc) || !strings.Contains(rec.Body.String(), `"healthy":true`) {
		t.Fatalf("列表未显示健康隧道: %s", rec.Body)
	}
	if rec := do("GET", "/api/tunnels?task=8", ""); !strings.Contains(rec.Body.String(), "\"tunnels\":[]") {
		t.Fatalf("按别的任务过滤应为空: %s", rec.Body)
	}
	if rec := do("GET", "/api/tunnels?task=abc", ""); rec.Code != 400 {
		t.Fatalf("task 非数字应 400，得到 %d", rec.Code)
	}

	// 第二条隧道被拒（一个任务一条出口），并且原因要说清楚。
	if rec := do("POST", "/api/tasks/7/tunnel", `{"url":"http://10.1.1.6/x.php"}`); rec.Code != 400 ||
		!strings.Contains(rec.Body.String(), "已有") {
		t.Fatalf("第二条隧道应被拒: %d %s", rec.Code, rec.Body)
	}

	// 关闭 → 回到默认出口，隧道真的被关。
	rec = do("DELETE", "/api/tasks/7/tunnel", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"closed":1`) {
		t.Fatalf("关闭响应不对: %d %s", rec.Code, rec.Body)
	}
	if got := tr.IdentityEgressLabel("task7"); got != "" {
		t.Fatalf("关闭后仍绑着出口 %q", got)
	}
	if !fake.isClosed() {
		t.Fatal("关闭后隧道没有真的关闭")
	}
	// 幂等：再关一次仍是 200/closed=0。
	if rec := do("DELETE", "/api/tasks/7/tunnel", ""); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), `"closed":0`) {
		t.Fatalf("重复关闭应幂等: %d %s", rec.Code, rec.Body)
	}
}

// 探活失败时 API 必须拒绝绑定，并让任务留在原出口上。
func TestTunnelAPICreateRefusesWhenProbeFails(t *testing.T) {
	m, tr, _ := newTunnelTestManager(t)
	m.tasks = map[string]*Task{"7": {ID: "7"}}
	s := &Server{m: m}
	mux := tunnelAPITestMux(s)
	m.tunnelOpener = func(_ context.Context, _ TunnelRequest) (tunnel.Dialer, error) {
		return &fakeTunnel{desc: "suo5:http://10.1.1.5/x.php", fail: true}, nil
	}
	req := httptest.NewRequest("POST", "/api/tasks/7/tunnel", strings.NewReader(`{"url":"http://10.1.1.5/x.php"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "探活失败") {
		t.Fatalf("探活失败应 400 且说明原因: %d %s", rec.Code, rec.Body)
	}
	if got := tr.IdentityEgressLabel("task7"); got != "" {
		t.Fatalf("探活失败却绑定了出口 %q", got)
	}
}

// 任务代理环境接口：给出该任务真正使用的带凭据地址（没它就无法手工复现任务出口）。
func TestTaskProxyEnvEndpoint(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	m.tasks = map[string]*Task{"7": {ID: "7"}}
	s := &Server{m: m}
	mux := tunnelAPITestMux(s)
	mux.HandleFunc("GET /api/tasks/{id}/proxy", s.taskProxyEnv)

	for _, bad := range []string{"/api/tasks/abc/proxy", "/api/tasks/0/proxy"} {
		req := httptest.NewRequest("GET", bad, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("%s 应 400，得到 %d", bad, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/api/tasks/999/proxy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("不存在的任务应 404，得到 %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/api/tasks/7/proxy", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("应 200，得到 %d %s", rec.Code, rec.Body)
	}
	var env struct {
		Proxy    string `json:"proxy"`
		Socks    string `json:"socks"`
		Identity string `json:"identity"`
		Egress   string `json:"egress"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	// 身份必须是 task7，且地址里带着这个身份与令牌（否则监听器无法分辨是谁的连接）。
	if env.Identity != "task7" {
		t.Fatalf("identity = %q，想要 task7", env.Identity)
	}
	if !strings.HasPrefix(env.Proxy, "http://task7:") || !strings.Contains(env.Proxy, "@") {
		t.Fatalf("proxy 地址没带任务身份: %q", env.Proxy)
	}
	if !strings.HasPrefix(env.Socks, "socks5h://task7:") {
		t.Fatalf("socks 地址没带任务身份: %q", env.Socks)
	}
	if env.Egress != "" {
		t.Fatalf("还没绑隧道，egress 应为空，得到 %q", env.Egress)
	}
}

// 文件库接口：清单带描述与绝对路径；下载按清单白名单解析，路径穿越必须 404。
func TestPayloadAPIListAndDownload(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	mux := tunnelAPITestMux(s)

	req := httptest.NewRequest("GET", "/api/payloads", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("清单接口失败: %d %s", rec.Code, rec.Body)
	}
	var man payloads.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &man); err != nil {
		t.Fatalf("清单不是 JSON: %v", err)
	}
	if len(man.Files) != 9 {
		t.Fatalf("条目数 = %d，想要 9（Neo-reGeorg 的九个模板）", len(man.Files))
	}
	// 生成出来的 Neo-reGeorg 载荷也必须能从这里下载出去（agent 就是照 manifest 的 path 取文件）。
	req = httptest.NewRequest("GET", "/api/payloads/download?name=tunnel.php", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.Len() == 0 {
		t.Fatalf("下载生成的隧道载荷失败: %d %d 字节", rec.Code, rec.Body.Len())
	}
	if !strings.Contains(rec.Body.String(), regeorg.TunnelChars) {
		t.Fatal("下载到的载荷里没有平台的固定参数")
	}

	// 正常下载：能拿到生成出来的隧道载荷。
	req = httptest.NewRequest("GET", "/api/payloads/download?name=tunnel.php", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("下载失败: %d %s", rec.Code, rec.Body)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("下载到的载荷是空的")
	}

	// 路径穿越/未登记的名字一律 404（name 只用来查清单，从不拼路径）。
	for _, bad := range []string{"../../etc/passwd", "..%2f..%2fetc%2fpasswd", "nope.php", ""} {
		req = httptest.NewRequest("GET", "/api/payloads/download?name="+bad, nil)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Fatalf("非法 name %q 竟然下载成功（%d 字节）", bad, rec.Body.Len())
		}
	}
}
