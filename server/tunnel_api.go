package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	pgdb "github.com/Autumn-27/artex/db"

	"github.com/Autumn-27/artex/payloads"
)

// maxTunnelRequestBytes bounds the tunnel-create body: it carries a URL and a few
// short options, never a payload.
const maxTunnelRequestBytes = 8 << 10

// listTunnels reports the live tunnels and their last probe verdict.
//
// GET /api/tunnels[?task=<id>] — without a filter it lists every task's, which is
// what an operator view needs; with one it answers "where does this task's traffic
// go". Tunnels are runtime state (they live in this process), so this is the only
// authoritative view of them.
func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	var taskID int64
	if q := strings.TrimSpace(r.URL.Query().Get("task")); q != "" {
		n, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "task 必须是数字任务 id")
			return
		}
		taskID = n
	}
	// 先兜底清扫：已结束任务的隧道不该出现在这份"权威视图"里（它们已经没用了，
	// 而且留在目标上是个隐患）。
	// （管理器内部会为回收的隧道写日志，这里不重复打。）
	s.m.ReclaimFinishedTasks()
	// 待生效出口的节流重试就挂在这里：界面每 5 秒轮询一次隧道列表，于是"任务一启动、
	// 身份就绪 ⇒ 出口自动生效"不需要额外的启动钩子。重试是异步的，不会拖住这个接口。
	retryPendingTaskEgress(s.m)
	list := s.m.Tunnels(taskID)
	if list == nil {
		list = []TunnelInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnels": list,
		// 还没生效的出口意图（含上次失败原因）单独给一份：界面把它们也渲染出来，
		// 并提供「重试绑定」，这样"建任务时填的出口"不会看起来像没填。
		"pending": pendingEgressViews(),
		// The library path rides along so the UI can point at the payload files the
		// same way the agent does.
		"payload_dir": s.m.PayloadDir(),
	})
}

// createTaskTunnel binds a tunnel to one task. Every safety rule lives in
// Manager.OpenTunnel (probe gate, self-loop refusal, fail-closed binding); this
// handler only validates the request and reports the outcome, so the API and the
// agent's tunnel_up tool cannot diverge.
//
// POST /api/tasks/{id}/tunnel  {"url": "...", "backend": "regeorg", "probe": "", "upstream": "direct", "debug": false}
func (s *Server) createTaskTunnel(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	n, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "task id 必须是数字")
		return
	}
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if pgdb.IsTerminal(s.m.TaskStatus(taskID)) {
		// A finished task has no agent to use it: binding would only leave a
		// dangling tunnel on the target (it would never be reclaimed by itself).
		writeErr(w, http.StatusConflict, "任务已结束，不能再新建隧道")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelRequestBytes)
	var request struct {
		URL string `json:"url"`
		// Backend 必须与投放的载荷配对（文件库清单里的 backend 字段）：默认 regeorg。
		Backend string `json:"backend"`
		Probe   string `json:"probe"`
		// Upstream 决定这条隧道**控制通道**的出口：""=跟随 global_proxy、"direct"=直连、其它=代理 URL。
		// 载荷在私有网段时必须 direct——对外的代理通常拒绝转发私有目标。
		Upstream string `json:"upstream"`
		// MaxConns 覆盖并发上限；0（默认）=按载荷类型自动（PHP 3、其它 16）。
		MaxConns int  `json:"max_conns"`
		Debug    bool `json:"debug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	tun, err := s.m.OpenTunnel(r.Context(), TunnelRequest{
		TaskID:    n,
		Backend:   request.Backend,
		ServerURL: request.URL,
		Probe:     request.Probe,
		Upstream:  request.Upstream,
		MaxConns:  request.MaxConns,
		Debug:     request.Debug,
	})
	if err != nil {
		// 探活失败/已有隧道/自环都是"这次绑定不成立"，不是服务端故障，所以用 400 把
		// 原因原样交给调用方（任务仍在原出口上，什么都没变）。
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 手动（或按提示重试）绑上了，就把待生效那条意图清掉。
	clearPendingTaskEgress(n)
	warn := s.auditTunnel(n, fmt.Sprintf("人工为任务 %d 建立隧道：%s", n, tun.Describe),
		fmt.Sprintf("载荷 %s；探活 %s 通过", tun.ServerURL, tun.Probe))
	resp := map[string]any{
		"id": tun.ID, "task_id": n, "egress": tun.Describe,
		"server_url": tun.ServerURL, "probe": tun.Probe,
		"healthy": true, "opened_at": tun.OpenedAt,
	}
	if warn != "" {
		resp["audit_warning"] = warn
	}
	writeJSON(w, http.StatusOK, resp)
}

// deleteTaskTunnel closes every tunnel of a task and returns it to the default
// egress. Idempotent: closing nothing is a success with closed=0.
//
// DELETE /api/tasks/{id}/tunnel
func (s *Server) deleteTaskTunnel(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	n, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "task id 必须是数字")
		return
	}
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	closed := len(s.m.Tunnels(n))
	s.m.ReclaimTaskTunnels(n)
	if closed > 0 {
		s.auditTunnel(n, fmt.Sprintf("人工关闭任务 %d 的隧道", n), "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"closed": closed, "task_id": n})
}

// taskProxyEnv reports the proxy environment a task's agents and tools are given: the
// recording listener carrying that task's credentials.
//
// It exists because the task's identity is generated inside the platform and is
// otherwise unobservable — without it nobody can answer "why is this task's traffic
// not going through its tunnel?" by reproducing the task's egress by hand. The
// credential is handed to the task's own shell anyway (see Manager.TaskProxyAddrs),
// so this does not widen the trust boundary, but it is a credential: the endpoint
// must stay behind API auth.
//
// GET /api/tasks/{id}/proxy
func (s *Server) taskProxyEnv(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("id")
	n, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, "task id 必须是数字")
		return
	}
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	proxyAddr, socksAddr := s.m.TaskProxyAddrs(taskID)
	identity, _, _ := s.m.taskCredFor(n)
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id":  n,
		"proxy":    proxyAddr,
		"socks":    socksAddr,
		"identity": identity,
		// "" = 默认出口；非空即该任务自己的出口（隧道）。
		"egress":  s.m.TaskEgressLabel(n),
		"tunnels": s.m.Tunnels(n),
	})
}

// listPayloads returns the platform's file library: every file, its deployment
// model, target runtime, requirements and known caveats (see the payloads package).
//
// GET /api/payloads
func (s *Server) listPayloads(w http.ResponseWriter, r *http.Request) {
	man, err := payloads.Sync(s.m.dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, man)
}

// downloadPayload serves one library file.
//
// GET /api/payloads/download?name=suo5.php
//
// The name is resolved ONLY against the manifest's entries — it is never joined into
// a path — so a traversal attempt simply finds no entry and 404s. That is the whole
// point of listing files from code rather than trusting a request parameter.
func (s *Server) downloadPayload(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, "缺少 name 参数")
		return
	}
	man, err := payloads.Sync(s.m.dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, e := range man.Files {
		if e.Name != name {
			continue
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+e.Name+`"`)
		http.ServeFile(w, r, e.Path)
		return
	}
	writeErr(w, http.StatusNotFound, "载荷不存在: "+name)
}
