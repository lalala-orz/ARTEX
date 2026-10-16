package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 「待生效的任务出口」：在"新建任务"里填的出口（用户已有的 socks5/http 代理）先记在这里，
// 绑定成功就从表里消失。
//
// 为什么需要它（时序问题）：隧道是绑在任务的"身份 identity + token"上的，而任务刚建时 agent
// 还没起、身份可能还没就绪。所以建任务时**不赌**身份是否就绪：先把意图记下来，能绑就立刻绑，
// 绑不上就留下原因等重试。重试时机就借用隧道列表接口（界面每 5 秒轮询一次），于是"任务一启动、
// 身份就绪 ⇒ 出口自动生效"不需要任何额外的启动钩子。
//
// 状态放包级：它只是一份"还没生效的意图"，进程重启丢了最多需要人工点一次「重试绑定」
// （隧道页本来就提供这个按钮），不值得为它引入持久化。
type pendingTaskEgress struct {
	Kind     string
	URL      string
	Probe    string
	Upstream string
	Reason   string
	At       time.Time
	LastTry  time.Time
}

// TaskEgressReq 是建任务请求里可选的出口（只支持"我已有的隧道/代理"）。
type TaskEgressReq struct {
	// Kind 是出口类型："proxy"（默认）= 我已有的隧道/代理（socks5/http，直拨不经 global_proxy）；
	// "regeorg"（也接受 neo/payload）= 平台投放 neo 载荷并驱动它。
	Kind string `json:"kind"`
	URL  string `json:"url"`
	// Probe 是探活目标（host:port）。留空时：代理型用 1.1.1.1:80，载荷型按载荷地址推。
	Probe string `json:"probe"`
	// Upstream 只对载荷型有意义：控制通道（平台 → 载荷）的出口。""=跟随 global_proxy、
	// "direct"=直连载荷。代理型没有控制通道，忽略它。
	Upstream string `json:"upstream"`
}

var (
	pendingEgressMu sync.Mutex
	pendingEgress   = map[int64]*pendingTaskEgress{}
)

// pendingEgressRetryInterval 是同一个待生效出口的最短重试间隔：列表接口每 5 秒被轮询一次，
// 不节流就会每次轮询都去连一遍代理（探活最长要几十秒），把接口拖垮。
const pendingEgressRetryInterval = 5 * time.Second

// PendingEgressView 是给列表接口的只读快照。
type PendingEgressView struct {
	TaskID  int64  `json:"task_id"`
	Kind    string `json:"kind,omitempty"`
	URL     string `json:"url"`
	Probe   string `json:"probe"`
	Reason  string `json:"reason,omitempty"`
	At      string `json:"at"`
	LastTry string `json:"last_try,omitempty"`
}

func setPendingTaskEgress(taskID int64, kind, url, probe, upstream, reason string) {
	if taskID <= 0 {
		return
	}
	pendingEgressMu.Lock()
	defer pendingEgressMu.Unlock()
	prev := pendingEgress[taskID]
	e := &pendingTaskEgress{Kind: kind, URL: url, Probe: probe, Upstream: upstream, Reason: reason, At: time.Now()}
	if prev != nil {
		// 保留首次登记时间，重试不该让它看起来像"刚填的"。
		e.At = prev.At
		e.LastTry = prev.LastTry
	}
	pendingEgress[taskID] = e
}

func clearPendingTaskEgress(taskID int64) {
	pendingEgressMu.Lock()
	delete(pendingEgress, taskID)
	pendingEgressMu.Unlock()
}

func pendingEgressViews() []PendingEgressView {
	pendingEgressMu.Lock()
	defer pendingEgressMu.Unlock()
	out := make([]PendingEgressView, 0, len(pendingEgress))
	for id, e := range pendingEgress {
		v := PendingEgressView{TaskID: id, Kind: e.Kind, URL: e.URL, Probe: e.Probe, Reason: e.Reason, At: e.At.Format(time.RFC3339)}
		if !e.LastTry.IsZero() {
			v.LastTry = e.LastTry.Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out
}

// registerTaskEgress 处理"新建任务时填的出口"：校验 → 记成待生效 → 立刻尝试绑定。
// 返回绑定的结果：nil 表示已生效；有错表示任务照建但出口没生效（原因已记进待生效表）。
func registerTaskEgress(m *Manager, taskID int64, kind, rawURL, probe, upstream string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	kind = normalizeEgressKind(kind)
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		err = fmt.Errorf("地址无效：%q", rawURL)
		setPendingTaskEgress(taskID, kind, rawURL, probe, upstream, err.Error())
		return err
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// 载荷 URL，或者 HTTP CONNECT 型代理 —— 两种都由 kind 决定怎么用。
	case "socks5", "socks5h":
		if kind != "proxy" {
			err = fmt.Errorf("socks5 地址属于「普通隧道」，请把出口类型改成「已有隧道/代理」：%q", rawURL)
			setPendingTaskEgress(taskID, kind, rawURL, probe, upstream, err.Error())
			return err
		}
	default:
		err = fmt.Errorf("地址只支持 http/https（neo 载荷）或 socks5/socks5h/http（已有代理）：%q", rawURL)
		setPendingTaskEgress(taskID, kind, rawURL, probe, upstream, err.Error())
		return err
	}
	setPendingTaskEgress(taskID, kind, rawURL, strings.TrimSpace(probe), upstream, "尚未生效：等待任务启动")
	return tryBindPendingTaskEgress(m, taskID)
}

// normalizeEgressKind 归一出口类型：默认按"我已有的隧道/代理"处理。
func normalizeEgressKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "regeorg", "neo", "neoreg", "payload":
		return "regeorg"
	default:
		return "proxy"
	}
}

// bindPendingTaskEgress 是"把待生效出口绑上去"的共用实现。Backend 固定 proxy：
// 建任务时填的只能是"已有的隧道/代理"，不去投放载荷。
func tryBindPendingTaskEgress(m *Manager, taskID int64) error {
	pendingEgressMu.Lock()
	e := pendingEgress[taskID]
	if e == nil {
		pendingEgressMu.Unlock()
		return nil
	}
	req := TunnelRequest{TaskID: taskID, Backend: e.Kind, ServerURL: e.URL, Probe: e.Probe, Upstream: e.Upstream}
	e.LastTry = time.Now()
	pendingEgressMu.Unlock()

	tun, err := m.OpenTunnel(context.Background(), req)
	if err != nil {
		pendingEgressMu.Lock()
		if cur := pendingEgress[taskID]; cur != nil {
			cur.Reason = err.Error()
			cur.LastTry = time.Now()
		}
		pendingEgressMu.Unlock()
		return err
	}
	clearPendingTaskEgress(taskID)
	log.Printf("[egress] 任务 %d 的出口已生效：%s（探活 %s）", taskID, tun.Describe, tun.Probe)
	return nil
}

// retryPendingTaskEgress 在列表接口里对所有待生效出口做节流重试。
//
// 必须异步：一次 OpenTunnel 要探活（最长几十秒），同步做会把列表接口拖住；界面每 5 秒轮询
// 一次，所以"这一轮没生效"下一轮就能看到更新后的原因。
func retryPendingTaskEgress(m *Manager) {
	if m == nil {
		return
	}
	pendingEgressMu.Lock()
	now := time.Now()
	var due []int64
	for id, e := range pendingEgress {
		if now.Sub(e.LastTry) < pendingEgressRetryInterval {
			continue
		}
		e.LastTry = now
		due = append(due, id)
	}
	pendingEgressMu.Unlock()
	for _, id := range due {
		go func(taskID int64) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[egress] 重试任务 %d 的出口时 panic（已忽略）: %v", taskID, r)
				}
			}()
			_ = tryBindPendingTaskEgress(m, taskID)
		}(id)
	}
}
