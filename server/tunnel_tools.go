package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/payloads"
	actool "github.com/Autumn-27/norma/tool"
)

// tunnelTools is the agent-facing tunnel surface: discover the platform's payload
// library, bring a tunnel up through the binding gate, look at it, close it.
//
// Runtime availability is gated by hostTools() on capture being on, like the traffic
// tools — a tunnel is bound to the recording listener, so with capture off there is
// nothing to bind.
func (s *Server) tunnelTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolTunnelPayloads(),
		s.toolTunnelUp(),
		s.toolTunnelList(),
		s.toolTunnelDown(),
	}
}

// taskIDForTool is the task a tool call belongs to; 0 outside a task run (a chat
// turn, say).
func taskIDForTool(ctx context.Context) int64 { return agent.RunInfoFrom(ctx).TaskID }

// toolTunnelPayloads lists the platform's file library. It re-syncs first, so the
// answer always matches the bytes on disk (and a missing manifest repairs itself
// instead of sending the agent looking for files that are not there).
func (s *Server) toolTunnelPayloads() actool.CoreTool {
	return roTool("tunnel_payloads",
		"列出平台自带的隧道载荷文件库：每个文件的目标运行环境、投放方式(upload-file 上传到 Web 路径 / run-process 在目标上执行 / exploit-request 原样发送该 HTTP 请求 / compile-inject 编译后注入)、环境要求、支持的传输模式、投放后应交给 tunnel_up 的 URL、注意事项与已知坑。拿到目标权限后先看它，挑匹配目标运行时的那个文件，按 path 取用并自行上传，再把可访问 URL 交给 tunnel_up。",
		objSchema(map[string]any{}),
		func(context.Context, json.RawMessage) (actool.Result, error) {
			man, err := payloads.Sync(s.m.dir)
			if err != nil {
				return actool.Errorf("读取载荷文件库失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"dir":      man.Dir,
				"manifest": payloads.ManifestName,
				"usage":    man.Usage,
				"files":    man.Files,
			})
		})
}

// toolTunnelUp brings up this task's tunnel. Everything safety-related happens in
// Manager.OpenTunnel: the probe gate, the self-loop refusal and the fail-closed
// binding — the tool only reports the outcome.
func (s *Server) toolTunnelUp() actool.CoreTool {
	return wrTool("tunnel_up",
		"为【当前任务】建立一条内网隧道：先经隧道端到端探活，通过后才把本任务的出网流量绑到该隧道上（其他任务不受影响）。用途是访问内网站点与内网服务；不要用它做端口扫描/并发压测——PHP 载荷每个连接会占住一个 FPM worker，压满会把目标整站阻塞。参数 url 是已投放且可访问的载荷 URL（见 tunnel_payloads，清单里 backend 字段标明配哪个后端）。探活失败会拒绝绑定，任务继续走原出口。用完请 tunnel_down。",
		objSchema(map[string]any{
			"url":       strParam("已投放且可访问的载荷 URL，例如 http://10.1.1.5/uploads/tunnel.php"),
			"backend":   strParam("可选：隧道后端，必须与投放的载荷配对——看 tunnel_payloads 清单里的 backend 字段。当前只有 regeorg（Neo-reGeorg），一般不用传"),
			"probe":     strParam("可选：探活目标 host:port。默认取载荷 URL 的 host:port，即让载荷主机去连它自己"),
			"upstream":  strParam("可选：这条隧道**控制通道**的出口。默认跟随平台 global_proxy；载荷在私有网段时填 direct（对外代理通常拒绝私有目标）"),
			"max_conns": map[string]any{"type": "integer", "description": "可选：覆盖并发上限。默认按载荷类型自动：.php 类=3（PHP 一条连接占一个 worker，实测 4 就崩），其它载荷=16；URL 没有扩展名时按 3 保守处理"},
			"debug":     map[string]any{"type": "boolean", "description": "可选：打开隧道客户端调试日志（排障用）"},
		}, "url"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				URL      string `json:"url"`
				Backend  string `json:"backend"`
				Probe    string `json:"probe"`
				Upstream string `json:"upstream"`
				MaxConns int    `json:"max_conns"`
				Debug    bool   `json:"debug"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			taskID := taskIDForTool(ctx)
			if taskID <= 0 {
				return actool.Errorf("tunnel_up 只能在任务内使用：本次调用没有任务上下文"), nil
			}
			tun, err := s.m.OpenTunnel(ctx, TunnelRequest{
				TaskID:    taskID,
				Backend:   in.Backend,
				ServerURL: in.URL,
				Probe:     in.Probe,
				Upstream:  in.Upstream,
				MaxConns:  in.MaxConns,
				Debug:     in.Debug,
			})
			if err != nil {
				return actool.Errorf("建立隧道失败: " + err.Error()), nil
			}
			warn := s.auditTunnel(taskID, fmt.Sprintf("为任务建立隧道：%s", tun.Describe),
				fmt.Sprintf("载荷 %s；探活 %s 通过；任务 %d 之后的出网流量经该隧道", tun.ServerURL, tun.Probe, taskID))
			out := map[string]any{
				"id": tun.ID, "egress": tun.Describe, "probe": tun.Probe,
				"server_url": tun.ServerURL,
				"note":       "本任务之后的出网流量会经这条隧道；其他任务不受影响。用完 tunnel_down 释放（PHP 目标尤其要关口，否则会占着 FPM worker）。",
			}
			if warn != "" {
				out["audit_warning"] = warn
			}
			return jsonResult(out)
		})
}

// toolTunnelList shows the tunnels and their last probe verdict. Inside a task it
// reports that task's; outside one (an orchestration or chat turn) it reports all.
func (s *Server) toolTunnelList() actool.CoreTool {
	return roTool("tunnel_list",
		"查看隧道及其健康状态：id、任务、载荷地址、当前出口(egress)、探活目标与最近一次探活结果。healthy=false 表示隧道已被判定不可用，此时该任务的新连接会被【拒绝】而不是退回直连（避免暴露本机真实地址），需要重建隧道。",
		objSchema(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			taskID := taskIDForTool(ctx)
			list := s.m.Tunnels(taskID)
			return jsonResult(map[string]any{"scope_task": taskID, "tunnels": list})
		})
}

// toolTunnelDown closes a tunnel (by id) or every tunnel of the current task.
func (s *Server) toolTunnelDown() actool.CoreTool {
	return wrTool("tunnel_down",
		"关闭隧道并把该任务放回默认出口。不传 id 时关闭当前任务的全部隧道（任务结束前建议显式关闭，避免对目标留下悬空的长连接）。",
		objSchema(map[string]any{
			"id": strParam("可选：tunnel_up/tunnel_list 返回的隧道 id；不传则关闭当前任务的全部隧道"),
		}),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(raw, &in)
			if id := strings.TrimSpace(in.ID); id != "" {
				if err := s.m.CloseTunnel(id); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				s.auditTunnel(taskIDForTool(ctx), "关闭隧道 "+id, "")
				return jsonResult(map[string]any{"closed": id})
			}
			taskID := taskIDForTool(ctx)
			if taskID <= 0 {
				return actool.Errorf("不传 id 时必须提供任务上下文"), nil
			}
			s.m.ReclaimTaskTunnels(taskID)
			s.auditTunnel(taskID, fmt.Sprintf("关闭任务 %d 的全部隧道", taskID), "")
			return jsonResult(map[string]any{"closed_task": taskID})
		})
}

// auditTunnel writes the binding into the task's activity stream — the platform's
// auditable record of what was done to a target. A failure is returned as a warning
// instead of raised: the tunnel is already up, and a failed audit write must not be
// reported as a failed bind (nor silently dropped).
func (s *Server) auditTunnel(taskID int64, summary, detail string) string {
	if taskID <= 0 {
		return ""
	}
	t := s.m.ResolveTask(strconv.FormatInt(taskID, 10))
	if t == nil || t.Store == nil {
		log.Printf("[tunnel] 任务 %d 审计未记录（找不到任务）: %s", taskID, summary)
		return "审计未记录：找不到任务"
	}
	act := db.Activity{
		Worker: "system", Kind: "text", Tool: "tunnel", Summary: summary, Detail: detail,
	}
	id, err := t.Store.AppendActivity(act)
	if err != nil {
		log.Printf("[tunnel] 任务 %d 审计写入失败: %v", taskID, err)
		return "审计写入失败：" + err.Error()
	}
	act.ID = id
	act.CreatedAt = time.Now()
	s.engine.Broadcaster().Publish(t.ID, act)
	return ""
}
