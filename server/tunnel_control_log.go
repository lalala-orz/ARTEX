package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/artex/tunnel"
)

// 控制通道记录的去重状态：键是"任务 + 失败摘要"，值是该失败上一次被记录的时间。
// 放包级是因为它纯粹是日志节流状态 —— 进程重启丢了最多多记一条，不需要跟隧道生命周期绑定。
var (
	tunnelControlMu    sync.Mutex
	tunnelControlFirst = map[int64]bool{}
	tunnelControlSeen  = map[string]time.Time{}
)

const (
	// tunnelControlDedupWindow 是同一类失败的最短记录间隔：一条挂掉的隧道会在数据路径上
	// 反复失败（每次 READ/FORWARD 一次），不节流就会刷屏并把目标流量挤出索引。
	tunnelControlDedupWindow = 20 * time.Second
	// tunnelControlStateCap 是节流表上限，纯兜底：隧道本来就不多。
	tunnelControlStateCap = 512
)

// tunnelControlLog 返回控制通道事件回调，决定"哪些事件值得进流量库"。
//
// 记什么：
//   - 每条隧道的**第一次成功请求** —— 这是"控制通道真到得了载荷"的第一手证据；
//   - **传输层失败**（超时/连不上/被代理拒）—— 这是"隧道为什么不通"的答案，以前只能翻进程日志；
//   - 同一类失败按 tunnelControlDedupWindow 去重。
//
// 不记什么：成功的长轮询（READ/FORWARD）。一条活跃隧道每秒几十个请求，全进索引会把它灌满，
// 而它们能提供的信息几乎为零。
//
// 回调跑在隧道的请求路径上，所以这里只做常数时间的事（查表 + 至多一次异步入队）。
func (m *Manager) tunnelControlLog(taskID int64, upstream string) func(tunnel.ControlEvent) {
	tr := m.Traffic()
	if tr == nil {
		return nil
	}
	// 出口标签进 egress 字段：和别的出口一样能在流量页的出口下拉里筛出"控制通道走了哪"。
	label := "tunnel-control:direct"
	if u := strings.TrimSpace(upstream); u != "" {
		label = "tunnel-control:" + u
	}
	return func(ev tunnel.ControlEvent) {
		failed := strings.TrimSpace(ev.Err) != ""
		key := fmt.Sprintf("%d|%s", taskID, summarizeControlErr(ev.Err))
		now := time.Now()
		tunnelControlMu.Lock()
		if len(tunnelControlSeen)+len(tunnelControlFirst) > tunnelControlStateCap {
			tunnelControlSeen = map[string]time.Time{}
			tunnelControlFirst = map[int64]bool{}
		}
		allow := false
		if failed {
			if last, ok := tunnelControlSeen[key]; !ok || now.Sub(last) > tunnelControlDedupWindow {
				tunnelControlSeen[key] = now
				allow = true
			}
		} else if !tunnelControlFirst[taskID] {
			tunnelControlFirst[taskID] = true
			allow = true
		}
		tunnelControlMu.Unlock()
		if !allow {
			return
		}
		tr.RecordControlExchange(traffic.ControlExchange{
			At:      ev.At,
			TaskID:  taskID,
			Egress:  label,
			Method:  ev.Method,
			Host:    ev.Host,
			Path:    ev.Path,
			URL:     ev.URL,
			Status:  ev.Status,
			ReqLen:  ev.ReqLen,
			RespLen: ev.RespLen,
			ErrText: ev.Err,
		})
	}
}

// summarizeControlErr 把错误压成短摘要当作去重键。完整错误里常带端口/连接 id 等可变部分，
// 直接用会让"同类失败"被当成不同失败，去重就失效了。
func summarizeControlErr(err string) string {
	s := strings.TrimSpace(err)
	if s == "" {
		return ""
	}
	if len(s) > 80 {
		s = s[:80] // 错误文本是 ASCII，按字节截断安全
	}
	return s
}
