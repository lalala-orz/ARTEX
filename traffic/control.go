package traffic

import (
	"fmt"
	"time"
)

// ControlExchange 是"隧道控制通道"的一次请求：平台 → 载荷 的那一跳。
//
// 为什么要入库：隧道成不成立、后来为什么不通，以前只能翻进程日志；目标流量一直在库里，
// 唯独"把它送出去的那条控制通道"没有记录，于是隧道失败时无法回答"是探活不过、还是控制
// 通道被代理挡了、还是载荷被删了"。把这一跳写进同一张流量表以后，隧道健康与失败就和别的
// 流量一样可筛、可查、可留证。
type ControlExchange struct {
	// At 是发生时间（Unix 秒）。0 用当前时间。
	At int64
	// TaskID 是这条隧道归属的任务；Identity 留空（控制通道不属于 agent 身份）。
	TaskID int64
	// Egress 是控制通道自己的出口标签，形如 tunnel-control:direct 或
	// tunnel-control:socks5://host:port —— 和别的出口一样能在出口下拉里筛。
	Egress string
	// Method/Host/Path/URL 是这次控制请求的形状（URL 只到路径，查询串里是载荷协议的数据）。
	Method string
	Host   string
	Path   string
	URL    string
	// Status 是 HTTP 状态码；传输层失败时为 0，原因放 ErrText。
	Status int
	// ReqLen/RespLen 是上下行字节数（载荷协议是 base64 文本，量级小）。
	ReqLen  int
	RespLen int
	// ErrText 非空表示这次请求在传输层就失败了（超时、连不上、被代理拒）。
	// 它会被存成这条记录的"响应正文"，所以在流量页点开就能看到失败原因。
	ErrText string
}

// RecordControlExchange 把一次控制通道请求写进流量索引。
//
// 与普通交换的区别只有两点：身份为空（不参与任务隧道的出口判定），以及**队列满时直接丢弃**
// ——记录永远不能反过来拖慢或卡住隧道本身，隧道能用比留下一条日志重要。
func (t *Traffic) RecordControlExchange(c ControlExchange) {
	if t == nil {
		return
	}
	at := c.At
	if at <= 0 {
		at = time.Now().Unix()
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.URL == "" {
		c.URL = "http://" + c.Host + c.Path
	}
	n := t.seq.Add(1)
	pe := pendingExchange{
		id:          fmt.Sprintf("ctl-%d-%04d", at, n%10000),
		ts:          at,
		host:        c.Host,
		method:      c.Method,
		tmpl:        c.Path,
		url:         c.URL,
		reqHead:     fmt.Sprintf("%s %s HTTP/1.1\nHost: %s", c.Method, c.Path, c.Host),
		reqCT:       "application/x-www-form-urlencoded",
		contentType: "text/plain",
		status:      c.Status,
		reqLen:      c.ReqLen,
		respLen:     c.RespLen,
		taskID:      c.TaskID,
		egress:      c.Egress,
	}
	if c.ErrText != "" {
		// 失败原因放进"响应正文"：流量页的响应面板直接显示它，不用另开字段。
		pe.respBody = []byte(c.ErrText)
		pe.respLen = len(c.ErrText)
		pe.respHead = "（控制通道未取到 HTTP 响应）"
	}
	if t.recCh == nil {
		t.record(pe)
		return
	}
	t.recMu.RLock()
	defer t.recMu.RUnlock()
	if t.recShut {
		return
	}
	select {
	case t.recCh <- pe:
	default:
		// 队列满：丢这一条。控制通道是长轮询，一条活跃隧道每秒能发几十个请求，
		// 宁可丢日志也不能让隧道的请求路径阻塞在记录上。
	}
}
