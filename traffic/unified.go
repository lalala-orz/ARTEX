package traffic

import (
	"strings"
)

// UnifiedRow 是流量页那一行数据的统一形态：HTTP/HTTPS 交换与裸 TCP 转发
// （SOCKS5/透明转发的非 HTTP 流量）放在同一张表里看。
//
// 之前裸 TCP 只有一个单独的"账本"侧栏，要看"这次任务到底产生了哪些流量"得在两个
// 地方来回切。现在它们是同一份数据的两个来源，用 kind 区分：
//
//	kind = "http"  → 一条被 MITM 的交换（ExchangeMeta 的字段全部有效）
//	kind = "raw"   → 一条裸 TCP 转发（RawID/BytesUp/BytesDown/Service 有效，
//	                 method 固定 "TCP"，url 是 tcp://host:port，status 为 0）
type UnifiedRow struct {
	ExchangeMeta
	Kind string `json:"kind"`
	// 下面这些只有 kind=raw 才有意义。
	RawID       int64  `json:"raw_id,omitempty"`
	BytesUp     int64  `json:"bytes_up,omitempty"`
	BytesDown   int64  `json:"bytes_down,omitempty"`
	Service     string `json:"service,omitempty"`
	ViaUpstream bool   `json:"via_upstream"`
}

// unifiedSelect 的两段 SELECT 列完全对齐（见 PageUnified 的注释）。
const unifiedColumns = `id,ts,host,method,url_template,url,status,content_type,resp_len,path,task_id,identity,egress,kind,raw_id,bytes_up,bytes_down,service,via_upstream`

// PageUnified 是流量页的取数入口：把交换表与裸 TCP 账本合成一份按时间倒序的列表。
//
// 过滤在 SQL 里做（两个子查询各自带上同样的 WHERE），这样分页才是"合并后"的分页，
// 而不是两个列表各翻各的。Egress 的语义在统一视图里是**精确**匹配：
//
//	f.Egress == ""       不筛
//	f.Egress == "direct" 只看直连（egress 为空）
//	其它                 egress 精确等于该值（UI 的下拉用真实存在的出口值）
func (t *Traffic) PageUnified(f PageQuery, page, size int) (rows []UnifiedRow, total int, err error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	if page < 0 {
		page = 0
	}
	where, args := unifiedWhere(f)
	if err = t.db.QueryRow(`SELECT COUNT(*) FROM (`+unifiedSource+`)`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	sel := `SELECT ` + unifiedColumns + ` FROM (` + unifiedSource + `)` + where +
		` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), size, page*size)
	rs, err := t.db.Query(sel, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var m UnifiedRow
		var via int
		if err := rs.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType,
			&m.RespLen, &m.Path, &m.TaskID, &m.Identity, &m.Egress, &m.Kind, &m.RawID, &m.BytesUp, &m.BytesDown,
			&m.Service, &via); err != nil {
			return nil, 0, err
		}
		m.ViaUpstream = via == 1
		rows = append(rows, m)
	}
	return rows, total, rs.Err()
}

// unifiedSource 是两份流量的并集。列语义：
//
//	exchanges            → kind=http，原样取
//	socks5_connections   → kind=raw，method 固定 TCP，url 拼成 tcp://host:port，
//	                       status 用 0 占位，resp_len 用上下行字节之和占位（排序有用），
//	                       content_type 放服务识别结果（如 mysql），path 留空。
const unifiedSource = `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path,task_id,identity,egress,'http' AS kind,0 AS raw_id,0 AS bytes_up,0 AS bytes_down,'' AS service,0 AS via_upstream FROM exchanges
UNION ALL
SELECT 'raw-'||id AS id,ts,dst_host AS host,'TCP' AS method,'' AS url_template,'tcp://'||dst_host||':'||dst_port AS url,0 AS status,COALESCE(service,'') AS content_type,bytes_up+bytes_down AS resp_len,'' AS path,task_id,identity,egress,'raw' AS kind,id AS raw_id,bytes_up,bytes_down,COALESCE(service,'') AS service,via_upstream AS via_upstream FROM socks5_connections`

// unifiedWhere 把 PageQuery 翻译成合并视图上的 WHERE。字段语义与 Page 一致，
// 只是 Egress 变成精确匹配（direct = 直连）。
func unifiedWhere(f PageQuery) (string, []any) {
	where := ""
	var args []any
	add := func(cond string, vs ...any) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += cond
		args = append(args, vs...)
	}
	if h := strings.TrimSpace(f.Host); h != "" {
		add("host LIKE ?", "%"+h+"%")
	}
	if f.TaskID > 0 {
		add("task_id=?", f.TaskID)
	}
	if f.Unattributed {
		add("task_id=0")
	}
	if f.TCPWithBody {
		// 只看"有正文的裸 TCP"：读协议头时识别出数据库服务、并保存了上下行字节的那些。
		add("kind='raw' AND raw_id IN (SELECT conn_id FROM socks5_bodies)")
	}
	if id := strings.TrimSpace(f.Identity); id != "" {
		add("identity=?", id)
	}
	switch e := strings.TrimSpace(f.Egress); {
	case e == "" || strings.EqualFold(e, "all"):
	case strings.EqualFold(e, "direct"):
		add("(egress='' OR egress IS NULL)")
	default:
		add("egress=?", e)
	}
	if m := strings.TrimSpace(f.Method); m != "" {
		add("method=?", strings.ToUpper(m))
	}
	if p := strings.TrimSpace(f.Path); p != "" {
		add("url_template LIKE ?", "%"+p+"%")
	}
	if cond, sargs, ok := statusFilter(f.Status); ok {
		add(cond, sargs...)
	}
	if f.RespMin != nil {
		add("resp_len>=?", *f.RespMin)
	}
	if f.RespMax != nil {
		add("resp_len<=?", *f.RespMax)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + s + "%"
		add("(host LIKE ? OR url LIKE ? OR url_template LIKE ? OR method LIKE ? OR content_type LIKE ? OR CAST(status AS TEXT) LIKE ?)",
			like, like, like, like, like, like)
	}
	return where, args
}

// EgressValues 汇总两份流量里实际出现过的出口（去重、排序），给前端的出口下拉用。
// 空串代表直连，由前端自己渲染成「直连」选项。
func (t *Traffic) EgressValues() ([]string, error) {
	rows, err := t.db.Query(`SELECT DISTINCT egress FROM exchanges WHERE egress<>'' AND egress IS NOT NULL
		UNION SELECT DISTINCT egress FROM socks5_connections WHERE egress<>'' AND egress IS NOT NULL ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
