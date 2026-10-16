package tunnel

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc 让测试用一个函数充当 RoundTripper。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// 控制通道的每一次请求都要能被看到，但**不能把查询串带出去**：regeorg 把载荷协议的数据
// 放在查询串里，整条 URL 记进流量库等于把通信内容抄一份。
func TestControlTransportReportsRequestsWithoutQuery(t *testing.T) {
	var seen []ControlEvent
	rt := &controlTransport{
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, ContentLength: 42, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		log: func(ev ControlEvent) { seen = append(seen, ev) },
	}
	req, err := http.NewRequest("POST", "http://payload.example/tunnel.php?cmd=READ&data=SECRETDATA", strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil || resp == nil {
		t.Fatalf("RoundTrip 应当正常返回：resp=%v err=%v", resp, err)
	}
	if len(seen) != 1 {
		t.Fatalf("应当看到 1 次控制请求，得到 %d", len(seen))
	}
	ev := seen[0]
	if ev.Method != "POST" || ev.Host != "payload.example" || ev.Path != "/tunnel.php" {
		t.Fatalf("事件形状不对：%+v", ev)
	}
	if ev.Status != 200 || ev.RespLen != 42 {
		t.Fatalf("响应信息不对：%+v", ev)
	}
	if strings.Contains(ev.URL, "?") || strings.Contains(ev.URL, "SECRETDATA") {
		t.Fatalf("URL 不该带查询串：%q", ev.URL)
	}
}

// 传输层失败必须被记下来（Err 非空、Status=0）—— 这是"隧道为什么不通"的答案。
func TestControlTransportReportsTransportErrors(t *testing.T) {
	var seen []ControlEvent
	rt := &controlTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp 10.0.0.9:80: connect: connection refused")
		}),
		log: func(ev ControlEvent) { seen = append(seen, ev) },
	}
	req, _ := http.NewRequest("POST", "http://payload.example/tunnel.php", strings.NewReader("x"))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("底层错误必须原样返回")
	}
	if len(seen) != 1 || seen[0].Err == "" || seen[0].Status != 0 {
		t.Fatalf("失败事件不对：%+v", seen)
	}
}

// 记录回调 panic 也不能影响隧道：这是"记录永远不能拖垮隧道"的底线。
func TestControlTransportSurvivesPanickingLogger(t *testing.T) {
	rt := &controlTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		log: func(ControlEvent) { panic("记录炸了") },
	}
	req, _ := http.NewRequest("POST", "http://payload.example/tunnel.php", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != 204 {
		t.Fatalf("回调 panic 不该影响请求：resp=%v err=%v", resp, err)
	}
}
