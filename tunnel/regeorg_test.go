package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/regeorg"
)

// fakeNeoreg 是一个最小的 Neo-reGeorg 服务端，只为验证客户端的协议实现是否正确。
//
// 它刻意模仿真实 PHP 载荷最关键的一条性质：**会话状态放在服务端的 session 里**，靠客户端
// 带回的 cookie 认领。早期版本按 mark 直接记账，于是掩盖了"客户端没带 cookie → 每个请求都
// 是新会话 → READ 永远说 TCP session is closed"这个真实故障。
type fakeNeoreg struct {
	mu       sync.Mutex
	nextID   int
	sessions map[string]map[string]net.Conn // cookie -> mark -> 到目标的连接
	// connectCookies 记录 CONNECT 用过的会话 cookie：每条隧道连接应当有自己的会话
	// （否则 PHP 的 session 文件锁会让同会话内的 READ/FORWARD 互相排队）。
	connectCookies map[string]bool
	// inflight / maxInflight 盯住"同一隧道同一时刻只有一个短请求"（CONNECT 长轮询不算）。
	inflight    int
	maxInflight int
	// hangRead=true 时对 READ 装死（睡过客户端的预算），readCount 记录收到过几次 READ。
	hangRead  bool
	readCount int
	// contentTypes 记录收到过的请求 Content-Type（钉住"必须发表单类型"这条真机结论）。
	contentTypes map[string]bool
	// brokenHello=true 时对探活回一段无意义的正文，用来验证"载荷对不上就不建隧道"。
	brokenHello bool
}

func newFakeNeoreg() *fakeNeoreg {
	return &fakeNeoreg{sessions: map[string]map[string]net.Conn{}, connectCookies: map[string]bool{}, contentTypes: map[string]bool{}}
}

// writeFail 按载荷的格式回一个失败状态。
func writeFail(w http.ResponseWriter, msg string) {
	_, _ = w.Write([]byte(regeorg.EncodeBody(map[byte][]byte{
		regeorg.FieldStatus: []byte(regeorg.StatusFail),
		regeorg.FieldError:  []byte(msg),
	})))
}

func (f *fakeNeoreg) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	f.mu.Lock()
	if f.contentTypes != nil {
		f.contentTypes[r.Header.Get("Content-Type")] = true
	}
	f.mu.Unlock()
	if len(body) == 0 {
		if f.brokenHello {
			_, _ = w.Write([]byte("not a payload"))
			return
		}
		// 第一次请求发会话 cookie：真实载荷的 session_start() 就是这样做的。
		if _, err := r.Cookie("PHPSESSID"); err != nil {
			f.mu.Lock()
			f.nextID++
			id := fmt.Sprintf("sess%d", f.nextID)
			f.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: id, Path: "/"})
		}
		_, _ = w.Write(regeorg.HelloBytes())
		return
	}
	// 没有会话 cookie：真实 PHP 的 session_start() 会**新建一个会话并下发 cookie**，
	// 所以这里也新建（CONNECT 在全新会话里是允许的——它自己就是建立会话状态的那一步；
	// 而 READ/FORWARD 落在没 CONNECT 过的会话里，才是真正的 "TCP session is closed"）。
	cookie, err := r.Cookie("PHPSESSID")
	if err != nil {
		f.mu.Lock()
		f.nextID++
		id := fmt.Sprintf("sess%d", f.nextID)
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: id, Path: "/"})
		cookie = &http.Cookie{Name: "PHPSESSID", Value: id}
	}
	info, err := regeorg.DecodeBody(string(body))
	if err != nil {
		w.WriteHeader(500)
		return
	}
	mark := string(info[regeorg.FieldMark])
	// 短请求（READ/FORWARD/DISCONNECT）计并发；CONNECT 是长轮询，不计。
	if cmd := string(info[regeorg.FieldCmd]); cmd != regeorg.CmdConnect {
		f.mu.Lock()
		f.inflight++
		if f.inflight > f.maxInflight {
			f.maxInflight = f.inflight
		}
		f.mu.Unlock()
		defer func() {
			f.mu.Lock()
			f.inflight--
			f.mu.Unlock()
		}()
	}
	out := map[byte][]byte{}
	switch string(info[regeorg.FieldCmd]) {
	case regeorg.CmdConnect:
		f.mu.Lock()
		f.connectCookies[cookie.Value] = true
		f.mu.Unlock()
		// 模仿真实载荷：CONNECT 分支里 @header_remove('set-cookie')，故意不下发会话 cookie。
		// 正因为如此，客户端必须整条隧道复用 hello 建立的会话，不能每连接换一个。
		w.Header().Del("Set-Cookie")
		target := net.JoinHostPort(string(info[regeorg.FieldIP]), string(info[regeorg.FieldPort]))
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			out[regeorg.FieldStatus] = []byte(regeorg.StatusFail)
			out[regeorg.FieldError] = []byte("Failed connecting to target")
			break
		}
		f.mu.Lock()
		if f.sessions[cookie.Value] == nil {
			f.sessions[cookie.Value] = map[string]net.Conn{}
		}
		f.sessions[cookie.Value][mark] = conn
		f.mu.Unlock()
		out[regeorg.FieldStatus] = []byte(regeorg.StatusOK)
	case regeorg.CmdForward:
		conn := f.session(cookie.Value, mark)
		if conn == nil {
			out[regeorg.FieldStatus] = []byte(regeorg.StatusFail)
			out[regeorg.FieldError] = []byte("TCP session is closed")
			break
		}
		if _, err := conn.Write(info[regeorg.FieldData]); err != nil {
			out[regeorg.FieldStatus] = []byte(regeorg.StatusFail)
			out[regeorg.FieldError] = []byte("write failed")
			break
		}
		out[regeorg.FieldStatus] = []byte(regeorg.StatusOK)
	case regeorg.CmdRead:
		f.mu.Lock()
		f.readCount++
		hang := f.hangRead
		f.mu.Unlock()
		if hang {
			// 装死：睡过客户端的数据路径预算（测试里配成 200ms×2）。
			time.Sleep(2 * time.Second)
			out[regeorg.FieldStatus] = []byte(regeorg.StatusOK)
			out[regeorg.FieldData] = nil
			break
		}
		conn := f.session(cookie.Value, mark)
		if conn == nil {
			out[regeorg.FieldStatus] = []byte(regeorg.StatusFail)
			out[regeorg.FieldError] = []byte("TCP session is closed")
			break
		}
		// 短超时读一次：没数据就回空 DATA，客户端会按 read-interval 再来问。
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		n, _ := conn.Read(buf)
		out[regeorg.FieldStatus] = []byte(regeorg.StatusOK)
		out[regeorg.FieldData] = buf[:n]
	case regeorg.CmdDisconnect:
		f.drop(cookie.Value, mark)
		out[regeorg.FieldStatus] = []byte(regeorg.StatusOK)
	default:
		out[regeorg.FieldStatus] = []byte(regeorg.StatusFail)
		out[regeorg.FieldError] = []byte("unknown cmd")
	}
	_, _ = w.Write([]byte(regeorg.EncodeBody(out)))
}

// readCountValue 返回收到的 READ 次数。
func (f *fakeNeoreg) readCountValue() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readCount
}

// maxShortInflight 返回非 CONNECT 请求达到过的最大并发数。
func (f *fakeNeoreg) maxShortInflight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInflight
}

// distinctConnectCookies 返回 CONNECT 用过的不同会话数。
func (f *fakeNeoreg) distinctConnectCookies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.connectCookies)
}

func (f *fakeNeoreg) session(cookie, mark string) net.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions[cookie][mark]
}

func (f *fakeNeoreg) drop(cookie, mark string) {
	f.mu.Lock()
	conn := f.sessions[cookie][mark]
	delete(f.sessions[cookie], mark)
	f.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// startEcho 起一个回声服务，充当"内网目标"。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func noAsync() *bool { v := false; return &v }

// 端到端：经"假载荷"把字节双向送过去，并且能连续开多条连接（PHP 载荷最缺的就是这个）。
func TestRegeorgDialRelaysAndSupportsConcurrentConnections(t *testing.T) {
	target := startEcho(t)
	fake := newFakeNeoreg()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:      []string{srv.URL + "/tunnel.php"},
		AsyncConnect:    noAsync(),
		ReadIntervalMS:  20,
		WriteIntervalMS: 20,
		MaxRetry:        3,
		Timeout:         10,
	})
	if err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}
	defer tn.Close()
	if got := tn.Describe(); got == "" {
		t.Fatal("Describe 为空")
	}

	// 三条并发连接，每条都要能双向过数据。
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := tn.Dial(ctx, target)
			if err != nil {
				t.Errorf("第 %d 条 Dial 失败: %v", i, err)
				return
			}
			defer conn.Close()
			msg := []byte("ping-" + string(rune('a'+i)))
			if _, err := conn.Write(msg); err != nil {
				t.Errorf("第 %d 条写入失败: %v", i, err)
				return
			}
			got := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Errorf("第 %d 条读回失败: %v", i, err)
				return
			}
			if string(got) != string(msg) {
				t.Errorf("第 %d 条回显不一致: %q vs %q", i, got, msg)
			}
		}(i)
	}
	wg.Wait()
}

// 异步 CONNECT（PHP 的形态）下也必须确认会话真的建立了：
// 载荷是先 fsockopen、成功了才把会话标成 running，所以 READ 能回答"连上没有"。
// 不验证的话，目标不可达也会被上层门禁当成"隧道可用"——那门禁就是假的。
func TestRegeorgAsyncConnectVerifiesSession(t *testing.T) {
	target := startEcho(t)
	fake := newFakeNeoreg()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	yes := true
	// 故意用 .php 后缀 + 显式 AsyncConnect，走异步路径。
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:      []string{srv.URL + "/tunnel.php"},
		AsyncConnect:    &yes,
		AsyncWaitMS:     3000,
		AsyncPollMS:     20,
		ReadIntervalMS:  20,
		WriteIntervalMS: 20,
		MaxRetry:        3,
		Timeout:         10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()

	// 可达目标：应当连上并双向过数据。
	conn, err := tn.Dial(ctx, target)
	if err != nil {
		t.Fatalf("异步 CONNECT 建连失败: %v", err)
	}
	defer conn.Close()
	msg := []byte("async-ok")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("回显不一致: %q vs %q", got, msg)
	}

	// 不可达目标：异步路径同样必须失败（而不是"发出去就算成功"）。
	if _, err := tn.Dial(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("异步 CONNECT 下目标不可达竟然也算成功（门禁会被伪造）")
	}
}

// 载荷对不上约定（参数不符/已被删）时必须**建不起来**，不能留一条永远连不通的隧道。
func TestRegeorgRefusesWhenPayloadDoesNotAnswer(t *testing.T) {
	fake := newFakeNeoreg()
	fake.brokenHello = true
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:   []string{srv.URL + "/tunnel.php"},
		AsyncConnect: noAsync(),
		MaxRetry:     2,
		Timeout:      5,
	}); err == nil {
		t.Fatal("载荷应答不对却建起了隧道")
	}
}

// 目标连不上时要如实报错（CONNECT 的 FAIL），不能装作成功。
func TestRegeorgDialReportsConnectFailure(t *testing.T) {
	fake := newFakeNeoreg()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:   []string{srv.URL + "/tunnel.php"},
		AsyncConnect: noAsync(),
		MaxRetry:     2,
		Timeout:      5,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	// 127.0.0.1:1 基本不会有服务监听。
	if _, err := tn.Dial(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("目标不可达时 Dial 竟然成功了")
	}
}

// 整条隧道必须**共用一个 PHP 会话**：载荷的 CONNECT 会剥掉 Set-Cookie，所以"每连接一个
// 会话"的客户端拿不到 cookie，后续请求会落到空会话上全部失败（真机上实测 0/8）。
func TestRegeorgSharesOneSession(t *testing.T) {
	target := startEcho(t)
	fake := newFakeNeoreg()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:      []string{srv.URL + "/tunnel.php"},
		AsyncConnect:    noAsync(),
		ReadIntervalMS:  20,
		WriteIntervalMS: 20,
		MaxRetry:        3,
		Timeout:         10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()

	for i := 0; i < 3; i++ {
		conn, err := tn.Dial(ctx, target)
		if err != nil {
			t.Fatalf("第 %d 条 Dial 失败: %v", i, err)
		}
		_ = conn.Close()
	}
	if got := fake.distinctConnectCookies(); got != 1 {
		t.Fatalf("CONNECT 用到 %d 个会话，想要 1 个（整条隧道共用一个）——载荷 CONNECT 不发 cookie，换会话就会全部失败", got)
	}
}

// 同一隧道的短请求必须串行：载荷在 CONNECT 上剥掉 Set-Cookie，整条隧道共用一个 PHP 会话，
// 而 PHP 的 session 文件锁会让并发的 READ/FORWARD 互相排队——实测表现为双路各约一半超时。
// （异步 CONNECT 不算在内：它是长轮询，串进去会自锁。）
func TestRegeorgSerializesShortRequestsPerTunnel(t *testing.T) {
	target := startEcho(t)
	fake := newFakeNeoreg()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:      []string{srv.URL + "/tunnel.php"},
		AsyncConnect:    noAsync(),
		ReadIntervalMS:  1,
		WriteIntervalMS: 1,
		MaxRetry:        3,
		Timeout:         10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()

	// 4 条连接同时收发，逼出并发。
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := tn.Dial(ctx, target)
			if err != nil {
				t.Errorf("Dial 失败: %v", err)
				return
			}
			defer conn.Close()
			msg := []byte("x")
			for n := 0; n < 3; n++ {
				if _, err := conn.Write(msg); err != nil {
					return
				}
			}
			time.Sleep(300 * time.Millisecond)
		}(i)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	if got := fake.maxShortInflight(); got > 1 {
		t.Fatalf("同一隧道内出现了 %d 个并发短请求，想要 1（否则会撞 PHP 会话锁）", got)
	}
}

// 载荷对 READ 装死时：必须在数据路径预算内放弃（而不是挂到分钟级）、重试次数恰好等于
// DataRetries、并且调用方立刻拿到错误（连接被撕掉，而不是无限等待）。
//
// 这三条是实测调出来的：曾经把预算调小到"快速失败"反而让成功率掉到 8/10；也曾因为预算过大，
// 载荷卡住时调用方要干等 30s。它们是编译期看不出来的行为，必须由测试钉住。
func TestRegeorgDataPathGivesUpWithinBudget(t *testing.T) {
	target := startEcho(t)
	fake := newFakeNeoreg()
	fake.hangRead = true
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:      []string{srv.URL + "/tunnel.php"},
		AsyncConnect:    noAsync(),
		ReadIntervalMS:  1,
		WriteIntervalMS: 1,
		MaxRetry:        3,
		Timeout:         5,
		DataTimeoutMS:   200,
		DataRetries:     2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()

	conn, err := tn.Dial(ctx, target)
	if err != nil {
		t.Fatalf("Dial 失败: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("载荷装死，读数却成功了")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("放弃用了 %v，远超数据路径预算（200ms × 2）", elapsed)
	}
	// 重试次数：READ 应当恰好被尝试 DataRetries 次。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fake.readCountValue() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := fake.readCountValue(); got != 2 {
		t.Fatalf("READ 尝试了 %d 次，想要 2 次（DataRetries）", got)
	}
}

// 默认值本身也要钉住：传 0 不能静默变成"没有超时"。
func TestRegeorgDataPathDefaults(t *testing.T) {
	cfg := withDefaults(RegeorgConfig{})
	if cfg.DataTimeoutMS != 10000 || cfg.DataRetries != 3 {
		t.Fatalf("数据路径默认 = %dms / %d 次，想要 10000ms / 3 次", cfg.DataTimeoutMS, cfg.DataRetries)
	}
	if cfg.ReadIntervalMS != 100 || cfg.WriteIntervalMS != 200 {
		t.Fatalf("轮询间隔默认 = 读 %dms / 写 %dms，想要 100 / 200", cfg.ReadIntervalMS, cfg.WriteIntervalMS)
	}
	if cfg.Timeout != 30 || cfg.MaxRetry != 10 {
		t.Fatalf("建立阶段默认 = %ds / %d 次，想要 30s / 10 次", cfg.Timeout, cfg.MaxRetry)
	}
	if cfg.ReadBuffKB != 7 {
		t.Fatalf("读缓冲默认 = %dKB，想要 7KB", cfg.ReadBuffKB)
	}
	// 显式给的值必须原样保留（不能把调用方的选择覆盖掉）。
	tuned := withDefaults(RegeorgConfig{DataTimeoutMS: 1500, DataRetries: 1, ReadIntervalMS: 250})
	if tuned.DataTimeoutMS != 1500 || tuned.DataRetries != 1 || tuned.ReadIntervalMS != 250 {
		t.Fatalf("显式取值被覆盖了: %+v", tuned)
	}
}

// Content-Type 必须是表单类型：真机上 PHP 5.6 只要看到非表单类型就会先输出
// $HTTP_RAW_POST_DATA 的 Deprecated 警告，于是响应头已发出、@session_start() 发不出
// Set-Cookie，客户端拿不到会话 → 一切回 "TCP session is closed"（nginx + PHP 5.6 实测）。
func TestRegeorgSendsFormContentType(t *testing.T) {
	target := startEcho(t)
	fake := newFakeNeoreg()
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tn, err := NewRegeorg(ctx, RegeorgConfig{
		ServerURLs:   []string{srv.URL + "/tunnel.php"},
		AsyncConnect: noAsync(),
		MaxRetry:     2,
		Timeout:      5,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()
	conn, err := tn.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.contentTypes) != 1 {
		t.Fatalf("请求出现过 %d 种 Content-Type: %v，想要恰好 1 种", len(fake.contentTypes), fake.contentTypes)
	}
	if _, ok := fake.contentTypes["application/x-www-form-urlencoded"]; !ok {
		t.Fatalf("Content-Type = %v，必须是 application/x-www-form-urlencoded（否则 PHP 会先输出警告、会话 cookie 发不出来）", fake.contentTypes)
	}
}
