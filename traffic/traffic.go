// Package traffic implements the request-recording subsystem (docs §10): an
// embedded go-mitmproxy proxy whose addon writes every target HTTP exchange into
// a human-browsable file tree, with a sidecar SQLite index for paged queries.
// Full capture, plaintext (no redaction), target HTTP only.
package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	_ "modernc.org/sqlite"
)

const indexSchema = `
CREATE TABLE IF NOT EXISTS exchanges (
  id           TEXT PRIMARY KEY,
  ts           INTEGER,
  host         TEXT,
  method       TEXT,
  url_template TEXT,
  url          TEXT,
  status       INTEGER,
  content_type TEXT,
  req_len      INTEGER,
  resp_len     INTEGER,
  path         TEXT,
  task_id      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ex_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_ex_tmpl ON exchanges(host, url_template);
CREATE INDEX IF NOT EXISTS idx_ex_ts   ON exchanges(ts);
CREATE INDEX IF NOT EXISTS idx_ex_status ON exchanges(status);
CREATE INDEX IF NOT EXISTS idx_ex_resp   ON exchanges(resp_len);

CREATE TABLE IF NOT EXISTS exchange_bodies (
  id        TEXT PRIMARY KEY,
  req_head  TEXT NOT NULL DEFAULT '',
  req_body  BLOB,
  req_blob  TEXT,
  resp_head TEXT NOT NULL DEFAULT '',
  resp_body BLOB,
  resp_blob TEXT
);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash        TEXT NOT NULL,
  exchange_id TEXT NOT NULL,
  PRIMARY KEY (hash, exchange_id)
);
CREATE INDEX IF NOT EXISTS idx_blob_refs_ex ON blob_refs(exchange_id);
`

// ftsSchema is applied separately from indexSchema: a driver build without FTS5
// must degrade to "no full-text search" rather than take the whole recorder down.
// trigram (not the default unicode61) is required for two reasons this subsystem
// depends on: it matches arbitrary substrings — "ssw0r" finds "P@ssw0rd" — and it
// handles CJK, which unicode61 does not tokenize. Contentless (content=”) keeps
// only the index, since the text itself lives in exchange_bodies; contentless_delete
// lets rows be deleted without replaying the original text back in.
const ftsSchema = `CREATE VIRTUAL TABLE IF NOT EXISTS ex_fts USING fts5(
  content, tokenize='trigram', content='', contentless_delete=1
);`

const (
	// maxInlineBody is the cutoff between a body stored inline (SQLite column) and
	// one spilled to the content-addressed blob store.
	maxInlineBody = 256 * 1024
	// blobPreview is how much of a spilled body stays inline so readers can tell
	// what it is (JSON shape, SQL dump header, ZIP magic) without fetching it.
	blobPreview = 8 * 1024
	// maxIndexBody caps a single body's contribution to the full-text index. Text
	// is indexed in full below this; binary never reaches the index at all.
	maxIndexBody = 4 * 1024 * 1024
	// minTrigram is the shortest term the trigram tokenizer can match; shorter
	// queries fall back to metadata LIKE.
	minTrigram = 3
	// maxBlobRead caps one traffic_blob read so paging through a large body never
	// floods the agent's context.
	maxBlobRead = 8 * 1024
	// autoVacuumIncremental is SQLite's numeric value for auto_vacuum=incremental.
	autoVacuumIncremental = 2
	// reclaimChunkPages bounds how much index space one locked step returns to the
	// filesystem (pages are 4KiB, so ~32MB). Reclamation holds the write lock, and
	// record() runs before go-mitmproxy replies to the client, so an unbounded
	// pass would stall the very requests being recorded.
	reclaimChunkPages = 8192
	// reclaimMergePages bounds the full-text merge done alongside each chunk.
	// Deleting from a contentless_delete index only writes tombstones; merging is
	// what discards them, and left undone the index grows on every deletion.
	reclaimMergePages = 256
	// reclaimMergeSteps bounds how many merges one reclamation performs. fts5
	// offers no way to ask whether an index has settled — its special INSERT
	// registers a row change of its own, so change counting cannot tell a real
	// merge from a no-op — so the budget is simply spent down, and whatever is
	// left over falls to the next deletion.
	reclaimMergeSteps = 16
	// reclaimMaxSteps backstops the loop. Both merging and incremental_vacuum are
	// documented to stop making progress eventually, but a reclamation that cannot
	// converge must give up rather than spin holding the write lock.
	reclaimMaxSteps = 512
	// reclaimBudget caps one background reclamation. Deleting a busy host can free
	// gigabytes, and the next deletion resumes wherever this one stopped.
	reclaimBudget = 5 * time.Minute
	// egressLogInterval rate-limits the "egress unreachable" log line, in seconds.
	// While an egress is down EVERY request through its listener fails with the
	// same error, so without this the journal would get one identical line per
	// request. The first failure (logged-at == 0) is always written.
	// recordQueueDepth absorbs a burst of concurrent responses without blocking them.
	// A full queue blocks (backpressure) rather than dropping a recorded exchange.
	recordQueueDepth  = 4096
	egressLogInterval = 60
	// egressProbeInterval throttles the active egress probe, in seconds. The probe
	// is what catches an egress death on the plaintext path, where go-mitmproxy
	// panics inside its own dial helper before any addon can report anything (see
	// sink.Requestheaders). Probing on every request would be wasteful; probing
	// never would leave that death invisible.
	egressProbeInterval = 30
	// egressProbeTimeout bounds one active probe, so a proxy that accepts TCP and
	// then says nothing costs one short-lived goroutine instead of a leak.
	egressProbeTimeout = 3 * time.Second
)

// TrafficSearchDescription is persisted into the tool catalog for new and
// upgraded installations. Keep it in the traffic package so the runtime tool
// and the catalog migration cannot drift apart.
const TrafficSearchDescription = "查询记录代理已抓取的目标流量（host 可选；支持裸主机、主机:端口或完整 URL，可再按 URL 子串或正文关键词过滤）。指定端口时只返回该服务的流量，避免同一 IP 的不同端口串包。body_contains 会在已抓取的请求/响应头与正文中做全文搜索，支持任意子串和中文（至少 3 个字符）；**证据常出现在代理端点（RCE/上传接口）的响应体里，此时应按证据关键串检索那条交换，而不是按证据所属主机检索**。默认按调用者所属任务限定范围，可用 task_id 覆盖。仅返回极轻量索引(id/method/url/status/resp_len + task_id/identity/egress)，不含响应内容；结果非空后必须用 traffic_get 逐条核实请求/响应，再把确实支持当前漏洞的 ID 交给 bind_finding_traffic。默认只返回 3 条、每页最多 10 条；结果多时用 page 翻页。"

// EgressState is the last observed health of one listener's upstream egress.
//
// It exists because an unreachable upstream is the ONE failure a client cannot
// see: on the plaintext-HTTP path go-mitmproxy's attack() panics before writing a
// status code, its own recover() eats the panic, and net/http then renders that
// silence as an empty 200 OK. The exchange never reaches the sink either, so it is
// not recorded and nothing survives anywhere. Reported so a dead tunnel/proxy is
// distinguishable from a genuinely empty resource.
type EgressState struct {
	OK        bool   `json:"ok"`
	Reason    string `json:"reason,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"` // unix seconds
}

// Traffic runs the recording proxy and owns the file tree + index.
// listener is one go-mitmproxy instance: its own TCP port and its own egress
// upstream, sharing the Traffic store (SQLite index, blobs, CA) with every other
// listener.
//
// Ports are what give each task an independent egress while still recording into
// ONE store. The alternative — one Traffic instance per egress — was rejected
// because the index is a single SQLite file: two *sql.DB handles onto it would
// contend on the write lock, and splitting the stores would put half the captured
// traffic beyond the reach of the traffic page and its agent tools.
type listener struct {
	id     string // "global", or "task:<id>"
	taskID int64  // 0 for the shared listener
	addr   string // fixed at creation: agents bake it into HTTP_PROXY, so it must not move
	proxy  *mproxy.Proxy
	// upstream is this listener's egress (nil = direct). Atomic so it can be
	// re-pointed at runtime without rebuilding the proxy; the next dial sees it.
	upstream atomic.Pointer[url.URL]
	// egress is this listener's upstream egress health, as last observed. It exists
	// because an unreachable upstream is the only failure the CLIENT cannot see: on
	// the plaintext-HTTP path go-mitmproxy's attack() panics, its own recover() eats
	// the panic, the ResponseWriter is never written, and net/http renders that
	// silence into an empty 200 OK — and the exchange never reaches the sink, so it
	// is not recorded either. Without this state an egress can be dead while the
	// platform looks perfectly healthy.
	egress atomic.Pointer[EgressState]
	// egressLoggedAt is the unix second of the last "egress unreachable" log line,
	// used to rate-limit it: while the egress is down every request through this
	// listener fails, and none of them deserves its own identical log line. Zero
	// means "never logged", so the first failure always gets through.
	egressLoggedAt atomic.Int64
	// egressProbedAt is the unix second of the last active probe of this listener's
	// upstream. Separate from egressLoggedAt because a probe may find the egress
	// healthy (nothing to log) and must still not be repeated on every request.
	egressProbedAt atomic.Int64
}

type Traffic struct {
	// identityFromUID 见 SetIdentityFromUID。
	identityFromUID func(uid int) string
	dir             string
	addr            string
	db              *sql.DB
	wmu             sync.Mutex // serializes writeExchange() vs DeleteHost (incl. blob GC)
	// Recording is off the response path: sink.Response only snapshots the flow and
	// enqueues, and one goroutine owns every SQLite write. See enqueue/recordLoop.
	recCh   chan pendingExchange
	recDone chan struct{}
	// recMu guards recShut/recCh so a send can never race the close in stopRecords.
	recMu   sync.RWMutex
	recShut bool
	// blobMu guards spill(): it writes blob files and derives their names, and it
	// used to run only under wmu on the recording path. enqueue calls it from many
	// connection goroutines at once, so it needs its own lock — sharing wmu would
	// put the response path back behind the SQLite transaction.
	blobMu sync.Mutex
	seq    atomic.Int64
	proxy  *mproxy.Proxy
	// fts reports whether the full-text index is available. False on a driver
	// build without FTS5: recording and metadata search still work, body search
	// degrades to unsupported rather than erroring.
	fts bool
	// reaping tracks background reclamation of legacy trees and index space, so
	// shutdown and tests can wait for it instead of racing it.
	reaping sync.WaitGroup
	// incrementalVacuum reports whether the index can return freed pages to the
	// filesystem on its own. False on a database created before this was the
	// default: PRAGMA incremental_vacuum is a silent no-op there, so deletions
	// reclaim nothing until an explicit full compaction converts the file.
	incrementalVacuum bool
	// reclaiming keeps a single background reclamation in flight. Concurrent ones
	// would only contend for wmu, never finish sooner.
	reclaiming atomic.Bool
	// closed is shut by Close so a reclamation abandons its remaining budget
	// instead of holding shutdown open for minutes. Nil on the zero value, which
	// stopping() treats as "not closing".
	closed    chan struct{}
	closeOnce sync.Once
	// pass is the set of hosts whose MITM interception failed for a proxy/protocol
	// reason; connections to them are tunneled transparently (fail-open) so the
	// request still reaches the target — unrecorded — instead of being killed.
	pass sync.Map // hostname(string) -> struct{}
	// egress is the DEFAULT outbound path every captured connection leaves through
	// (nil = direct dial). Both the intercepted and the transparent-passthrough
	// paths honor it (go-mitmproxy's getUpstreamConn), so no host escapes it.
	// Hot-swappable at runtime via SetUpstreamProxy/SetUpstreamDialer. An identity
	// bound with SetIdentityEgress overrides it for that identity's connections.
	egress atomic.Pointer[egress]
	// identities maps an authenticated identity to its own egress. Populated when a
	// task binds a tunnel; empty in a single-tenant install, where the default
	// egress above is all there is. sync.Map because connections look themselves up
	// from many goroutines while bindings change.
	identities sync.Map // identity(string) -> *identityEgress
	// identityCount mirrors len(identities) so diagnostics and the cheap "is anything
	// bound" checks do not walk the map.
	identityCount atomic.Int64
	// authOverride is WithAuthenticate's hook, when the caller supplied one. It wins
	// over the identity registry.
	authOverride func(user, pass string) (identity string, ok bool)
}

// SetIdentityFromUID 注入 uid → 身份的解析器（透明兜底：连接没有握手，只能靠 peer uid 认人）。
func (t *Traffic) SetIdentityFromUID(fn func(uid int) string) { t.identityFromUID = fn }

// egress is one outbound path: a URL proxy, an injected dialer (a task's tunnel,
// say), or direct when the holder itself is nil. Exactly one of url/dialer is set.
type egress struct {
	url    *url.URL
	dialer Dialer
	label  string
}

// identityEgress is the egress bound to one authenticated identity, plus the token
// that authenticates it and the task it belongs to, so the ledger can attribute a
// row without re-deriving either.
type identityEgress struct {
	token  string
	taskID int64
	egress *egress
}

// Dialer is an egress that opens connections itself, such as a task's in-process
// tunnel. Describe must be redacted (no credentials): the ledger records it as the
// answer to "where did this connection actually go".
type Dialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Describe() string
}

// Option configures the recording proxy at construction. Options are variadic
// so every existing two-argument Open call keeps compiling unchanged.
type Option func(*proxyConfig)

// proxyConfig collects the Option-settable knobs before the proxy is built.
type proxyConfig struct {
	authenticate func(user, pass string) (identity string, ok bool)
}

// WithAuthenticate identifies the client using the listener, for both ingresses:
// the SOCKS5 greeting (RFC 1929) and the HTTP Proxy-Authorization header. The
// returned identity is remembered per connection and handed to the egress layer,
// which is what lets one listener route different clients to different egresses.
// Return ok=false to reject the client.
//
// nil (the default) accepts anyone with an empty identity. The egress proxy's own
// credentials stay in the upstream URL and are never conflated with these.
func WithAuthenticate(fn func(user, pass string) (identity string, ok bool)) Option {
	return func(c *proxyConfig) { c.authenticate = fn }
}

// Open initializes the traffic tree, blob store and SQLite index under dir.
func Open(dir, addr string, opts ...Option) (*Traffic, error) {
	var cfg proxyConfig
	for _, o := range opts {
		o(&cfg)
	}
	for _, d := range []string{dir, filepath.Join(dir, "_index"), filepath.Join(dir, "_blobs"), filepath.Join(dir, "_ca")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// busy_timeout is a per-connection setting, so it belongs in the DSN rather
	// than in a one-off Exec: the pool opens connections on demand, and an Exec
	// only configures whichever one happened to serve it — leaving every other
	// connection to fail instantly the moment a writer holds the database.
	// The driver splits the DSN at the first '?', so a data directory containing
	// one would silently name a different file; that path falls back to a bare
	// DSN, where initIndex still applies the pragmas to its own connection.
	index := filepath.Join(dir, "_index", "index.sqlite")
	dsn := index
	if !strings.ContainsRune(index, '?') {
		dsn = "file:" + index + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	t := &Traffic{dir: dir, addr: addr, db: db, closed: make(chan struct{}), authOverride: cfg.authenticate}
	t.recCh = make(chan pendingExchange, recordQueueDepth)
	t.recDone = make(chan struct{})
	go t.recordLoop()
	if err := t.initIndex(); err != nil {
		db.Close()
		return nil, err
	}

	p, err := mproxy.NewProxy(&mproxy.Options{
		Addr:        addr,
		SslInsecure: true,
		CaRootPath:  filepath.Join(dir, "_ca"),
		// SOCKS5 shares this port: the first client byte selects the protocol.
		// A TLS CONNECT is MITM'd through the very same attacker/CA/addon
		// pipeline as an HTTP CONNECT; any other payload is relayed as raw TCP
		// through the upstream chosen below, and reported here as metadata.
		Authenticate: t.authenticate,
		// 透明兜底：连接由内核重定向而来、没有握手，只能靠 peer uid 认身份。
		IdentityFromUID: func(uid int) string {
			if t.identityFromUID == nil {
				return ""
			}
			return t.identityFromUID(uid)
		},
		EgressLabel: t.egressLabelFor,
		// Keep a bounded head of each direction for database ports only: that is
		// where the evidence is (handshake, first statements) and it keeps every
		// other relay allocation-free.
		Socks5CaptureBytes: socks5CaptureHeadBytes,
		Socks5CapturePorts: Socks5CapturePorts(),
		Socks5RawMeta: func(m mproxy.Socks5RawMeta) {
			// The relay finishes off the request path. Write in the background so
			// a busy index never delays a session teardown — recordSocks5Conn
			// takes no write lock of its own.
			service := classifySocks5Service(m.Port, m.HeadUp, m.HeadDown)
			go t.recordSocks5Conn(Socks5Conn{
				TS:          time.Now().Unix(),
				ListenerID:  GlobalListenerID,
				TaskID:      t.identityTaskID(m.Identity),
				Identity:    m.Identity,
				DstHost:     m.Host,
				DstPort:     m.Port,
				BytesUp:     m.BytesUp,
				BytesDown:   m.BytesDown,
				ViaUpstream: m.ViaUpstream,
				Egress:      m.Egress,
				Service:     service,
				HeadUp:      m.HeadUp,
				HeadDown:    m.HeadDown,
			})
		},
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	// Upstream selection. By default (no egress set) targets are dialed DIRECTLY:
	// go-mitmproxy's own default upstream uses http.ProxyFromEnvironment, so an
	// HTTP_PROXY/HTTPS_PROXY in the environment (a VPN/system proxy) would make it
	// forward target requests through that external proxy — which can't reach the
	// target → 502. Returning nil forces a direct dial. When a global egress proxy
	// IS configured (SetUpstreamProxy), every captured request — intercepted AND
	// transparently tunneled — is forwarded through it instead, so no host leaks
	// the real source IP. An injected dialer (SetUpstreamDialer) takes precedence
	// and is what go-mitmproxy consults first.
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return t.upstreamURL(), nil })
	// No dialer hook yet: go-mitmproxy treats a non-nil one as "the dialer owns the
	// egress", so installing it here would disable the URL upstream above.
	// SetUpstreamDialer installs and clears it as the egress changes.
	// Fail-open: MITM every host by default, EXCEPT ones a prior request proved we
	// can't intercept without breaking (see maybePassthrough). Those are tunneled
	// transparently so the request still reaches the target instead of being killed.
	p.SetShouldInterceptRule(func(req *http.Request) bool {
		_, tunnel := t.pass.Load(hostOnly(req.Host))
		return !tunnel
	})
	p.AddAddon(&sink{t: t})
	t.proxy = p
	return t, nil
}

// initIndex applies the schema on a single pinned connection. Pinning is what
// makes auto_vacuum reliable: it can only be set while the database still holds
// no tables, and only the VACUUM that follows writes it into the file header —
// two steps a pooled *sql.DB is free to route to different connections, which
// would silently drop the setting.
//
// auto_vacuum=incremental is what lets a deletion hand freed pages back to the
// filesystem. Without it SQLite merely chains them onto its freelist, so the
// index file never shrinks no matter how much traffic is deleted — and since
// every body below maxInlineBody lives in that file, plus a trigram index
// roughly twice the size of the text it covers, a capture-heavy install ends up
// holding gigabytes for traffic it no longer has. On a database that already has
// tables the pragma is a documented no-op, so installs created before this keep
// auto_vacuum=0 until a full compaction converts the file; incrementalVacuum
// records that so reclaim can say so instead of pretending to reclaim.
func (t *Traffic) initIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Re-applied rather than left to the DSN so the bare-DSN fallback in Open is
	// still correct: journal_mode persists in the file header, which is what every
	// later connection reads.
	for _, p := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	var tables int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		for _, p := range []string{`PRAGMA auto_vacuum=incremental`, `VACUUM`} {
			if _, err := conn.ExecContext(ctx, p); err != nil {
				return err
			}
		}
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	t.incrementalVacuum = mode == autoVacuumIncremental
	if !t.incrementalVacuum {
		log.Printf("[traffic] 索引库未启用增量回收（auto_vacuum=%d）：删除流量不会缩小 index.sqlite，需要执行一次存储压缩来转换", mode)
	}
	if _, err := conn.ExecContext(ctx, indexSchema); err != nil {
		return err
	}
	// Attribution columns added after the first release: CREATE TABLE IF NOT EXISTS
	// never alters an existing table, so an install created before them would keep
	// the old shape and every INSERT (which now lists them) would fail — the same
	// reason the SOCKS5 ledger migrates its egress/identity columns here.
	for _, col := range []struct{ name, decl string }{
		{"task_id", `INTEGER NOT NULL DEFAULT 0`},
		{"identity", `TEXT NOT NULL DEFAULT ''`},
		{"egress", `TEXT NOT NULL DEFAULT ''`},
	} {
		if err := addColumnIfMissing(ctx, conn, "exchanges", col.name, col.decl); err != nil {
			return err
		}
	}
	// The attribution index is created here, not in indexSchema: on an existing
	// database that statement would run before the ALTER above and fail on the
	// missing column, taking the whole index (and capture) down with it.
	if _, err := conn.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_ex_task ON exchanges(task_id)`); err != nil {
		return err
	}
	// The SOCKS5 ledger is independent of the full-text index, so it is applied
	// before the FTS attempt: a driver build without FTS5 must still record
	// raw-TCP connections.
	if err := t.initSocks5Schema(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, ftsSchema); err != nil {
		log.Printf("[traffic] 全文索引不可用，正文搜索将被禁用（元数据搜索不受影响）：%v", err)
		return nil
	}
	t.fts = true
	return nil
}

// hostOnly strips an optional :port, so passthrough keys match whether the host
// arrives as "example.com:443" (CONNECT) or "example.com" (request URL).
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// hostPort is the address clients should dial. A bare ":port" means "bind all
// interfaces" (legacy default), so it is mapped to loopback: a client on this
// host cannot portably reach 0.0.0.0, and the recorder is a local egress anyway.
func (t *Traffic) hostPort() string {
	if strings.HasPrefix(t.addr, ":") {
		return "127.0.0.1" + t.addr
	}
	return t.addr
}

// ProxyAddr returns the URL workers set as HTTP(S)_PROXY.
func (t *Traffic) ProxyAddr() string { return "http://" + t.hostPort() }

// SocksAddr returns the same listener's SOCKS5 URL. The ingress shares the port
// (see traffic/socks5.go), so this differs from ProxyAddr only in scheme — and
// it is socks5h rather than socks5 on purpose: the point of routing through the
// egress is to have the far side resolve target names, since a client-side
// lookup would both leak DNS and fail for internal-only names.
func (t *Traffic) SocksAddr() string { return "socks5h://" + t.hostPort() }

// SetUpstreamProxy points every captured request at a default egress proxy
// (http/https/socks5, optional user:pass in the URL). An empty raw string clears
// it, restoring direct dialing. The change is atomic and takes effect on the next
// connection — no restart, no proxy rebuild. go-mitmproxy dials all three schemes
// itself, so socks5 works uniformly here regardless of the target tool.
//
// Setting a URL proxy replaces any default egress dialer. An identity bound with
// SetIdentityEgress still overrides both, for its own connections only.
func (t *Traffic) SetUpstreamProxy(raw string) error {
	if strings.TrimSpace(raw) == "" {
		t.applyEgress(nil)
		return nil
	}
	u, err := ValidateProxyURL(raw)
	if err != nil {
		return err
	}
	t.applyEgress(&egress{url: u, label: redactProxyURL(u)})
	return nil
}

// SetUpstreamDialer makes an egress dialer (a task's in-process tunnel, say) the
// DEFAULT outbound path, replacing any URL proxy. A nil dialer clears it, restoring
// direct dialing. Like SetUpstreamProxy the swap is atomic and applies to the next
// connection.
func (t *Traffic) SetUpstreamDialer(d Dialer) {
	if d == nil {
		t.applyEgress(nil)
		return
	}
	t.applyEgress(&egress{dialer: d, label: d.Describe()})
	t.syncUpstreamKeepAlive()
}

// SetIdentity registers or refreshes an identity's credentials and task, leaving any
// egress bound to it alone. This is what a task registration uses: agents are rebuilt
// (and so re-registered) far more often than a tunnel is bound, and a rebuild must not
// silently unbind the task's tunnel.
func (t *Traffic) SetIdentity(identity, token string, taskID int64) {
	if strings.TrimSpace(identity) == "" {
		return
	}
	existing := t.identityEgressFor(identity)
	ie := &identityEgress{token: token, taskID: taskID}
	if existing != nil {
		ie.egress = existing.egress
	}
	if _, loaded := t.identities.Swap(identity, ie); !loaded {
		t.identityCount.Add(1)
	}
}

// SetIdentityEgress registers an identity authenticated by token, bound to taskID,
// and optionally gives it its own egress d. Connections whose client presented that
// credential leave through d; everything else — the default egress, and every other
// identity — is unaffected, which is what makes a tunnel a per-task decision rather
// than a platform-wide one.
//
// A nil d is meaningful and is not the same as ClearIdentityEgress: the identity is
// still known and authenticated, and its traffic is still attributed to taskID, but
// it uses the default egress. Registering every task this way keeps the ledger
// attribution complete while only the tasks that need a tunnel get one.
//
// Per-identity egress is dialer-only by design: a URL proxy would have to be applied
// inside the routing hook, and the CONNECT belongs to dialUpstream.
func (t *Traffic) SetIdentityEgress(identity, token string, taskID int64, d Dialer) {
	if strings.TrimSpace(identity) == "" {
		return
	}
	ie := &identityEgress{token: token, taskID: taskID}
	if d != nil {
		ie.egress = &egress{dialer: d, label: d.Describe()}
	}
	if _, loaded := t.identities.Swap(identity, ie); !loaded {
		t.identityCount.Add(1)
	}
	t.syncDialer()
	t.syncUpstreamKeepAlive()
}

// ClearIdentityEgress drops an identity's binding, so its connections fall back to
// the default egress.
func (t *Traffic) ClearIdentityEgress(identity string) {
	if _, loaded := t.identities.LoadAndDelete(identity); loaded {
		t.identityCount.Add(-1)
	}
	t.syncDialer()
	t.syncUpstreamKeepAlive()
}

// identityEgressFor returns the binding for an identity, or nil.
func (t *Traffic) identityEgressFor(identity string) *identityEgress {
	if identity == "" {
		return nil
	}
	v, ok := t.identities.Load(identity)
	if !ok {
		return nil
	}
	e, _ := v.(*identityEgress)
	return e
}

// identityTaskID is the task an identity belongs to, for ledger attribution.
func (t *Traffic) identityTaskID(identity string) int64 {
	if e := t.identityEgressFor(identity); e != nil {
		return e.taskID
	}
	return 0
}

// authenticate validates a client against the identity registry.
//
// A client that presents no credentials keeps the default egress. The platform has
// its own paths that reach this listener anonymously — the http custom tool's
// use_recording_proxy builds an in-process Transport with no credentials, and an
// MCP server is handed the address as a --proxy-server argument — and none of them
// may break because some task bound a tunnel.
//
// Credentials, once presented, must name a known identity: a revoked or mistyped
// task must not silently fall back to the default egress, which is exactly how
// traffic ends up leaving through an egress nobody chose for it.
func (t *Traffic) authenticate(user, pass string) (string, bool) {
	if t.authOverride != nil {
		return t.authOverride(user, pass)
	}
	if user == "" && pass == "" {
		return "", true
	}
	e := t.identityEgressFor(user)
	if e == nil || e.token == "" || subtle.ConstantTimeCompare([]byte(e.token), []byte(pass)) != 1 {
		log.Printf("[traffic] 拒绝无法识别的代理凭据 identity=%q（已绑定的任务出口 %d 个）", user, t.identityLen())
		return "", false
	}
	return user, true
}

// identityLen counts registered identities, for diagnostics.
func (t *Traffic) identityLen() int { return int(t.identityCount.Load()) }

// routeDialer is the egress hook the listener consults for every connection while
// some dialer exists. It resolves the connection's authenticated identity to its own
// egress and hands connections it does not own back to the default path (upstream
// proxy URL, or a direct dial) via ErrEgressNotHandled.
func (t *Traffic) routeDialer(ctx context.Context, req *http.Request, network, address string) (net.Conn, error) {
	identity := mproxy.IdentityFromContext(ctx)
	if e := t.identityEgressFor(identity); e != nil && e.egress != nil {
		log.Printf("[traffic] 出口路由 %s -> 身份 %q 的隧道", address, identity)
		return e.egress.dialer.Dial(ctx, address)
	}
	if g := t.egress.Load(); g != nil && g.dialer != nil {
		log.Printf("[traffic] 出口路由 %s -> 身份 %q 无隧道，用默认拨号器", address, identity)
		return g.dialer.Dial(ctx, address)
	}
	log.Printf("[traffic] 出口路由 %s -> 身份 %q 无隧道，交回默认路径（URL 代理或直连）", address, identity)
	return nil, mproxy.ErrEgressNotHandled
}

// egressLabelFor names the egress for one connection: the identity's own binding
// when it has one, otherwise the default. It always answers, so the ledger never
// falls back to naming the router itself.
func (t *Traffic) egressLabelFor(ctx context.Context, req *http.Request) string {
	if e := t.identityEgressFor(mproxy.IdentityFromContext(ctx)); e != nil && e.egress != nil {
		return e.egress.label
	}
	return t.EgressLabel()
}

// syncDialer installs the routing hook exactly while some dialer exists and clears
// it otherwise: go-mitmproxy treats a non-nil dialer hook as "the dialer owns the
// egress", so installing it speculatively would take the URL upstream off its
// original mechanism for installs that never bind a tunnel.
// tunnelEgress marks a slot-limited egress (a tunnel with very few concurrent
// connections). Structural, so traffic need not import the tunnel package.
type tunnelEgress interface{ TunnelEgress() bool }

// syncUpstreamKeepAlive stops the listener's transports from pooling upstream
// connections while ANY egress it may use is slot-limited. An idle pooled
// connection keeps holding a tunnel slot until the peer times it out, which is
// how a tunnel ends up refusing every new connection after a few requests.
// Conservative by design: disabling reuse on a listener that also serves direct
// traffic costs a little efficiency, never correctness.
func (t *Traffic) syncUpstreamKeepAlive() {
	if t.proxy == nil || t.proxy.Opts == nil {
		return
	}
	t.proxy.Opts.DisableUpstreamKeepAlive.Store(t.hasTunnelEgress())
}

func (t *Traffic) hasTunnelEgress() bool {
	isTunnel := func(e *egress) bool {
		if e == nil || e.dialer == nil {
			return false
		}
		te, ok := e.dialer.(tunnelEgress)
		return ok && te.TunnelEgress()
	}
	if isTunnel(t.egress.Load()) {
		return true
	}
	found := false
	t.identities.Range(func(_, v any) bool {
		if ie, ok := v.(*identityEgress); ok && isTunnel(ie.egress) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (t *Traffic) syncDialer() {
	if t.proxy == nil {
		return
	}
	if !t.anyDialer() {
		t.proxy.SetUpstreamDialer(nil, "")
		return
	}
	// An empty label on purpose: the router is not an egress, so nothing may be
	// labelled after it. EgressLabel names each connection instead.
	t.proxy.SetUpstreamDialer(t.routeDialer, "")
}

// anyDialer reports whether any dialer egress is bound, as the default or to an
// identity. Identities registered without one do not need the routing hook.
func (t *Traffic) anyDialer() bool {
	if e := t.egress.Load(); e != nil && e.dialer != nil {
		return true
	}
	found := false
	t.identities.Range(func(_, v any) bool {
		if ie, ok := v.(*identityEgress); ok && ie.egress != nil && ie.egress.dialer != nil {
			found = true
			return false
		}
		return true
	})
	return found
}

// applyEgress swaps the default outbound path and re-syncs the dialer hook.
func (t *Traffic) applyEgress(e *egress) {
	t.egress.Store(e)
	t.syncDialer()
	t.syncUpstreamKeepAlive()
}

// upstreamURL is the URL form of the current egress: nil when it is a dialer (the
// dialer hook owns the egress then) or when nothing is configured, which makes
// go-mitmproxy dial the target directly.
func (t *Traffic) upstreamURL() *url.URL {
	if e := t.egress.Load(); e != nil {
		return e.url
	}
	return nil
}

// IdentityEgressLabel names the egress bound to one identity, "" when it has none
// (its traffic uses the default egress). The API and the ledger both need to answer
// "where does this task's traffic actually go".
func (t *Traffic) IdentityEgressLabel(identity string) string {
	if e := t.identityEgressFor(identity); e != nil && e.egress != nil {
		return e.egress.label
	}
	return ""
}

// EgressLabel names the current outbound path for logs and the API: "" for a
// direct dial, the redacted proxy URL, or the dialer's own description.
func (t *Traffic) EgressLabel() string {
	if e := t.egress.Load(); e != nil {
		return e.label
	}
	return ""
}

// redactProxyURL renders a proxy URL without its userinfo: labels reach logs and
// the ledger, where credentials must never appear.
func redactProxyURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	return c.String()
}

// ValidateProxyURL parses and checks a proxy URL (http/https/socks5, optional
// user:pass), returning the parsed URL. Exposed so callers can validate a global
// proxy before persisting it even when the traffic proxy itself is disabled.
func ValidateProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("解析代理地址 %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	case "":
		return nil, fmt.Errorf("代理 %q 缺少协议(用 http://、https:// 或 socks5://)", raw)
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q(用 http、https 或 socks5)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("代理 %q 缺少主机地址", raw)
	}
	return u, nil
}

// CACertPath returns the PEM CA cert clients must trust to verify HTTPS through
// the MITM proxy (go-mitmproxy writes it here on first start).
func (t *Traffic) CACertPath() string {
	return filepath.Join(t.dir, "_ca", "mitmproxy-ca-cert.pem")
}

// Start runs the proxy (blocking); run in a goroutine.
func (t *Traffic) Start() error { return t.proxy.Start() }

// Close waits for background tree reclamation to finish before closing the
// index, so shutdown never leaves a goroutine unlinking files out from under a
// removed data directory. Index-space reclamation is signalled to stop first:
// it holds a whole minutes-long budget, and finishing it is never worth delaying
// shutdown for — the next deletion resumes it.
func (t *Traffic) Close() error {
	if t.closed != nil {
		t.closeOnce.Do(func() { close(t.closed) })
	}
	// Drain accepted exchanges before the DB handle goes away.
	t.stopRecords()
	t.reaping.Wait()
	return t.db.Close()
}

// stopping reports whether Close has been called. A nil channel (the zero value)
// is never ready, so this reads as "not closing" without a separate guard.
func (t *Traffic) stopping() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
func (t *Traffic) DB() *sql.DB { return t.db }

// sink is the go-mitmproxy addon that records completed exchanges.
type sink struct {
	mproxy.BaseAddon
	t *Traffic
}

func (s *sink) Response(f *mproxy.Flow) {
	if f.Request == nil || f.Response == nil {
		return
	}
	s.t.enqueue(f)
}

// RequestError fires when a request through an established MITM tunnel fails. If
// the failure looks proxy/protocol-caused (h2 quirks, HEAD-with-body, protocol
// errors) — not a plain target-unreachable error — we flag the host for
// transparent passthrough so future requests to it succeed instead of dying.
func (s *sink) RequestError(f *mproxy.Flow, err error) { s.t.maybePassthrough(f, err) }

// maybePassthrough marks a host to be tunneled transparently on the next
// connection, but only for errors the proxy itself caused — a target that is
// simply down/filtered would fail without us too, and must stay MITM'd+recorded.
func (t *Traffic) maybePassthrough(f *mproxy.Flow, err error) {
	if err == nil || f == nil || f.Request == nil || f.Request.URL == nil || !proxyCausedErr(err) {
		return
	}
	host := f.Request.URL.Hostname()
	if host == "" {
		return
	}
	if _, loaded := t.pass.LoadOrStore(host, struct{}{}); !loaded {
		log.Printf("[traffic] 与 %s 的 MITM 出错，改为透传（该 host 后续直连目标、不再记录，但请求照常）：%v", host, err)
	}
}

// proxyCausedErr reports whether err indicates the interception layer (not the
// target) is at fault — HTTP/2 handling, HEAD-with-body, or a protocol violation.
func proxyCausedErr(err error) bool {
	s := strings.ToLower(err.Error())
	for _, p := range []string{"head request", "http2", "http/2", "protocol error", "protocol_error", "malformed"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// pendingExchange is one completed exchange, snapshotted off the flow. The proxy
// reuses Flow objects once an addon returns, so every field recording needs — the
// header text and the body bytes included — is copied while it is still valid.
type pendingExchange struct {
	id, host, method, tmpl, url string
	reqHead, respHead           string
	reqCT, contentType          string
	identity, egress            string
	ts                          int64
	status, reqLen, respLen     int
	taskID                      int64
	reqBody, respBody           []byte
	// done is set only on a FlushRecords barrier; the writer closes it instead of
	// persisting anything.
	done chan struct{}
}

// enqueue hands a completed exchange to the writer. It runs on the response path,
// so it only snapshots. Everything that touches SQLite or the blob store happens in
// recordLoop: doing it here serialised every concurrent response behind one write
// lock (measured: 100 parallel requests, p50 ~2.4s against 3.5ms direct).
func (t *Traffic) enqueue(f *mproxy.Flow) {
	if f == nil || f.Request == nil || f.Response == nil || f.Request.URL == nil {
		return
	}
	identity := ""
	if f.ConnContext != nil {
		identity = f.ConnContext.Identity
	}
	// Where this exchange actually left: the identity own egress (a task tunnel) when
	// it has one, otherwise the listener-level upstream (global_proxy). Same rule as
	// the raw-TCP ledger, so proxied-or-direct is answerable per row, not per listener.
	egress := t.IdentityEgressLabel(identity)
	if egress == "" {
		egress = t.EgressLabel()
	}
	n := t.seq.Add(1)
	now := time.Now()
	pe := pendingExchange{
		id:          fmt.Sprintf("%d-%04d", now.Unix(), n%10000),
		ts:          now.Unix(),
		host:        f.Request.URL.Hostname(),
		method:      f.Request.Method,
		tmpl:        db.TemplatePath(f.Request.URL.EscapedPath()),
		url:         f.Request.URL.String(),
		reqHead:     fmt.Sprintf("%s %s %s\n%s", f.Request.Method, f.Request.URL.RequestURI(), f.Request.Proto, requestHeaderLines(f.Request)),
		respHead:    fmt.Sprintf("HTTP %d\n%s", f.Response.StatusCode, headerLines(f.Response.Header)),
		reqCT:       f.Request.Header.Get("Content-Type"),
		contentType: f.Response.Header.Get("Content-Type"),
		status:      f.Response.StatusCode,
		reqLen:      len(f.Request.Body),
		respLen:     len(f.Response.Body),
		identity:    identity,
		taskID:      t.identityTaskID(identity),
		egress:      egress,
		reqBody:     append([]byte(nil), f.Request.Body...),
		respBody:    append([]byte(nil), f.Response.Body...),
	}
	if t.recCh == nil {
		// Zero-value Traffic (tests): no writer goroutine, record inline.
		t.record(pe)
		return
	}
	t.recMu.RLock()
	defer t.recMu.RUnlock()
	if t.recShut {
		return
	}
	t.recCh <- pe
}

// recordLoop is the single writer: one exchange at a time, in arrival order.
func (t *Traffic) recordLoop() {
	defer close(t.recDone)
	for pe := range t.recCh {
		if pe.done != nil {
			close(pe.done) // a FlushRecords barrier: nothing to persist
			continue
		}
		t.record(pe)
	}
}

// stopRecords drains the queue, so shutdown never drops an accepted exchange.
func (t *Traffic) stopRecords() {
	if t.recCh == nil || t.recDone == nil {
		return
	}
	t.recMu.Lock()
	if !t.recShut {
		t.recShut = true
		close(t.recCh)
	}
	t.recMu.Unlock()
	<-t.recDone
}

// FlushRecords blocks until everything enqueued so far is persisted. Recording is
// asynchronous, so a caller that must observe a record immediately uses this.
func (t *Traffic) FlushRecords() {
	if t.recCh == nil || t.recDone == nil {
		return
	}
	done := make(chan struct{})
	t.recMu.RLock()
	if t.recShut {
		t.recMu.RUnlock()
		return
	}
	t.recCh <- pendingExchange{done: done}
	t.recMu.RUnlock()
	<-done
}

// record persists one exchange entirely in SQLite: metadata, bodies and the
// full-text index. Nothing is written to a per-request directory — only bodies
// above maxInlineBody spill to the content-addressed blob store.
func (t *Traffic) record(pe pendingExchange) {
	// The write lock covers blob + index writes, so DeleteHost (and its blob GC)
	// can run under the same lock without racing a concurrent record.
	t.wmu.Lock()
	defer t.wmu.Unlock()

	// Bodies are spilled before the transaction opens: blob writes are filesystem
	// work and must not sit inside the SQLite write lock.
	reqB := t.spill(pe.reqBody, pe.reqCT)
	respB := t.spill(pe.respBody, pe.contentType)

	tx, err := t.db.Begin()
	if err != nil {
		log.Printf("[traffic] 记录 %s 失败（开启事务）：%v", pe.url, err)
		return
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	res, err := tx.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path,task_id,identity,egress)
VALUES(?,?,?,?,?,?,?,?,?,?,'',?,?,?)`,
		pe.id, pe.ts, pe.host, pe.method, pe.tmpl, pe.url, pe.status, pe.contentType,
		pe.reqLen, pe.respLen, pe.taskID, pe.identity, pe.egress)
	if err != nil {
		log.Printf("[traffic] 记录 %s 失败（写索引）：%v", pe.url, err)
		return
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		log.Printf("[traffic] 记录 %s 失败（取 rowid）：%v", pe.url, err)
		return
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`,
		pe.id, pe.reqHead, reqB.inline, nullIfEmpty(reqB.hash), pe.respHead, respB.inline, nullIfEmpty(respB.hash)); err != nil {
		log.Printf("[traffic] 记录 %s 失败（写正文）：%v", pe.url, err)
		return
	}

	for _, h := range []string{reqB.hash, respB.hash} {
		if h == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, pe.id); err != nil {
			log.Printf("[traffic] 记录 %s 失败（登记 blob 引用）：%v", pe.url, err)
			return
		}
	}

	if t.fts {
		// The index is fed from memory, so a body that spilled to _blobs is still
		// fully searchable even though only its preview is stored inline.
		idx := strings.Join([]string{pe.url, pe.reqHead, reqB.index, pe.respHead, respB.index}, "\n")
		if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			log.Printf("[traffic] 记录 %s 失败（写全文索引）：%v", pe.url, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[traffic] 记录 %s 失败（提交）：%v", pe.url, err)
	}
}

// storedBody is one body after the inline/spill decision: inline is what goes in
// the SQLite column (the whole body, or a preview when spilled), hash names the
// blob when it spilled, and index is the text handed to FTS (empty for binary).
type storedBody struct {
	inline []byte
	hash   string
	index  string
}

// spillUnderWriteLock keeps spill() where it has always run: under wmu, the same
// lock that serialises recording versus DeleteHost and its blob GC.
func (t *Traffic) spillUnderWriteLock(body []byte, contentType string) storedBody {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	return t.spill(body, contentType)
}

// spill decides where one body lives. Small bodies stay inline. Large ones are
// written to the content-addressed store and keep a readable preview inline so a
// reader can identify them without fetching the blob. Either way, text bodies
// are handed to the full-text index in full (up to maxIndexBody) — indexing is
// independent of where the bytes end up.
func (t *Traffic) spill(body []byte, contentType string) storedBody {
	if len(body) == 0 {
		return storedBody{}
	}
	text := !isBinaryBody(contentType, body)
	indexText := func() string {
		if !text {
			return ""
		}
		return string(clipBytes(body, maxIndexBody))
	}
	if len(body) <= maxInlineBody {
		return storedBody{inline: body, index: indexText()}
	}

	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	// One bucket level (256 buckets) is enough to keep any single directory small;
	// the store only ever holds bodies above maxInlineBody, deduplicated by hash.
	blobDir := filepath.Join(t.dir, "_blobs", "sha256", h[:2])
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		log.Printf("[traffic] 创建 blob 目录失败：%v", err)
		return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
	}
	blobPath := filepath.Join(blobDir, h+".bin")
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		if err := os.WriteFile(blobPath, body, 0o644); err != nil {
			log.Printf("[traffic] 写 blob %s 失败：%v", h, err)
			return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
		}
	}
	sb := storedBody{hash: h, index: indexText()}
	if text {
		sb.inline = []byte(truncateUTF8(body, blobPreview))
	} else {
		sb.inline = []byte(binaryTag(contentType, body))
	}
	return sb
}

// binaryTypes are content-type prefixes whose bodies are never worth indexing or
// previewing as text. Anything not listed is treated as text (with a NUL-byte
// check as backstop), so unusual-but-searchable types like application/sql or a
// bare text/* are not silently dropped from the index.
var binaryTypes = []string{
	"image/", "audio/", "video/", "font/",
	"application/octet-stream", "application/zip", "application/gzip",
	"application/x-gzip", "application/x-tar", "application/x-7z-compressed",
	"application/x-rar", "application/pdf", "application/x-msdownload",
	"application/vnd.android.package-archive", "application/java-archive",
	"application/wasm", "application/x-shockwave-flash",
}

func isBinaryBody(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, p := range binaryTypes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	// Backstop for mislabeled or absent content types: real text does not carry
	// NUL bytes, so a NUL in the head of the body means binary regardless.
	return bytes.IndexByte(clipBytes(body, 512), 0) >= 0
}

// binaryTag describes a spilled binary body in one line, including the leading
// magic bytes so a reader can recognize the format without downloading it.
func binaryTag(contentType string, body []byte) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		ct = "application/octet-stream"
	}
	magic := hex.EncodeToString(clipBytes(body, 4))
	return fmt.Sprintf("[binary %s, %d bytes, magic=%s]", ct, len(body), magic)
}

func clipBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// truncateUTF8 cuts b to at most n bytes without splitting a multi-byte rune,
// so a preview never ends in half a CJK character.
func truncateUTF8(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	b = b[:n]
	// A rune is at most 4 bytes, so backing off 3 bytes always finds the boundary
	// (unless the input was already invalid UTF-8, in which case we keep the cut).
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		if r, size := utf8.DecodeLastRune(b); r != utf8.RuneError || size != 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func headerLines(h map[string][]string) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// requestHeaderLines restores the HTTP Host header, which net/http stores on
// Request.Host rather than in Header. Keeping it in request.http makes the raw
// capture complete and directly replayable.
func requestHeaderLines(req *mproxy.Request) string {
	headers := req.Header.Clone()
	headers.Del("Host")
	host := req.URL.Host
	if raw := req.Raw(); raw != nil && strings.TrimSpace(raw.Host) != "" {
		host = raw.Host
	}
	var b strings.Builder
	if host = strings.TrimSpace(host); host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteByte('\n')
	}
	b.WriteString(headerLines(headers))
	return b.String()
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	out := r.Replace(s)
	if out == "" || out == "_" {
		return "root"
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

var blobHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// blobPath locates a stored blob. Current writes use one bucket level; blobs
// written before that change used two, so both layouts are probed rather than
// migrated.
func (t *Traffic) blobPath(hash string) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	// Validated as pure hex before touching the filesystem, so a crafted hash can
	// never traverse out of the blob directory.
	if !blobHashRe.MatchString(hash) {
		return "", fmt.Errorf("非法的 blob hash")
	}
	for _, p := range []string{
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin"),
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("blob %s 不存在", hash)
}

// Blob opens a spilled body for streaming; the caller must close the file.
// Streaming matters here: the driver exposes no incremental BLOB API, so keeping
// large bodies on disk is what lets them be served without loading them whole.
func (t *Traffic) Blob(hash string) (*os.File, int64, error) {
	p, err := t.blobPath(hash)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// BlobRange reads at most length bytes of a blob from offset, and reports the
// blob's total size. Used by the agent tool to page through a large body without
// pulling all of it into the model's context.
func (t *Traffic) BlobRange(hash string, offset, length int64) (data []byte, total int64, err error) {
	f, size, err := t.Blob(hash)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if offset < 0 {
		offset = 0
	}
	if offset >= size {
		return nil, size, nil
	}
	if length <= 0 || offset+length > size {
		length = size - offset
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, size, err
	}
	return buf[:n], size, nil
}

// ExchangeMeta is one row of the index (returned by Search).
type ExchangeMeta struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	RespLen     int    `json:"resp_len"`
	Path        string `json:"path"`
	// TaskID/Identity/Egress say which task this exchange belongs to and which
	// egress the connection left through ("" = the default egress / direct for an
	// anonymous connection). They are what makes a tunnelled internal request
	// distinguishable from a direct one in the traffic view.
	TaskID   int64  `json:"task_id"`
	Identity string `json:"identity"`
	Egress   string `json:"egress"`
}

// Search returns paged exchange metadata (never bodies).
func (t *Traffic) Search(host string, page, size int) ([]ExchangeMeta, error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path,task_id,identity,egress FROM exchanges`
	args := []any{}
	if host != "" {
		q += ` WHERE host=?`
		args = append(args, host)
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, size, page*size)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path, &m.TaskID, &m.Identity, &m.Egress); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ftsFilter builds the SQL condition restricting rows to those whose indexed
// text matches term. ok is false when full-text search cannot serve the term —
// no FTS index on this build, or fewer than three characters, which the trigram
// tokenizer cannot match — leaving callers to fall back to metadata matching.
func (t *Traffic) ftsFilter(term string) (cond string, arg any, ok bool) {
	term = strings.TrimSpace(term)
	if !t.fts || utf8.RuneCountInString(term) < minTrigram {
		return "", nil, false
	}
	return `rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)`, ftsQuote(term), true
}

// ftsQuote wraps a term as an FTS5 string literal so that punctuation and query
// operators inside it (quotes, AND/OR/NEAR, *, ^) are matched literally instead
// of being parsed as query syntax.
func ftsQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// PageQuery bundles the optional filters and sort order for Page. Every filter
// is combined with AND; an empty string skips that filter, and RespMin/RespMax
// of -1 skip the response-size bounds. An empty Sort/Order defaults to
// newest-first by timestamp.
type PageQuery struct {
	Host    string // host substring
	Method  string // exact method (case-insensitive)
	Query   string // broad search box: metadata columns OR captured text
	Body    string // content box: captured request/response text only (full-text)
	Path    string // url_template substring — the vulnerability's path
	Status  string // exact code ("404") or class bucket ("4xx")
	RespMin *int64 // minimum resp_len; nil = unset（0 是合法下界，不能用零值当"未设置"）
	RespMax *int64 // maximum resp_len; nil = unset
	// RespMin/RespMax 是指针：nil=不筛。曾经用 >=0 表示"已设置"，于是零值 PageQuery
	// 变成 resp_len==0（几乎匹配不到任何行）——这个坑踩过两次，改成指针后不复存在。
	Sort  string // ts | status | resp_len (default ts)
	Order string // asc | desc (default desc)
	// Attributed-egress filters for the traffic page drill-down. Zero values mean no
	// filter at all.
	TaskID int64 // exact task id
	// Unattributed 只看"没有任务归属"的行（task_id=0）：平台自身 / 没有任务上下文的流量。
	// 不能用 TaskID=0 表达这个意思——零值在那里等于"没填筛选"。
	Unattributed bool
	// TCPWithBody 只看"保存了正文的裸 TCP"（识别出的数据库协议）。它只在合并视图里有意义：
	// 交换表的正文是 HTTP 报文，不属于这个筛选。
	TCPWithBody bool
	Identity    string // exact identity
	Egress      string // egress substring, e.g. socks5 or regeorg
}

// sortColumns whitelists the columns Page may order by, so the caller-supplied
// Sort can never reach the SQL as anything but one of these fixed names.
var sortColumns = map[string]string{"ts": "ts", "status": "status", "resp_len": "resp_len"}

// statusFilter turns a status token into a SQL condition: an exact code ("404")
// matches that status, an "Nxx" class ("4xx") matches the whole hundreds band.
// ok is false for an empty or unrecognized token.
func statusFilter(s string) (cond string, args []any, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil, false
	}
	if len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] == 'x' && s[2] == 'x' {
		base := int(s[0]-'0') * 100
		return "status>=? AND status<?", []any{base, base + 100}, true
	}
	if n, err := strconv.Atoi(s); err == nil {
		return "status=?", []any{n}, true
	}
	return "", nil, false
}

// Page returns one page of exchange metadata for the traffic list, filtered by
// the criteria in f (all optional, combined with AND) and ordered by the
// requested column. Query is the broad search box (metadata columns OR, when the
// term is long enough for the trigram index, captured request/response text);
// Body narrows to exchanges whose captured text matches, via that same index.
// Also returns the total number of rows matching the filter (for the UI's
// pagination). Bodies are never included in the rows.
func (t *Traffic) Page(f PageQuery, page, size int) (rows []ExchangeMeta, total int, err error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	if page < 0 {
		page = 0
	}
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
	if id := strings.TrimSpace(f.Identity); id != "" {
		add("identity=?", id)
	}
	switch e := strings.TrimSpace(f.Egress); {
	case e == "" || strings.EqualFold(e, "all"):
	case strings.EqualFold(e, "direct"):
		// 直连：出口标签为空。
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
		const meta = "host LIKE ? OR url LIKE ? OR url_template LIKE ? OR method LIKE ? OR content_type LIKE ? OR CAST(status AS TEXT) LIKE ?"
		// Metadata match OR full-text match: one search box, widest recall. Terms
		// too short for trigram silently fall back to metadata only.
		if cond, arg, ok := t.ftsFilter(s); ok {
			add("(("+meta+") OR "+cond+")", like, like, like, like, like, like, arg)
		} else {
			add("("+meta+")", like, like, like, like, like, like)
		}
	}
	// Body is the dedicated content box: it only searches captured request/response
	// text, so it goes straight to the full-text index with no metadata fallback. A
	// term too short for the trigram tokenizer cannot be served and is skipped
	// rather than guessed at — the UI hints at the three-character minimum.
	if b := strings.TrimSpace(f.Body); b != "" {
		if cond, arg, ok := t.ftsFilter(b); ok {
			add(cond, arg)
		}
	}
	if err = t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	col := sortColumns[strings.ToLower(strings.TrimSpace(f.Sort))]
	if col == "" {
		col = "ts"
	}
	dir := "DESC"
	if strings.EqualFold(strings.TrimSpace(f.Order), "asc") {
		dir = "ASC"
	}
	// id embeds capture timestamp + sequence, so a trailing id DESC makes the order
	// total and pagination stable even when the sort column has many ties.
	sel := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path,task_id,identity,egress FROM exchanges` +
		where + ` ORDER BY ` + col + ` ` + dir + `, id DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), size, page*size)
	rs, err := t.db.Query(sel, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var m ExchangeMeta
		if err := rs.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path, &m.TaskID, &m.Identity, &m.Egress); err != nil {
			return nil, 0, err
		}
		rows = append(rows, m)
	}
	return rows, total, rs.Err()
}

// Get returns the full request/response text of one exchange. Bodies come from
// the database; rows recorded before bodies moved into SQLite carry a non-empty
// path and are read from the legacy on-disk tree instead, so history stays
// readable without being migrated.
func (t *Traffic) Get(id string) (req, resp string, err error) {
	var reqHead, respHead string
	var reqBody, respBody []byte
	var reqBlob, respBlob sql.NullString
	var reqLen, respLen int
	err = t.db.QueryRow(`SELECT b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob,e.req_len,e.resp_len
FROM exchange_bodies b JOIN exchanges e ON e.id=b.id WHERE b.id=?`, id).
		Scan(&reqHead, &reqBody, &reqBlob, &respHead, &respBody, &respBlob, &reqLen, &respLen)
	if err == nil {
		return assembleRaw(reqHead, reqBody, reqBlob, reqLen), assembleRaw(respHead, respBody, respBlob, respLen), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}

	var rel string
	if err = t.db.QueryRow(`SELECT path FROM exchanges WHERE id=?`, id).Scan(&rel); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(rel) == "" {
		return "", "", fmt.Errorf("exchange %s 无正文记录", id)
	}
	rb, _ := os.ReadFile(filepath.Join(t.dir, rel, "request.http"))
	pb, _ := os.ReadFile(filepath.Join(t.dir, rel, "response.http"))
	return string(rb), string(pb), nil
}

// assembleRaw rebuilds one side's raw HTTP text: head, blank line, body. A body
// that spilled to the blob store shows its inline preview followed by the blob
// pointer, so the reader can see what it is and fetch the rest by hash.
func assembleRaw(head string, body []byte, blob sql.NullString, total int) string {
	var b strings.Builder
	b.WriteString(head)
	b.WriteByte('\n')
	b.Write(body)
	if blob.Valid && blob.String != "" {
		fmt.Fprintf(&b, "\n…[truncated] @blob sha256:%s (len=%d)", blob.String, total)
	}
	return b.String()
}

// HostCount is one distinct recorded host plus its exchange count.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// Hosts returns distinct recorded hosts with exchange counts, most recent
// activity first — powers the page's target picker.
func (t *Traffic) Hosts() ([]HostCount, error) {
	rows, err := t.db.Query(`SELECT host, COUNT(*) AS n, MAX(ts) AS last FROM (SELECT host, ts FROM exchanges UNION ALL SELECT dst_host AS host, ts FROM socks5_connections) GROUP BY host ORDER BY last DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCount
	for rows.Next() {
		var h HostCount
		var last int64
		if err := rows.Scan(&h.Host, &h.Count, &last); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Count returns total recorded exchanges.
func (t *Traffic) Count() (int, error) {
	var n int
	err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
	return n, err
}

// DeleteHost removes every recorded exchange whose host contains the given
// substring — mirroring the UI's host filter, so what you filtered is what gets
// deleted. Everything lives in SQLite, so the deletion is one transaction across
// the index, bodies, full-text index and blob references. Content-addressed
// blobs are shared across hosts and so are garbage-collected afterwards rather
// than deleted by host. Returns rows deleted.
func (t *Traffic) DeleteHost(host string) (int64, error) {
	like := "%" + host + "%"
	t.wmu.Lock()
	defer t.wmu.Unlock()
	// Resolved before the rows go away: with a substring match, the index is the
	// only record of which host directories the filter actually hit.
	legacy, err := t.hostTrees(`host LIKE ?`, like)
	if err != nil {
		return 0, err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	n, err := t.deleteWhereBoth(tx, `host LIKE ?`, `dst_host LIKE ?`, like)
	if err != nil {
		return 0, err
	}
	// Staged before the commit so a filesystem failure can still abort the whole
	// deletion, and before gcBlobs so reference collection sees the correct live
	// set — a staged tree is invisible to it.
	stageDir, moves, err := t.stageTrees(legacy)
	if err != nil {
		return 0, errors.Join(err, restoreTrees(stageDir, moves))
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.Join(fmt.Errorf("提交流量索引删除: %w", err), restoreTrees(stageDir, moves))
	}
	t.reapStage(stageDir)
	if n > 0 {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// DeleteAll removes every recorded exchange — the page's clear-everything
// action. It differs from the host-scoped deletions in two ways. It sweeps host
// directories without consulting the index, because "clear everything" should
// leave nothing behind and a directory whose rows are already gone would
// otherwise survive. And it ends with a full compaction: VACUUM costs what it
// keeps, so an emptied index is the one moment it is free, and it is also the
// only way to switch on auto_vacuum for a database created without it.
//
// Evidence already bound to a finding is untouched. Those bodies were copied
// into the evidence store when they were bound, precisely so that disposable
// traffic could be cleared without taking proof with it.
//
// Returns the number of exchanges deleted and how many bytes of index the
// compaction handed back.
func (t *Traffic) DeleteAll() (deleted int64, reclaimed int64, err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	before := t.indexBytes()
	trees, err := t.allHostTrees()
	if err != nil {
		return 0, 0, err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	if deleted, err = t.deleteWhereBoth(tx, `1=1`, `1=1`); err != nil {
		return 0, 0, err
	}
	// Staged before the commit so a filesystem failure can still abort the whole
	// deletion, exactly as in DeleteHost.
	stageDir, moves, err := t.stageTrees(trees)
	if err != nil {
		return 0, 0, errors.Join(err, restoreTrees(stageDir, moves))
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, errors.Join(fmt.Errorf("提交流量索引删除: %w", err), restoreTrees(stageDir, moves))
	}
	t.reapStage(stageDir)
	if err := t.gcBlobs(); err != nil {
		return deleted, 0, err
	}
	if err := t.compactIndex(); err != nil {
		// The deletion is already durable; compaction is disk space, not
		// correctness, so it must not turn a completed purge into a failed one.
		log.Printf("[traffic] 压实索引失败：%v", err)
		return deleted, 0, nil
	}
	return deleted, before - t.indexBytes(), nil
}

// allHostTrees lists every host directory left by the pre-SQLite layout. Unlike
// hostTrees it does not go through the index, so it also finds directories whose
// rows are already gone. Underscore-prefixed entries are the store's own
// (_index, _blobs, _ca, _delete_staging) and are never hosts.
func (t *Traffic) allHostTrees() ([]string, error) {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			dirs = append(dirs, filepath.Join(t.dir, e.Name()))
		}
	}
	return dirs, nil
}

// compactIndex rewrites the index into a fresh file, which is what actually
// returns its pages to the filesystem. VACUUM's runtime and temporary space
// scale with the content it keeps, so this is only reached right after DeleteAll
// has emptied the index — never as a routine step. It doubles as the conversion
// path for a database created before auto_vacuum=incremental: that pragma only
// takes effect through the VACUUM that follows it, and both must run on the same
// connection. Callers must hold wmu.
func (t *Traffic) compactIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if t.fts {
		// A full merge, not the bounded one reclaim uses: with the index emptied
		// there is nothing left to merge, so this only discards the tombstones.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts) VALUES('optimize')`); err != nil {
			return fmt.Errorf("合并全文索引: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA auto_vacuum=incremental`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("压实索引: %w", err)
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	// A legacy database has just been converted, so later deletions can reclaim
	// space on their own instead of waiting for another purge.
	t.incrementalVacuum = mode == autoVacuumIncremental
	if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("截断 WAL: %w", err)
	}
	return nil
}

// deleteWhere removes every trace of the exchanges matching the condition:
// full-text index rows, bodies, blob references, and finally the index rows.
// Order matters — each sub-select reads exchanges, so that table is emptied last.
// deleteWhereBoth 同时清理两份流量：HTTP 交换（exchanges 系）与裸 TCP 账本（socks5 系）。
//
// 之前所有删除路径（按主机、按主机批量、清空全部）只走 deleteWhere，而它只动 exchanges/
// exchange_bodies/blob_refs/ex_fts —— socks5_connections 与 socks5_bodies 从来没被删过，
// 所以"删了流量"以后裸 TCP 行和它们保存的上下行头部还在（合并成一张表后一眼就能看到）。
// socksWhere 是同一批条件在 socks5_connections 上的写法（列名是 dst_host），参数复用。
func (t *Traffic) deleteWhereBoth(tx *sql.Tx, exWhere, socksWhere string, args ...any) (int64, error) {
	socksDeleted := int64(0)
	if socksWhere != "" {
		if _, err := tx.Exec(`DELETE FROM socks5_bodies WHERE conn_id IN (SELECT id FROM socks5_connections WHERE `+socksWhere+`)`, args...); err != nil {
			return 0, fmt.Errorf("删除裸 TCP 正文: %w", err)
		}
		res, err := tx.Exec(`DELETE FROM socks5_connections WHERE `+socksWhere, args...)
		if err != nil {
			return 0, fmt.Errorf("删除裸 TCP 账本: %w", err)
		}
		// 删除条数要把裸 TCP 算进去：否则"清空全部流量"删掉两百多条却报 0，看起来像没删。
		socksDeleted, _ = res.RowsAffected()
	}
	n, err := t.deleteWhere(tx, exWhere, args...)
	return n + socksDeleted, err
}
func (t *Traffic) deleteWhere(tx *sql.Tx, where string, args ...any) (int64, error) {
	if t.fts {
		// ex_fts is contentless and addressed by rowid, hence the rowid sub-select.
		if _, err := tx.Exec(`DELETE FROM ex_fts WHERE rowid IN (SELECT rowid FROM exchanges WHERE `+where+`)`, args...); err != nil {
			return 0, fmt.Errorf("删除全文索引: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除正文: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE exchange_id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除 blob 引用: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM exchanges WHERE `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("删除索引行: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// hostTrees returns the on-disk directory of every host matching the condition.
// Exchanges recorded since bodies moved into SQLite have no directory at all, so
// most of these paths simply will not exist — staging skips those. The lookup is
// deliberately not restricted to rows with a path: a host whose index rows are
// already gone can still have an orphaned directory, and deleting the host should
// take that with it.
func (t *Traffic) hostTrees(where string, args ...any) ([]string, error) {
	rows, err := t.db.Query(`SELECT DISTINCT host FROM exchanges WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dirs []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		dirs = append(dirs, filepath.Join(t.dir, sanitize(h)))
	}
	return dirs, rows.Err()
}

type stagedTrafficPath struct {
	source string
	staged string
}

type hostDeleteStageJournal struct {
	Version   int                   `json:"version"`
	ArchiveID int64                 `json:"archive_id,omitempty"`
	TaskID    int64                 `json:"task_id,omitempty"`
	Hosts     []string              `json:"hosts,omitempty"`
	Moves     []hostDeleteStageMove `json:"moves"`
}

type hostDeleteStageMove struct {
	Source string `json:"source"`
	Staged string `json:"staged"`
}

const hostDeleteStageJournalName = "journal.json"

// stageTrees moves host directories aside onto the same filesystem. The rename is
// atomic and instant, which buys two things the unlink cannot: the deletion stays
// reversible until the transaction commits, and the tree stops being visible to
// blob reference collection right away (legacyBlobRefs skips underscore-prefixed
// directories, so anything under _delete_staging is already out of the live set).
// An empty stageDir is returned when there was nothing to stage.
func (t *Traffic) stageTrees(dirs []string) (stageDir string, moves []stagedTrafficPath, err error) {
	return t.stageTreesForArchive(dirs, nil, 0, 0)
}

func (t *Traffic) stageTreesForArchive(dirs, hosts []string, archiveID, taskID int64) (stageDir string, moves []stagedTrafficPath, err error) {
	seen := make(map[string]struct{}, len(dirs))
	planned := make([]stagedTrafficPath, 0, len(dirs))
	for _, source := range dirs {
		if _, dup := seen[source]; dup {
			continue
		}
		seen[source] = struct{}{}
		if _, err := os.Lstat(source); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return stageDir, moves, fmt.Errorf("检查历史流量目录 %s: %w", source, err)
		}
		planned = append(planned, stagedTrafficPath{source: source})
	}
	// 归档路径即使一个历史 host 目录都没有(新装机的流量只落在 SQLite + _blobs)
	// 也必须留下 journal：崩溃点若落在 PostgreSQL 提交与 SQLite 提交之间，重启后
	// SQLite 事务被回滚，只有这份 journal 能让恢复流程补做 host 行的删除。少了它，
	// 已转冷任务的独占流量会永久留在热库里。
	uniqueHosts := uniqueArchiveHosts(hosts)
	if len(planned) == 0 && len(uniqueHosts) == 0 {
		return "", nil, nil
	}
	parent := filepath.Join(t.dir, "_delete_staging")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, fmt.Errorf("创建流量暂存目录: %w", err)
	}
	if stageDir, err = os.MkdirTemp(parent, "hosts-"); err != nil {
		return "", nil, fmt.Errorf("创建流量暂存目录: %w", err)
	}
	journal := hostDeleteStageJournal{Version: 1, ArchiveID: archiveID, TaskID: taskID, Hosts: uniqueHosts}
	for i := range planned {
		planned[i].staged = filepath.Join(stageDir, fmt.Sprintf("%d-%s", i, filepath.Base(planned[i].source)))
		journal.Moves = append(journal.Moves, hostDeleteStageMove{Source: planned[i].source, Staged: planned[i].staged})
	}
	if err := writeHostDeleteStageJournal(filepath.Join(stageDir, hostDeleteStageJournalName), journal); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", nil, err
	}
	for _, move := range planned {
		source, staged := move.source, move.staged
		if err := os.Rename(source, staged); err != nil {
			return stageDir, moves, fmt.Errorf("移出历史流量目录 %s: %w", source, err)
		}
		moves = append(moves, stagedTrafficPath{source: source, staged: staged})
	}
	return stageDir, moves, nil
}

func writeHostDeleteStageJournal(path string, journal hostDeleteStageJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// restoreTrees puts staged directories back where they came from, newest move
// first, and drops the staging directory once everything is home.
func restoreTrees(stageDir string, moves []stagedTrafficPath) error {
	var errs []error
	for i := len(moves) - 1; i >= 0; i-- {
		move := moves[i]
		if _, err := os.Lstat(move.source); err == nil {
			errs = append(errs, fmt.Errorf("restore destination already exists: %s", move.source))
			continue
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("inspect restore destination %s: %w", move.source, err))
			continue
		}
		if err := os.Rename(move.staged, move.source); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", move.source, err))
		}
	}
	if len(errs) == 0 && stageDir != "" {
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, fmt.Errorf("remove traffic stage: %w", err))
		}
	}
	return errors.Join(errs...)
}

// reapStage unlinks a committed staging directory in the background. This is the
// step that used to stall the recorder: a legacy tree mirrors the URL path per
// request and can hold hundreds of thousands of small files, and the whole unlink
// ran while the write lock was held. The rows are already gone by now, so losing
// this to a shutdown leaves garbage under _delete_staging, never inconsistent
// state.
func (t *Traffic) reapStage(stageDir string) {
	if stageDir == "" {
		return
	}
	t.reaping.Go(func() {
		if err := os.RemoveAll(stageDir); err != nil {
			log.Printf("[traffic] 清理历史流量目录 %s 失败：%v", stageDir, err)
		}
	})
}

// DeleteHostsExact removes recorded exchanges for a set of EXACT hosts (the
// batch path for the page's multi-select delete): index rows + each host's file
// tree, then one blob-GC pass. Exact match — unlike DeleteHost's substring —
// so picking "api.example.com" never sweeps "api.example.com.cn". Returns rows
// deleted. Duplicate hosts are harmless (idempotent deletes, single tree pass).
func (t *Traffic) DeleteHostsExact(hosts []string) (int64, error) {
	stage, err := t.StageDeleteHostsExact(hosts)
	if err != nil {
		return 0, err
	}
	deleted := stage.Deleted()
	if err := stage.Commit(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// HostDeleteStage keeps the SQLite delete transaction open so a task deletion
// can be coordinated with PostgreSQL: the traffic side is staged here and only
// committed once the caller's own transaction has succeeded. The Traffic write
// lock is held until Commit or Rollback, so no recorder can add rows or a blob
// reference for a host that is mid-deletion. Rolling back is just a transaction
// rollback now that nothing is moved on disk.
type HostDeleteStage struct {
	traffic  *Traffic
	tx       *sql.Tx
	stageDir string
	moves    []stagedTrafficPath
	deleted  int64
	done     bool
}

// Deleted reports the number of exchange rows selected by this stage.
func (s *HostDeleteStage) Deleted() int64 {
	if s == nil {
		return 0
	}
	return s.deleted
}

// StageDeleteHostsExact prepares a reversible exact-host deletion. Callers must
// finish every successful stage with Commit or Rollback.
func (t *Traffic) StageDeleteHostsExact(hosts []string) (*HostDeleteStage, error) {
	return t.stageDeleteHostsExact(hosts, 0, 0, 0)
}

// StageDeleteHostsExactForArchive ties the reversible traffic deletion to a
// persistent task archive. Startup recovery uses archiveCommitted to decide
// whether an interrupted stage must be completed or rolled back.
func (t *Traffic) StageDeleteHostsExactForArchive(hosts []string, archiveID, taskID int64) (*HostDeleteStage, error) {
	if archiveID <= 0 || taskID <= 0 {
		return nil, errors.New("archive and task ids must be positive")
	}
	return t.stageDeleteHostsExact(hosts, archiveID, taskID, 0)
}

// StageDeleteForTask 按任务删流量（可回滚暂存版）：交换表与裸 TCP 账本都按 task_id 命中，
// 主机清单作为兜底。删任务走这条，而不是"只按主机清单删"。
func (t *Traffic) StageDeleteForTask(taskID int64, hosts []string) (*HostDeleteStage, error) {
	if taskID <= 0 {
		return nil, errors.New("task id must be positive")
	}
	return t.stageDeleteHostsExact(hosts, 0, taskID, taskID)
}
func (t *Traffic) stageDeleteHostsExact(hosts []string, archiveID, taskID, matchTask int64) (*HostDeleteStage, error) {
	t.wmu.Lock()
	stage := &HostDeleteStage{traffic: t}
	fail := func(cause error) (*HostDeleteStage, error) {
		if rollbackErr := stage.rollbackLocked(); rollbackErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("回滚流量删除: %w", rollbackErr))
		}
		return nil, cause
	}
	abort := func(cause error) (*HostDeleteStage, error) {
		t.wmu.Unlock()
		stage.done = true
		return nil, cause
	}

	unique := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		unique = append(unique, host)
	}

	// Exact hosts are known up front, so their directories are derived directly
	// rather than looked up: a host whose index rows are already gone can still
	// own an orphaned directory that this deletion should take with it.
	legacy := make([]string, 0, len(unique))
	for _, h := range unique {
		legacy = append(legacy, filepath.Join(t.dir, sanitize(h)))
	}

	tx, err := t.db.Begin()
	if err != nil {
		return abort(err)
	}
	stage.tx = tx
	if matchTask > 0 {
		// 任务维度：task_id 命中，或主机在清单里——两个条件都要。
		//   只按任务：老数据没有归属（task_id=0）却确实属于这个任务，会漏。
		//   只按主机：同名主机上别的任务的流量会被误删，主机不在清单里又会漏。
		exWhere, socksWhere := `task_id=?`, `task_id=?`
		args := []any{matchTask}
		if len(unique) > 0 {
			marks := strings.TrimSuffix(strings.Repeat("?,", len(unique)), ",")
			exWhere = `(task_id=? OR host IN (` + marks + `))`
			socksWhere = `(task_id=? OR dst_host IN (` + marks + `))`
			for _, h := range unique {
				args = append(args, h)
			}
		}
		n, err := t.deleteWhereBoth(tx, exWhere, socksWhere, args...)
		if err != nil {
			return fail(err)
		}
		stage.deleted += n
	} else {
		for _, h := range unique {
			n, err := t.deleteWhereBoth(tx, `host=?`, `dst_host=?`, h)
			if err != nil {
				return fail(err)
			}
			stage.deleted += n
		}
	}

	stage.stageDir, stage.moves, err = t.stageTreesForArchive(legacy, unique, archiveID, taskID)
	if err != nil {
		return fail(err)
	}
	return stage, nil
}

// RecoverHostDeleteStages resolves filesystem moves left by a process exit.
// SQLite rolls open transactions back on restart, while the supplied callback
// identifies task archives whose PostgreSQL compaction already committed.
func (t *Traffic) RecoverHostDeleteStages(archiveCommitted func(int64, int64) (bool, error)) error {
	if t == nil {
		return nil
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	parent := filepath.Join(t.dir, "_delete_staging")
	entries, err := os.ReadDir(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	needsGC := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		stageDir := filepath.Join(parent, entry.Name())
		raw, err := os.ReadFile(filepath.Join(stageDir, hostDeleteStageJournalName))
		if os.IsNotExist(err) {
			// Older versions did not persist enough information for lossless
			// recovery. Keep the directory for manual inspection.
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var journal hostDeleteStageJournal
		if err := json.Unmarshal(raw, &journal); err != nil {
			errs = append(errs, fmt.Errorf("读取流量暂存日志 %s: %w", stageDir, err))
			continue
		}
		if journal.Version != 1 {
			errs = append(errs, fmt.Errorf("流量暂存日志 %s 的版本 %d 不受支持", stageDir, journal.Version))
			continue
		}
		moves := make([]stagedTrafficPath, 0, len(journal.Moves))
		for _, move := range journal.Moves {
			if !pathWithin(t.dir, move.Source) || !pathWithin(stageDir, move.Staged) {
				errs = append(errs, fmt.Errorf("流量暂存日志包含越界路径: %s", stageDir))
				moves = nil
				break
			}
			if _, err := os.Lstat(move.Staged); err == nil {
				moves = append(moves, stagedTrafficPath{source: move.Source, staged: move.Staged})
			} else if !os.IsNotExist(err) {
				errs = append(errs, err)
				moves = nil
				break
			}
		}
		if moves == nil {
			continue
		}
		committed := false
		if journal.ArchiveID > 0 {
			if archiveCommitted == nil {
				errs = append(errs, fmt.Errorf("流量归档 %d 无状态解析器", journal.ArchiveID))
				continue
			}
			committed, err = archiveCommitted(journal.ArchiveID, journal.TaskID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		} else if len(journal.Hosts) > 0 {
			committed, err = t.hostsHaveNoExchanges(journal.Hosts)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if !committed {
			if err := restoreTrees(stageDir, moves); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := t.deleteArchivedHosts(journal.Hosts); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, err)
			continue
		}
		needsGC = true
	}
	if needsGC {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *Traffic) hostsHaveNoExchanges(hosts []string) (bool, error) {
	for _, host := range hosts {
		var count int
		if err := t.db.QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

func (t *Traffic) deleteArchivedHosts(hosts []string) error {
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, host := range hosts {
		if _, err := t.deleteWhereBoth(tx, `host=?`, `dst_host=?`, host); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func pathWithin(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, candidateAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// Rollback discards the staged deletion, leaving the traffic store untouched.
func (s *HostDeleteStage) Rollback() error {
	if s == nil || s.done {
		return nil
	}
	return s.rollbackLocked()
}

func (s *HostDeleteStage) rollbackLocked() error {
	if s == nil || s.done {
		return nil
	}
	var errs []error
	if s.tx != nil {
		if err := s.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			errs = append(errs, fmt.Errorf("回滚流量索引: %w", err))
		}
	}
	if err := restoreTrees(s.stageDir, s.moves); err != nil {
		errs = append(errs, err)
	}
	s.done = true
	s.traffic.wmu.Unlock()
	return errors.Join(errs...)
}

// Commit makes the staged deletion permanent. SQLite is committed only after
// the caller has committed its PostgreSQL task deletion.
func (s *HostDeleteStage) Commit() error {
	if s == nil || s.done {
		return nil
	}
	if err := s.tx.Commit(); err != nil {
		// A failed SQLite commit normally rolls the transaction back. Restore the
		// trees so the traffic store remains internally consistent and recoverable.
		restoreErr := restoreTrees(s.stageDir, s.moves)
		s.done = true
		s.traffic.wmu.Unlock()
		return errors.Join(fmt.Errorf("提交流量索引删除: %w", err), restoreErr)
	}
	// Unlinking the staged trees is what used to hold the write lock for hours;
	// it now runs in the background, while collection below only needs them to be
	// out of the live tree — which the staging rename already guaranteed.
	s.traffic.reapStage(s.stageDir)
	s.traffic.reclaim()
	var errs []error
	if err := s.traffic.gcBlobs(); err != nil {
		errs = append(errs, fmt.Errorf("回收流量 blob: %w", err))
	}
	s.done = true
	s.traffic.wmu.Unlock()
	return errors.Join(errs...)
}

// indexBytes is the index's real footprint on disk: the database plus its
// write-ahead log and shared-memory file, since those are what an operator sees
// the data directory holding.
func (t *Traffic) indexBytes() int64 {
	base := filepath.Join(t.dir, "_index", "index.sqlite")
	var total int64
	for _, p := range []string{base, base + "-wal", base + "-shm"} {
		if st, err := os.Stat(p); err == nil {
			total += st.Size()
		}
	}
	return total
}

// reclaim hands space freed by a deletion back to the filesystem. Deleting rows
// only makes them invisible: SQLite chains their pages onto a freelist, and
// deleting from the contentless_delete full-text index writes tombstones rather
// than removing the postings they hide. Neither shrinks a single byte on disk,
// and since bodies below maxInlineBody live in that same file, an install that
// captures heavily ends up holding far more than the traffic it still has.
//
// The work is done in the background, in bounded steps that drop the write lock
// between them, because it is proportional to what was deleted — freeing several
// gigabytes under one lock would stall record(), which go-mitmproxy calls before
// it replies to the client, and so would stall the requests being recorded.
// Safe to call with wmu held: the background pass simply waits for it.
//
// Best-effort throughout. Failing to reclaim costs disk space, never
// correctness, so errors are logged and the next deletion resumes the work.
func (t *Traffic) reclaim() {
	if !t.reclaiming.CompareAndSwap(false, true) {
		return // one pass at a time; a second would only contend for the lock
	}
	t.reaping.Go(func() {
		defer t.reclaiming.Store(false)
		// One pinned connection for the whole pass: a long reclamation issues
		// hundreds of statements, and letting the pool hand each one a different
		// connection would both churn connections and split the freelist readings
		// that decide when to stop away from the vacuum they measure.
		ctx := context.Background()
		conn, err := t.db.Conn(ctx)
		if err != nil {
			log.Printf("[traffic] 回收索引空间失败（获取连接）：%v", err)
			return
		}
		defer conn.Close()
		deadline := time.Now().Add(reclaimBudget)
		merges := reclaimMergeSteps
		for step := 0; ; step++ {
			t.wmu.Lock()
			progressed, err := t.reclaimChunk(ctx, conn, &merges)
			t.wmu.Unlock()
			if err != nil {
				log.Printf("[traffic] 回收索引空间失败：%v", err)
				return
			}
			if !progressed {
				break
			}
			if t.stopping() {
				return // shutdown must not wait out the remaining budget
			}
			if step+1 >= reclaimMaxSteps {
				log.Printf("[traffic] 索引空间回收未做完（已用满 %d 步上限），下次删除时继续", reclaimMaxSteps)
				return
			}
			if time.Now().After(deadline) {
				log.Printf("[traffic] 索引空间回收未做完（已用满 %s 预算），下次删除时继续", reclaimBudget)
				return
			}
		}
		// Truncating the log is what makes the reclamation visible on disk: in WAL
		// mode the freed pages are recorded there first, and a PASSIVE checkpoint
		// would leave the log itself sitting at its high-water mark.
		t.wmu.Lock()
		defer t.wmu.Unlock()
		if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			log.Printf("[traffic] 截断 WAL 失败：%v", err)
		}
	})
}

// reclaimChunk does one bounded step and reports whether it made progress, which
// is what the caller loops on. merges carries the remaining full-text merge
// budget and is spent down here. Callers must hold wmu.
func (t *Traffic) reclaimChunk(ctx context.Context, conn *sql.Conn, merges *int) (bool, error) {
	progressed := false
	if t.fts && *merges > 0 {
		// A negative rank is fts5's page budget for one incremental merge.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts, rank) VALUES('merge', ?)`, -reclaimMergePages); err != nil {
			return false, fmt.Errorf("合并全文索引: %w", err)
		}
		*merges--
		progressed = true
	}
	if !t.incrementalVacuum {
		// incremental_vacuum is a silent no-op on a database created with
		// auto_vacuum=0; only a full compaction can convert one. Merging the
		// full-text index above still pays off, so stop here rather than earlier.
		return progressed, nil
	}
	var before, after int
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&before); err != nil {
		return false, err
	}
	if before == 0 {
		return progressed, nil
	}
	// The budget is a constant and PRAGMA arguments cannot be bound as parameters.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, reclaimChunkPages)); err != nil {
		return false, fmt.Errorf("回收索引空闲页: %w", err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&after); err != nil {
		return false, err
	}
	// Progress, not an empty freelist, is the right stopping condition:
	// incremental_vacuum can only release pages it manages to move to the end of
	// the file, so a residual freelist it cannot shrink is a normal outcome.
	return progressed || after < before, nil
}

// gcBlobs removes blobs that no remaining exchange references. Live references
// come from blob_refs, so collection is one query plus a sweep of the blob
// directory — no exchange body is ever read. Emptied bucket directories are
// removed as well; the previous file-scanning collector deleted only files and
// left the buckets behind permanently. Best-effort: walk errors only skip the
// affected entries. Callers must hold wmu so this never races a concurrent
// record() writing a fresh blob + reference.
func (t *Traffic) gcBlobs() error {
	refs := make(map[string]struct{})
	rows, err := t.db.Query(`SELECT DISTINCT hash FROM blob_refs`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		refs[h] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := t.legacyBlobRefs(refs); err != nil {
		return err
	}

	root := filepath.Join(t.dir, "_blobs", "sha256")
	var buckets []string
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			if p != root {
				buckets = append(buckets, p)
			}
			return nil
		}
		h := strings.TrimSuffix(d.Name(), ".bin")
		if _, ok := refs[h]; !ok {
			os.Remove(p)
		}
		return nil
	}); err != nil {
		return err
	}
	// Deepest first, so a two-level bucket left by the old layout collapses fully.
	// Remove fails harmlessly on a non-empty directory — exactly the guard needed
	// to avoid deleting a bucket that still holds live blobs.
	sort.Slice(buckets, func(i, j int) bool { return len(buckets[i]) > len(buckets[j]) })
	for _, b := range buckets {
		os.Remove(b)
	}
	return nil
}

// legacyBlobRefs adds hashes referenced by pre-SQLite exchanges, whose bodies are
// still .http files on disk holding "@blob sha256:<hex>" pointers. Without this
// the first collection after the upgrade would delete blobs that history still
// points at. Skipped entirely once no legacy rows remain — the steady state — so
// the tree walk is transitional rather than a permanent cost.
func (t *Traffic) legacyBlobRefs(refs map[string]struct{}) error {
	var n int
	if err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges WHERE path<>''`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	blobRe := regexp.MustCompile(`@blob sha256:([0-9a-f]{64})`)
	return filepath.WalkDir(t.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// _blobs/_index/_ca never contain references; skip their subtrees.
			if p != t.dir && strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if nm := d.Name(); nm != "request.http" && nm != "response.http" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range blobRe.FindAllSubmatch(b, -1) {
			refs[string(m[1])] = struct{}{}
		}
		return nil
	})
}

// query returns one page of exchange metadata filtered by host and/or a url
// substring. Default page size is intentionally small (3) to keep tool results
// lightweight and capped at 10; page is 0-based (page*limit offset).
// defaultTaskScopeFromAgentID resolves the calling agent to a task id when the
// agent id carries one ("task12", "task12-reporter"). 0 means "no scope", which
// leaves the search global — the caller then relies on the returned task_id.
func defaultTaskScopeFromAgentID(agentID string) int64 {
	s := strings.TrimSpace(agentID)
	if !strings.HasPrefix(s, "task") {
		return 0
	}
	s = strings.TrimPrefix(s, "task")
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseInt(s[:end], 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// query is the unscoped form used by tests and callers that need no task scope.
func (t *Traffic) query(host, contains, bodyContains string, page, limit int) ([]ExchangeMeta, error) {
	return t.queryScoped(host, contains, bodyContains, 0, page, limit)
}

func (t *Traffic) queryScoped(host, contains, bodyContains string, taskID int64, page, limit int) ([]ExchangeMeta, error) {
	if limit <= 0 {
		limit = 3
	}
	if limit > 10 {
		limit = 10
	}
	if page < 0 {
		page = 0
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path,task_id,identity,egress FROM exchanges WHERE 1=1`
	args := []any{}
	if taskID > 0 {
		q += ` AND task_id=?`
		args = append(args, taskID)
	}
	if host != "" {
		hostName, port, err := normalizeSearchHost(host)
		if err != nil {
			return nil, err
		}
		q += ` AND host=?`
		args = append(args, hostName)
		if port != "" {
			// Recorded rows historically store URL.Hostname() (without the port),
			// so constrain the original URL authority as a compatibility fallback.
			// New and old captures therefore share the same search contract.
			authority := net.JoinHostPort(hostName, port)
			q += ` AND (url LIKE ? OR url LIKE ? OR url LIKE ?)`
			args = append(args,
				"%://"+authority+"/%",
				"%://"+authority+"?%",
				"%://"+authority,
			)
		}
	}
	if contains != "" {
		q += ` AND (url LIKE ? OR url_template LIKE ?)`
		args = append(args, "%"+contains+"%", "%"+contains+"%")
	}
	if b := strings.TrimSpace(bodyContains); b != "" {
		cond, arg, ok := t.ftsFilter(b)
		if !ok {
			if !t.fts {
				return nil, fmt.Errorf("当前实例未启用全文索引，无法按正文搜索")
			}
			return nil, fmt.Errorf("正文搜索关键词至少需要 %d 个字符（当前 %d 个）", minTrigram, utf8.RuneCountInString(b))
		}
		q += ` AND ` + cond
		args = append(args, arg)
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, page*limit)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path, &m.TaskID, &m.Identity, &m.Egress); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// normalizeSearchHost accepts the forms agents commonly have at hand while
// keeping the stored host (URL.Hostname()) as the canonical host key. A port,
// when supplied, is applied to the URL authority so captures from different
// services on the same IP cannot be mixed.
func normalizeSearchHost(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("host 为必填参数")
	}
	if strings.Contains(raw, "://") {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Host == "" {
			return "", "", fmt.Errorf("无法解析 host：%q", raw)
		}
		host, port = u.Hostname(), u.Port()
	} else if h, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		host, port = h, p
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	} else {
		host = raw
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("无法解析 host：%q", raw)
	}
	if port != "" {
		p, parseErr := strconv.Atoi(port)
		if parseErr != nil || p < 1 || p > 65535 {
			return "", "", fmt.Errorf("端口无效：%q", port)
		}
		port = strconv.Itoa(p)
	}
	return strings.ToLower(host), port, nil
}

// Tools exposes traffic lookup to work agents so they query already-captured
// traffic instead of re-curling the same resource (token + dedup win).
func (t *Traffic) Tools() []actool.CoreTool {
	allow := func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}
	ro := func(json.RawMessage) bool { return true }

	search := actool.Build(actool.Spec{
		Name:        "traffic_search",
		Description: TrafficSearchDescription,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":          map[string]any{"type": "string", "description": "按主机过滤（可选；如 '107.172.96.177'、'107.172.96.177:8082' 或 'http://107.172.96.177:8082/path'）。与 body_contains 至少给一个"},
				"contains":      map[string]any{"type": "string", "description": "URL 子串过滤（可选，如 'api' / 'login'）"},
				"body_contains": map[string]any{"type": "string", "description": "正文全文搜索（至少 3 个字符），匹配请求/响应的头与正文，如 'password' / 'root:x:0' / 'i-8vbid9vyu04zpjux8xkk'。证据常常在**代理端点**（RCE/上传接口）的响应体里，此时用证据里的关键串搜它，而不是搜证据所属的主机"},
				"task_id":       map[string]any{"type": "integer", "description": "只看某个任务的流量（可选；默认按调用者所属任务限定，避免多任务同主机串包）"},
				"limit":         map[string]any{"type": "integer", "description": "每页条数，默认 3，最大 10"},
				"page":          map[string]any{"type": "integer", "description": "页码，从 0 开始，默认 0（按 ts 倒序分页）"},
			},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Host, Contains string
				BodyContains   string `json:"body_contains"`
				TaskID         int64  `json:"task_id"`
				Limit          int
				Page           int
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Host) == "" && len([]rune(strings.TrimSpace(a.BodyContains))) < minTrigram {
				return actool.Errorf("host 与 body_contains 至少要给一个（正文关键词至少 3 个字符）：按主机查，或用证据里的关键串反查承载它的那条交换。"), nil
			}
			scope := a.TaskID
			if scope == 0 && tc != nil {
				// Default to the caller's own task: several tasks can hit the same
				// host, and an unscoped answer mixes their captures together.
				scope = defaultTaskScopeFromAgentID(tc.AgentID)
			}
			rows, err := t.queryScoped(a.Host, a.Contains, a.BodyContains, scope, a.Page, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(rows) == 0 {
				return actool.Text("无匹配流量。"), nil
			}
			// 精简为最小索引：仅保留定位所需字段 + 响应码/长度，不带任何响应内容。
			type liteRow struct {
				ID       string `json:"id"`
				Method   string `json:"method"`
				URL      string `json:"url"`
				Status   int    `json:"status"`
				RespLen  int    `json:"resp_len"`
				TaskID   int64  `json:"task_id"`
				Identity string `json:"identity,omitempty"`
				Egress   string `json:"egress,omitempty"`
			}
			lite := make([]liteRow, 0, len(rows))
			for _, r := range rows {
				lite = append(lite, liteRow{ID: r.ID, Method: r.Method, URL: r.URL, Status: r.Status, RespLen: r.RespLen,
					TaskID: r.TaskID, Identity: r.Identity, Egress: r.Egress})
			}
			b, _ := json.Marshal(lite)
			return actool.Text(string(b)), nil
		},
	})

	get := actool.Build(actool.Spec{
		Name:        "traffic_get",
		Description: "按 id 取一条已抓流量的请求/响应原文（过大会截断）。配合 traffic_search 用，避免重复 curl。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"id": map[string]any{"type": "string", "description": "traffic_search 返回的 id"}},
			"required":   []any{"id"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ ID string }
			_ = json.Unmarshal(in, &a)
			req, resp, err := t.Get(a.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("=== REQUEST ===\n" + clip(req, 2500) + "\n\n=== RESPONSE ===\n" + clip(resp, 4000)), nil
		},
	})

	blob := actool.Build(actool.Spec{
		Name:        "traffic_blob",
		Description: "分段读取超大请求/响应体的原文。traffic_get 里显示为 '…[truncated] @blob sha256:<hash>' 的部分即存放于此，把该 hash 传进来即可取完整内容。单次最多返回 8KB，用 offset 继续往后读（返回结果会给出总长度）。适合翻阅备份文件、源码泄露、大 JSON 导出等超过内联阈值的响应。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hash":   map[string]any{"type": "string", "description": "traffic_get 中 @blob sha256: 后面的 64 位十六进制值"},
				"offset": map[string]any{"type": "integer", "description": "起始字节偏移，默认 0"},
				"length": map[string]any{"type": "integer", "description": "本次读取字节数，默认且最大 8192"},
			},
			"required": []any{"hash"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Hash   string
				Offset int64
				Length int64
			}
			_ = json.Unmarshal(in, &a)
			if a.Length <= 0 || a.Length > maxBlobRead {
				a.Length = maxBlobRead
			}
			data, total, err := t.BlobRange(a.Hash, a.Offset, a.Length)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(data) == 0 {
				return actool.Text(fmt.Sprintf("偏移 %d 已超出内容长度（总长 %d 字节）。", a.Offset, total)), nil
			}
			head := fmt.Sprintf("[offset=%d 本次=%d 总长=%d]\n", a.Offset, len(data), total)
			if isBinaryBody("", data) {
				return actool.Text(head + "二进制内容，以十六进制展示前 512 字节：\n" + hex.EncodeToString(clipBytes(data, 512))), nil
			}
			return actool.Text(head + truncateUTF8(data, len(data))), nil
		},
	})

	return []actool.CoreTool{search, get, blob}
}

// SeedToolMetas returns the traffic tools built on a ZERO receiver, for seeding the
// tools catalog (metadata only — Name/Description/InputSchema). The handlers close
// over the nil receiver but are never invoked on this instance, so it is safe.
func SeedToolMetas() []actool.CoreTool { return (&Traffic{}).Tools() }

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... [截断，共 %d 字节；完整在流量文件树] ...", len(s))
}
