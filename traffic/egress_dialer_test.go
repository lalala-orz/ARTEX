package traffic

import (
	"context"
	"database/sql"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// recordingDialer is an egress that dials directly while counting calls, standing
// in for a task's in-process tunnel.
type recordingDialer struct {
	label string
	calls atomic.Int64
}

func (d *recordingDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

func (d *recordingDialer) Describe() string { return d.label }

// TestSocks5RawRelayHonoursEgressDialer pins the rule the tunnel feature exists
// for: an injected dialer owns the raw-TCP egress even when a URL proxy is also
// configured, the traffic really leaves through it, and the ledger says so by
// name —which is what tells a tunnel apart from a proxy after the fact.
func TestSocks5RawRelayHonoursEgressDialer(t *testing.T) {
	echo := startEchoTarget(t, "TUNNEL-BANNER")
	echoPort := portOf(t, echo)
	// A URL upstream that must stay unused: the dialer takes precedence.
	upstream, hits := startCountingUpstream(t)

	addr := freeAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)

	if err := tr.SetUpstreamProxy("socks5://" + upstream); err != nil {
		t.Fatal(err)
	}
	d := &recordingDialer{label: "suo5:http://10.1.1.5/x.php"}
	tr.SetUpstreamDialer(d)

	socks5RoundTrip(t, addr, "127.0.0.1", echoPort, "PING", "TUNNEL-BANNER")

	row := waitLedgerRow(t, tr, echoPort, true)
	if row.Egress != d.label {
		t.Fatalf("ledger egress = %q, want %q", row.Egress, d.label)
	}
	if d.calls.Load() == 0 {
		t.Fatal("dialer was never used")
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("URL upstream received %d connection(s) although a dialer owns the egress", got)
	}

	// Clearing the dialer returns the listener to a DIRECT dial: the last setter
	// wins, and nil means "no egress" rather than "restore what was configured
	// before". A second target keeps this phase's row unambiguous —waitLedgerRow
	// matches on (port, via_upstream) and the first phase also left through an
	// egress.
	echo2 := startEchoTarget(t, "TUNNEL-BANNER")
	echoPort2 := portOf(t, echo2)
	before := atomic.LoadInt32(hits)
	tr.SetUpstreamDialer(nil)
	socks5RoundTrip(t, addr, "127.0.0.1", echoPort2, "PING", "TUNNEL-BANNER")
	row = waitLedgerRow(t, tr, echoPort2, false)
	if row.Egress != "" {
		t.Fatalf("direct dial must have an empty egress label, got %q", row.Egress)
	}
	if got := atomic.LoadInt32(hits); got != before {
		t.Fatalf("cleared egress still used the URL upstream (%d →%d)", before, got)
	}

	// Re-installing the URL proxy works after a dialer owned the egress, and the
	// ledger goes back to naming it.
	echo3 := startEchoTarget(t, "TUNNEL-BANNER")
	echoPort3 := portOf(t, echo3)
	if err := tr.SetUpstreamProxy("socks5://" + upstream); err != nil {
		t.Fatal(err)
	}
	socks5RoundTrip(t, addr, "127.0.0.1", echoPort3, "PING", "TUNNEL-BANNER")
	row = waitLedgerRow(t, tr, echoPort3, true)
	if want := "socks5://" + upstream; row.Egress != want {
		t.Fatalf("ledger egress = %q, want %q", row.Egress, want)
	}
	if got := atomic.LoadInt32(hits); got <= before {
		t.Fatalf("URL upstream not used after being re-installed (%d →%d)", before, got)
	}
}

// TestSocks5LedgerUpgradesForEgress pins the upgrade path: an index created before
// the egress column existed must gain it on open. CREATE TABLE IF NOT EXISTS never
// alters an existing table, so without the migration every relay insert on such an
// install would fail —silently, since recordSocks5Conn only logs.
func TestSocks5LedgerUpgradesForEgress(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "_index"), 0o755); err != nil {
		t.Fatal(err)
	}
	dsn := filepath.Join(dir, "_index", "index.sqlite")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	// The ledger exactly as released before egress existed.
	if _, err := db.Exec(`CREATE TABLE socks5_connections (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL,
  listener_id  TEXT    NOT NULL,
  task_id      INTEGER NOT NULL DEFAULT 0,
  dst_host     TEXT    NOT NULL,
  dst_port     INTEGER NOT NULL,
  bytes_up     INTEGER NOT NULL DEFAULT 0,
  bytes_down   INTEGER NOT NULL DEFAULT 0,
  mitmed       INTEGER NOT NULL DEFAULT 0,
  via_upstream INTEGER NOT NULL DEFAULT 0
)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	tr.recordSocks5Conn(Socks5Conn{
		TS: 1, ListenerID: GlobalListenerID, DstHost: "10.0.0.5", DstPort: 3306,
		BytesUp: 12, BytesDown: 340, ViaUpstream: true, Egress: "suo5:http://10.1.1.5/x.php",
	})
	rows, total, err := tr.Socks5Conns("10.0.0.5", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("ledger after upgrade: total=%d rows=%+v", total, rows)
	}
	if want := "suo5:http://10.1.1.5/x.php"; rows[0].Egress != want {
		t.Fatalf("egress after upgrade = %q, want %q", rows[0].Egress, want)
	}
	if !rows[0].ViaUpstream {
		t.Fatal("pre-existing columns must survive the upgrade")
	}
}

// socks5DialAuth negotiates RFC 1929 user/pass before CONNECTing. Mirrors
// socks5Dial, which only speaks no-auth.
func socks5DialAuth(t *testing.T, proxyAddr, user, pass string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		t.Fatal(err)
	}
	if hello[0] != 0x05 || hello[1] != 0x02 {
		t.Fatalf("greeting reply %v, want user/pass (0x02) offered", hello)
	}
	auth := append([]byte{0x01, byte(len(user))}, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := c.Write(auth); err != nil {
		t.Fatal(err)
	}
	var ar [2]byte
	if _, err := io.ReadFull(c, ar[:]); err != nil {
		t.Fatal(err)
	}
	if ar[1] != 0x00 {
		t.Fatalf("auth rejected for %q (status 0x%02x)", user, ar[1])
	}
	return c
}

// socks5Connect sends the CONNECT command on an already-authenticated conn and
// requires it to succeed.
func socks5Connect(t *testing.T, c net.Conn, host string, port int) {
	t.Helper()
	var req []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x01}, ip.To4()...)
	} else {
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT %s:%d refused (rep=0x%02x)", host, port, rep[1])
	}
	_ = c.SetDeadline(time.Time{})
}

// socks5AuthRejected asserts the listener refuses these credentials.
func socks5AuthRejected(t *testing.T, proxyAddr, user, pass string) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil {
		t.Fatal(err)
	}
	if hello[1] != 0x02 {
		t.Fatalf("greeting reply %v, want user/pass offered", hello)
	}
	auth := append([]byte{0x01, byte(len(user))}, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	_, _ = c.Write(auth)
	var ar [2]byte
	if _, err := io.ReadFull(c, ar[:]); err != nil {
		t.Fatal(err)
	}
	if ar[1] == 0x00 {
		t.Fatalf("credentials %q:%q were accepted, want rejection", user, pass)
	}
}

// TestIdentityEgressRoutesPerClient is the acceptance test for per-task egress: one
// listener, three clients, and only the task that bound a tunnel leaves through it.
// The rest keep the default egress, which is what "a tunnel affects one task" means
// in practice.
func TestIdentityEgressRoutesPerClient(t *testing.T) {
	echo7 := startEchoTarget(t, "TASK7-BANNER")
	port7 := portOf(t, echo7)
	echo9 := startEchoTarget(t, "TASK9-BANNER")
	port9 := portOf(t, echo9)
	upstream, hits := startCountingUpstream(t)

	addr := freeAddr(t)
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()
	waitListening(t, addr)
	if err := tr.SetUpstreamProxy("socks5://" + upstream); err != nil {
		t.Fatal(err)
	}

	tunnel := &recordingDialer{label: "suo5:http://10.1.1.5/x.php"}
	tr.SetIdentityEgress("task7", "tok7", 7, tunnel)
	tr.SetIdentityEgress("task9", "tok9", 9, nil) // no tunnel: attributed, default egress

	// task7 leaves through its tunnel, and the ledger says so by name and by task.
	c7 := socks5DialAuth(t, addr, "task7", "tok7")
	socks5Connect(t, c7, "127.0.0.1", port7)
	c7.Write([]byte("PING"))
	banner := make([]byte, len("TASK7-BANNER"))
	if _, err := io.ReadFull(c7, banner); err != nil {
		t.Fatal(err)
	}
	c7.Close()
	row := waitLedgerRow(t, tr, port7, true)
	if row.Identity != "task7" || row.TaskID != 7 {
		t.Fatalf("ledger attribution = identity %q task %d, want task7/7", row.Identity, row.TaskID)
	}
	if row.Egress != tunnel.label {
		t.Fatalf("task7 egress = %q, want %q", row.Egress, tunnel.label)
	}
	if tunnel.calls.Load() == 0 {
		t.Fatal("task7 did not use its tunnel")
	}
	callsAfterTask7 := tunnel.calls.Load()

	// task9 has no tunnel: it must leave through the default egress and must not
	// touch task7's tunnel.
	hitsBefore9 := atomic.LoadInt32(hits)
	c9 := socks5DialAuth(t, addr, "task9", "tok9")
	socks5Connect(t, c9, "127.0.0.1", port9)
	c9.Write([]byte("PING"))
	banner9 := make([]byte, len("TASK9-BANNER"))
	if _, err := io.ReadFull(c9, banner9); err != nil {
		t.Fatal(err)
	}
	c9.Close()
	row = waitLedgerRow(t, tr, port9, true)
	if row.Identity != "task9" || row.TaskID != 9 {
		t.Fatalf("ledger attribution = identity %q task %d, want task9/9", row.Identity, row.TaskID)
	}
	if want := "socks5://" + upstream; row.Egress != want {
		t.Fatalf("task9 egress = %q, want %q", row.Egress, want)
	}
	if got := tunnel.calls.Load(); got != callsAfterTask7 {
		t.Fatalf("task9 reached task7's tunnel (%d →%d)", callsAfterTask7, got)
	}
	if atomic.LoadInt32(hits) <= hitsBefore9 {
		t.Fatal("task9 did not use the default egress")
	}

	// An anonymous client — no credentials at all — keeps the default egress even
	// while a tunnel is bound. The platform reaches this listener that way from two
	// in-process paths: the http custom tool's use_recording_proxy builds a Transport
	// with no credentials, and an MCP server is handed the address as a
	// --proxy-server argument. Neither may break because a task bound a tunnel.
	echoAnon := startEchoTarget(t, "ANON-BANNER")
	portAnon := portOf(t, echoAnon)
	hitsBeforeAnon := atomic.LoadInt32(hits)
	callsBeforeAnon := tunnel.calls.Load()
	socks5RoundTrip(t, addr, "127.0.0.1", portAnon, "PING", "ANON-BANNER")
	row = waitLedgerRow(t, tr, portAnon, true)
	if row.Identity != "" || row.TaskID != 0 {
		t.Fatalf("anonymous client attributed to identity %q task %d, want none", row.Identity, row.TaskID)
	}
	if want := "socks5://" + upstream; row.Egress != want {
		t.Fatalf("anonymous egress = %q, want %q", row.Egress, want)
	}
	if got := tunnel.calls.Load(); got != callsBeforeAnon {
		t.Fatalf("anonymous client reached the task tunnel (%d → %d)", callsBeforeAnon, got)
	}
	if atomic.LoadInt32(hits) <= hitsBeforeAnon {
		t.Fatal("anonymous client did not use the default egress")
	}

	// A credential nobody registered is refused instead of quietly inheriting the
	// default egress: a revoked or mistyped task must not keep working.
	socks5AuthRejected(t, addr, "task404", "whatever")
}
