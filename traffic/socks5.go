package traffic

// SOCKS5 ingress ledger.
//
// The recorder's MITM proxy shares its listening port with a SOCKS5 entry
// (third_party/go-mitmproxy/proxy/socks5.go): the first client byte selects the
// protocol, and a SOCKS5 CONNECT whose payload is not TLS is relayed as raw TCP
// — straight to the target or through the configured egress proxy. That is what
// lets non-HTTP tooling (mysql/redis clients, agent-authored scripts) leave
// through the same egress as the recorded HTTP traffic.
//
// Relayed bytes are never stored. What lands here is metadata only: target,
// byte counts, and whether the egress proxy was used. TLS CONNECTs do not appear
// here at all — they are MITM'd and show up as ordinary exchanges instead.

import (
	"context"
	"database/sql"
	"log"
	"strings"
)

// GlobalListenerID attributes every ledger row to this build's single
// process-wide listener. The listener_id/task_id columns are kept so the table
// stays schema-compatible with a deployment where one recorder serves a
// listener per task (where they carry real values); here they are always this
// constant and 0.
const GlobalListenerID = "global"

const socks5Schema = `
CREATE TABLE IF NOT EXISTS socks5_connections (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL,
  listener_id  TEXT    NOT NULL,
  task_id      INTEGER NOT NULL DEFAULT 0,
  dst_host     TEXT    NOT NULL,
  dst_port     INTEGER NOT NULL,
  bytes_up     INTEGER NOT NULL DEFAULT 0,
  bytes_down   INTEGER NOT NULL DEFAULT 0,
  mitmed       INTEGER NOT NULL DEFAULT 0,
  via_upstream INTEGER NOT NULL DEFAULT 0,
  egress       TEXT    NOT NULL DEFAULT '',
  identity     TEXT    NOT NULL DEFAULT '',
  service      TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_s5_ts   ON socks5_connections(ts);
CREATE INDEX IF NOT EXISTS idx_s5_dst  ON socks5_connections(dst_host, dst_port);
`

// Socks5Conn is one completed raw-TCP relay through the SOCKS5 ingress.
// Metadata only: the relayed content is never recorded anywhere.
type Socks5Conn struct {
	ID          int64  `json:"id"`
	TS          int64  `json:"ts"`
	ListenerID  string `json:"listener_id"`
	TaskID      int64  `json:"task_id"`
	DstHost     string `json:"dst_host"`
	DstPort     int    `json:"dst_port"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	Mitmed      bool   `json:"mitmed"`
	ViaUpstream bool   `json:"via_upstream"`
	// Egress names what the relay actually left through, redacted: the proxy URL
	// without credentials, a dialer's description (a task's tunnel), or "" for a
	// direct dial. ViaUpstream says whether it left this host at all; Egress says
	// how, which is what tells a tunnel apart from a proxy.
	Egress string `json:"egress"`
	// Identity is who the client authenticated as, recorded as presented rather than
	// only as a task id: the string survives a binding being cleared, so a row can
	// still say who it belonged to after the fact.
	Identity string `json:"identity"`
	// Service names the database protocol recognised from the captured head
	// ("" = not captured, or not a recognised database). Only recognised database
	// services have their heads stored.
	Service string `json:"service"`
	// HeadUp/HeadDown carry the captured bytes into the recorder; they never
	// travel in the API response (the body endpoint serves them).
	HeadUp   []byte `json:"-"`
	HeadDown []byte `json:"-"`
}

// recordSocks5Conn writes one metadata row. The traffic write lock (wmu) is
// deliberately NOT taken: a relay finishes on its own schedule, and holding the
// lock HTTP recording serialises on would couple raw-TCP session teardown to
// recording latency. SQLite serialises the insert itself (WAL + busy_timeout).
func (t *Traffic) recordSocks5Conn(c Socks5Conn) {
	res, err := t.db.Exec(`INSERT INTO socks5_connections
(ts,listener_id,task_id,dst_host,dst_port,bytes_up,bytes_down,mitmed,via_upstream,egress,identity,service)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.TS, c.ListenerID, c.TaskID, c.DstHost, c.DstPort, c.BytesUp, c.BytesDown,
		boolInt(c.Mitmed), boolInt(c.ViaUpstream), c.Egress, c.Identity, c.Service)
	if err != nil {
		log.Printf("[traffic] socks5 连接元数据写入失败: %v", err)
		return
	}
	if c.Service != "" && (len(c.HeadUp) > 0 || len(c.HeadDown) > 0) {
		if id, idErr := res.LastInsertId(); idErr == nil {
			t.recordSocks5Body(id, c.Service, c.HeadUp, c.HeadDown)
		}
	}
}

// Socks5Conns returns one page of the raw-connection ledger, newest first.
// dstHostFilter is an optional substring match on the target host, mirroring the
// traffic page's host filter so "what you filtered is what you see".
func (t *Traffic) Socks5Conns(dstHostFilter string, page, size int) (rows []Socks5Conn, total int, err error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	if page < 0 {
		page = 0
	}
	where := ""
	var args []any
	if h := strings.TrimSpace(dstHostFilter); h != "" {
		where = " WHERE dst_host LIKE ?"
		args = append(args, "%"+h+"%")
	}
	if err = t.db.QueryRow(`SELECT COUNT(*) FROM socks5_connections`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rs, err := t.db.Query(`SELECT id,ts,listener_id,task_id,dst_host,dst_port,bytes_up,bytes_down,mitmed,via_upstream,egress,identity,service
FROM socks5_connections`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(append([]any{}, args...), size, page*size)...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var c Socks5Conn
		var mitmed, via int
		if err := rs.Scan(&c.ID, &c.TS, &c.ListenerID, &c.TaskID, &c.DstHost, &c.DstPort,
			&c.BytesUp, &c.BytesDown, &mitmed, &via, &c.Egress, &c.Identity, &c.Service); err != nil {
			return nil, 0, err
		}
		c.Mitmed, c.ViaUpstream = mitmed == 1, via == 1
		rows = append(rows, c)
	}
	return rows, total, rs.Err()
}

// initSocks5Schema applies the ledger schema on the pinned connection initIndex
// already holds (sql.Conn exposes ExecContext, which *sql.DB's ExecContext
// equivalent would route to an arbitrary pooled connection).
//
// CREATE TABLE IF NOT EXISTS never alters an existing table, so columns added
// after the first release are applied here too — otherwise an install created
// before them would keep writing the old shape and every insert would fail.
func (t *Traffic) initSocks5Schema(conn *sql.Conn) error {
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, socks5Schema); err != nil {
		return err
	}
	for _, col := range []struct{ name, decl string }{
		{"egress", `TEXT NOT NULL DEFAULT ''`},
		{"identity", `TEXT NOT NULL DEFAULT ''`},
		{"service", `TEXT NOT NULL DEFAULT ''`},
	} {
		if err := addColumnIfMissing(ctx, conn, "socks5_connections", col.name, col.decl); err != nil {
			return err
		}
	}
	// Captured database heads live in their own table: one row per connection,
	// written only for recognised services.
	if _, err := conn.ExecContext(ctx, socks5BodiesSchema); err != nil {
		return err
	}
	return nil
}

// addColumnIfMissing adds a column to an existing table. ALTER TABLE has no
// IF NOT EXISTS, so the current shape is read first. Both statements run on the
// caller's pinned connection: a pooled *sql.DB is free to route them to different
// connections, which would make the check and the ALTER disagree. Identifiers are
// interpolated, so callers pass constants — never anything derived from input.
func addColumnIfMissing(ctx context.Context, conn *sql.Conn, table, column, decl string) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notNull, pk int
			name, ctype      string
			dflt             any
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+decl)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
