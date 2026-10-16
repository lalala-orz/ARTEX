package server

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/traffic"
)

// TestGetTrafficSocks5Handler exercises the raw-TCP ledger endpoint without a
// database: the handler only needs the Manager's recorder plus its capture flag,
// so the fixture is a Manager carrying exactly those two things.
func TestGetTrafficSocks5Handler(t *testing.T) {
	tr, err := traffic.Open(filepath.Join(t.TempDir(), "traffic"), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, err := tr.DB().Exec(`INSERT INTO socks5_connections
(ts,listener_id,task_id,dst_host,dst_port,bytes_up,bytes_down,mitmed,via_upstream)
VALUES(?,?,?,?,?,?,?,?,?)`,
		1700000000, traffic.GlobalListenerID, 0, "10.0.0.9", 3306, 41, 512, 0, 1); err != nil {
		t.Fatal(err)
	}

	m := &Manager{dir: t.TempDir(), tasks: map[string]*Task{}, traffic: tr}
	m.trafficOn = true
	s := &Server{m: m}

	type resp struct {
		Enabled     bool                 `json:"enabled"`
		Socks       string               `json:"socks"`
		Total       int                  `json:"total"`
		Connections []traffic.Socks5Conn `json:"connections"`
	}
	get := func(query string) resp {
		t.Helper()
		rec := httptest.NewRecorder()
		s.getTrafficSocks5(rec, httptest.NewRequest("GET", "/api/traffic/socks5"+query, nil))
		if rec.Code != 200 {
			t.Fatalf("GET %s: status=%d body=%s", query, rec.Code, rec.Body.String())
		}
		var out resp
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("GET %s: %v (body=%s)", query, err, rec.Body.String())
		}
		return out
	}

	got := get("?page=0&size=50")
	if !got.Enabled {
		t.Fatalf("capture is on, enabled must be true: %+v", got)
	}
	if got.Socks == "" {
		t.Fatalf("capture on must advertise the SOCKS5 endpoint: %+v", got)
	}
	if got.Total != 1 || len(got.Connections) != 1 {
		t.Fatalf("ledger row not returned: %+v", got)
	}
	c := got.Connections[0]
	if c.DstHost != "10.0.0.9" || c.DstPort != 3306 || c.BytesUp != 41 || c.BytesDown != 512 || !c.ViaUpstream {
		t.Fatalf("ledger row wrong: %+v", c)
	}

	// A filter matching nothing must still serialise an array, not null: the UI
	// iterates it unconditionally.
	rec := httptest.NewRecorder()
	s.getTrafficSocks5(rec, httptest.NewRequest("GET", "/api/traffic/socks5?host=nothing-matches", nil))
	if !strings.Contains(rec.Body.String(), `"connections":[]`) {
		t.Fatalf("empty result should serialise an empty array, got %s", rec.Body.String())
	}

	// Capture off: the ledger is still readable, but no SOCKS5 endpoint is
	// advertised — agents are not pointed at an ingress the operator turned off.
	m.trafficOn = false
	if off := get(""); off.Socks != "" {
		t.Fatalf("capture off must not advertise a SOCKS5 endpoint: %+v", off)
	}
}
