package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/payloads"
)

func doJSON(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func manifestEntry(t *testing.T, dir, name string) payloads.Entry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, payloads.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var man payloads.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	for _, e := range man.Files {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("manifest 里没有 %s", name)
	return payloads.Entry{}
}

// 用户上传的说明必须进 manifest（agent 才知道这是什么、怎么用），并且能改。
func TestFileDescriptionReachesManifest(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	mux := filesAPITestMux(s)
	mux.HandleFunc("PUT /api/files/meta", s.updateFileMeta)

	body, ct := multipartBody(t, "httpshell.php", []byte("<?php // mine ?>"))
	req := httptest.NewRequest("POST", "/api/files/upload?description=%E5%86%85%E7%BD%91+webshell+%E5%B7%A5%E5%85%B7", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("上传 %d %s", rec.Code, rec.Body)
	}
	if e := manifestEntry(t, m.PayloadDir(), "httpshell.php"); e.Description != "内网 webshell 工具" {
		t.Fatalf("manifest 里的说明 = %q", e.Description)
	}

	// 列表也要带上（UI 直接显示）
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/files", nil))
	var list FileListDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, f := range list.Files {
		if f.Name == "httpshell.php" {
			got = f.Description
		}
	}
	if got != "内网 webshell 工具" {
		t.Fatalf("列表里的说明 = %q", got)
	}

	// 事后改说明
	rec = doJSON(t, mux, "PUT", "/api/files/meta", `{"name":"httpshell.php","description":"改过的说明"}`)
	if rec.Code != 200 {
		t.Fatalf("改说明 %d %s", rec.Code, rec.Body)
	}
	if e := manifestEntry(t, m.PayloadDir(), "httpshell.php"); e.Description != "改过的说明" {
		t.Fatalf("改后 manifest 说明 = %q", e.Description)
	}
}

// 这是这一轮的核心诉求：平台生成的载荷**可以被用户替换**，而且替换后 Sync 不得
// 把它覆盖回去（否则"我换了个能用的载荷"下次启动就被还原）。
func TestUserCanReplaceGeneratedPayloadAndSyncKeepsIt(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	mux := filesAPITestMux(s)
	mux.HandleFunc("POST /api/files/revert", s.revertFile)

	if _, err := payloads.Sync(m.dir); err != nil {
		t.Fatal(err)
	}
	const name = "tunnel.php"
	orig, err := os.ReadFile(filepath.Join(m.PayloadDir(), name))
	if err != nil {
		t.Fatalf("平台载荷应当存在: %v", err)
	}
	mine := []byte("<?php // my own tunnel payload ?>")

	body, ct := multipartBody(t, name, mine)
	req := httptest.NewRequest("POST", "/api/files/upload?description=我自己的隧道载荷", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("替换上传 %d %s", rec.Code, rec.Body)
	}

	// 再来一次 Sync（等价于重启）：用户版本必须还在。
	if _, err := payloads.Sync(m.dir); err != nil {
		t.Fatal(err)
	}
	now, err := os.ReadFile(filepath.Join(m.PayloadDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(now, mine) {
		t.Fatal("Sync 把用户替换的载荷覆盖回去了（这正是要避免的）")
	}
	e := manifestEntry(t, m.PayloadDir(), name)
	if !e.Override {
		t.Fatal("manifest 应当标注这个载荷已被用户替换（override）")
	}
	if e.Description != "我自己的隧道载荷" {
		t.Fatalf("说明 = %q", e.Description)
	}

	// 「恢复平台版本」应当把官方载荷找回来，并清掉说明/替换标记。
	rec = doJSON(t, mux, "POST", "/api/files/revert", `{"name":"tunnel.php"}`)
	if rec.Code != 200 {
		t.Fatalf("恢复 %d %s", rec.Code, rec.Body)
	}
	back, err := os.ReadFile(filepath.Join(m.PayloadDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, orig) {
		t.Fatal("恢复之后应当是平台原始载荷")
	}
	e = manifestEntry(t, m.PayloadDir(), name)
	if e.Override || e.Description != "" {
		t.Fatalf("恢复后不该还有 override/说明: %+v", e)
	}
	// 恢复后又不允许直接删了
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/files?name=tunnel.php", nil))
	if rec.Code != 400 {
		t.Fatalf("恢复后的平台载荷应当拒删(400)，得到 %d", rec.Code)
	}
}
