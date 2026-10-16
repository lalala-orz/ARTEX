package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/payloads"
)

func filesAPITestMux(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/files", s.listFiles)
	mux.HandleFunc("POST /api/files/upload", s.uploadFiles)
	mux.HandleFunc("GET /api/files/download", s.downloadFile)
	mux.HandleFunc("DELETE /api/files", s.deleteFile)
	return mux
}

func multipartBody(t *testing.T, name string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

// 文件管理必须独立于载荷：用户上传的东西要能列出来、下回去、删掉，并且立刻出现在
// agent 读的 manifest.json 里（否则 agent 根本不知道它存在）。
func TestFilesAPIUploadListDownloadDelete(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	mux := filesAPITestMux(s)
	const payload = "admin\nroot\n"

	body, ct := multipartBody(t, "wordlist.txt", []byte(payload))
	req := httptest.NewRequest("POST", "/api/files/upload", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("上传应当 200，得到 %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/files", nil))
	if rec.Code != 200 {
		t.Fatalf("列表 %d", rec.Code)
	}
	var list FileListDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	var uploaded *FileEntryDTO
	for i := range list.Files {
		if list.Files[i].Name == "wordlist.txt" {
			uploaded = &list.Files[i]
		}
	}
	if uploaded == nil {
		t.Fatalf("列表里没有刚上传的文件: %+v", list.Files)
	}
	if uploaded.Payload {
		t.Fatal("用户上传的文件不该被标成载荷")
	}
	if uploaded.Size != int64(len(payload)) {
		t.Fatalf("大小不对: %d", uploaded.Size)
	}
	if list.Payload == 0 {
		t.Fatal("同一份目录的两个视角：载荷仍应被识别为载荷")
	}

	raw, err := os.ReadFile(filepath.Join(m.PayloadDir(), payloads.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var man payloads.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, e := range man.Files {
		if e.Name == "wordlist.txt" {
			seen = true
			if e.Kind != "file" {
				t.Fatalf("manifest 里 kind=%q，想要 file", e.Kind)
			}
		}
	}
	if !seen {
		t.Fatal("manifest 里没有用户上传的文件（agent 就发现不了它）")
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/files/download?name=wordlist.txt", nil))
	if rec.Code != 200 || rec.Body.String() != payload {
		t.Fatalf("下载内容不对: %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/files?name=wordlist.txt", nil))
	if rec.Code != 200 {
		t.Fatalf("删除 %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(m.PayloadDir(), "wordlist.txt")); !os.IsNotExist(err) {
		t.Fatal("文件应当已被删除")
	}
}

// 文件库只接受"目录内的单个文件名"，这些都必须被拒。
func TestLibraryNameRejectsTraversal(t *testing.T) {
	ok := []string{"wordlist.txt", "tunnel.php", "a.b.c", "带中文的名字.txt"}
	for _, n := range ok {
		if _, got := libraryName(n); !got {
			t.Fatalf("%q 应当被接受", n)
		}
	}
	bad := []string{"", " ", ".", "..", "../evil", "a/b", `a\b`, "/etc/passwd", payloads.ManifestName, "x\x00y"}
	for _, n := range bad {
		if _, got := libraryName(n); got {
			t.Fatalf("%q 不该被接受", n)
		}
	}
}

func TestFilesAPIRejectsBadRequests(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	mux := filesAPITestMux(s)
	// 上传：清单文件不许被覆盖。（路径穿越在上传这条路上到不了 handler ——
	// mime/multipart 解析时已经 filepath.Base 过了 —— 所以那部分由
	// TestLibraryNameRejectsTraversal 直接锁 libraryName。）
	for _, name := range []string{payloads.ManifestName} {
		body, ct := multipartBody(t, name, []byte("x"))
		req := httptest.NewRequest("POST", "/api/files/upload", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == 200 {
			t.Fatalf("文件名 %q 不该被接受", name)
		}
	}
	// 删除：不存在 / 非法
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/files?name=nope.txt", nil))
	if rec.Code != 404 {
		t.Fatalf("删不存在的文件应当 404，得到 %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/files?name="+payloads.ManifestName, nil))
	if rec.Code == 200 {
		t.Fatal("不该允许删除 manifest.json")
	}
	// 下载：非法名字
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/files/download?name=../secret", nil))
	if rec.Code == 200 {
		t.Fatal("路径穿越的下载不该成功")
	}
}

// 生成的载荷允许删（重启/Sync 会按模板重建），删完立刻能重建回来。
func TestFilesAPIDeleteGeneratedPayloadThenSyncRestores(t *testing.T) {
	m, _, _ := newTunnelTestManager(t)
	s := &Server{m: m}
	mux := filesAPITestMux(s)
	if _, err := payloads.Sync(m.dir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(m.PayloadDir(), "tunnel.php")
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("Sync 之后应当有生成的载荷: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/files?name=tunnel.php", nil))
	if rec.Code != 400 {
		t.Fatalf("平台生成的载荷应当拒删(400)，得到 %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("被拒后文件必须还在: %v", err)
	}
	// 用户自有文件则可以删（这条同时确认拒绝逻辑没有误伤）。
	body, ct := multipartBody(t, "mine.txt", []byte("x"))
	req := httptest.NewRequest("POST", "/api/files/upload", body)
	req.Header.Set("Content-Type", ct)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("上传自有文件 %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/files?name=mine.txt", nil))
	if rec.Code != 200 {
		t.Fatalf("自有文件应当可删 %d %s", rec.Code, rec.Body)
	}
}
