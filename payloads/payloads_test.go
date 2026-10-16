package payloads

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Autumn-27/artex/regeorg"
	"testing"
)

// 文件库的核心承诺：目录里的文件与 manifest 描述必须一致 —— agent 是照着 manifest 干活
// 的，描述与字节不符就等于让它上传错东西。
func TestSyncWritesFilesAndManifest(t *testing.T) {
	dir := t.TempDir()
	man, err := Sync(dir)
	if err != nil {
		t.Fatal(err)
	}
	if man.Dir != Dir(dir) {
		t.Fatalf("dir = %q，想要 %q", man.Dir, Dir(dir))
	}
	if man.Version != ManifestVersion || man.Usage == "" {
		t.Fatalf("manifest 头部不完整: %+v", man)
	}
	if len(man.Files) != 9 {
		t.Fatalf("条目数 = %d，想要 9（Neo-reGeorg 的九个模板）", len(man.Files))
	}
	seen := map[string]bool{}
	backends := map[string]int{}
	for _, e := range man.Files {
		seen[e.Name] = true
		if e.Backend == "" {
			t.Errorf("条目 %s 没有标注后端", e.Name)
		}
		backends[e.Backend]++
		if e.Path == "" || e.SHA256 == "" || e.Size == 0 {
			t.Errorf("条目缺少 path/sha256/size: %+v", e)
		}
		if e.Deploy == "" || e.Target == "" || e.Requires == "" || e.TunnelURL == "" {
			t.Errorf("条目描述不完整（agent 要照它选文件）: %+v", e)
		}
		b, err := os.ReadFile(e.Path)
		if err != nil {
			t.Errorf("清单里的文件不存在: %v", err)
			continue
		}
		if len(b) != e.Size || sha256hex(b) != e.SHA256 {
			t.Errorf("%s 的 size/sha256 与实际字节不符", e.Name)
		}
	}
	for _, want := range []string{
		"tunnel.php", "tunnel.jsp", "tunnel.jspx", "tunnel.aspx", "tunnel.ashx", "tunnel.go",
		"tunnel.js", "NeoReGeorg.cs", "NeoreGeorg.java",
	} {
		if !seen[want] {
			t.Errorf("清单缺少 %s", want)
		}
	}
	if backends["regeorg"] != 9 || len(backends) != 1 {
		t.Errorf("后端分布 = %v，想要只有 regeorg:9", backends)
	}
	// 生成出来的 Neo-reGeorg 载荷必须真的写进了平台的固定参数：客户端与载荷靠它对齐，
	// 一旦有人改了参数却漏改生成器，这里就会炸。
	for _, name := range []string{"tunnel.php", "tunnel.jsp", "tunnel.aspx", "tunnel.ashx", "tunnel.go", "tunnel.js"} {
		raw, err := os.ReadFile(filepath.Join(Dir(dir), name))
		if err != nil {
			t.Errorf("读 %s 失败: %v", name, err)
			continue
		}
		if !bytes.Contains(raw, []byte(regeorg.TunnelChars)) {
			t.Errorf("%s 里没有平台的字母表参数", name)
		}
		if !bytes.Contains(raw, []byte(strconv.Itoa(regeorg.BLVLOffset))) {
			t.Errorf("%s 里没有平台的长度偏移参数", name)
		}
	}

	// manifest.json 必须能被原样读回来（agent 就是直接读这个文件）。
	raw, err := os.ReadFile(filepath.Join(Dir(dir), ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("manifest.json 不是合法 JSON: %v", err)
	}
	if len(back.Files) != len(man.Files) || back.Files[0].Path != man.Files[0].Path {
		t.Fatalf("读回来的 manifest 与返回的不一致")
	}
}

// 投放方式是 agent 选文件的关键字段，必须与上游文档一致：网页马是"上传文件"，
// go/node 是"跑进程"，.cs/.java 是"编译注入"。
func TestCatalogDeployModels(t *testing.T) {
	want := map[string]Deploy{
		"tunnel.php":      DeployUploadFile,
		"tunnel.jsp":      DeployUploadFile,
		"tunnel.jspx":     DeployUploadFile,
		"tunnel.aspx":     DeployUploadFile,
		"tunnel.ashx":     DeployUploadFile,
		"tunnel.go":       DeployRunProcess,
		"tunnel.js":       DeployRunProcess,
		"NeoReGeorg.cs":   DeployCompileInject,
		"NeoreGeorg.java": DeployCompileInject,
	}
	man, err := Sync(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range man.Files {
		w, ok := want[e.Name]
		if !ok {
			t.Errorf("出现未预期的文件 %s", e.Name)
			continue
		}
		if e.Deploy != w {
			t.Errorf("%s 的投放方式 = %q，想要 %q", e.Name, e.Deploy, w)
		}
	}
}

// 同步必须幂等，并且能修掉被改动的文件：嵌入的载荷一旦随客户端升级，磁盘上的旧副本
// 不能被留在那里配新客户端。
func TestSyncIsIdempotentAndHealsTamperedFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Sync(dir); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(Dir(dir), "tunnel.php")
	if err := os.WriteFile(target, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(dir); err != nil {
		t.Fatal(err)
	}
	healed, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(healed) == "tampered" {
		t.Fatal("同步没有修复被改动的载荷")
	}
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(dir); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("重复同步改变了文件内容")
	}
}

func TestSyncRequiresDataDir(t *testing.T) {
	if _, err := Sync(""); err == nil {
		t.Fatal("空数据目录应当报错")
	}
}
