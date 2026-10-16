package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/payloads"
)

// 平台文件库（data/files）的**通用**管理：列表、上传、下载、删除。
//
// 它与「载荷」是同一份目录的两个视角：
//   - 载荷：平台按 Neo-reGeorg 模板生成、并带投放说明（deploy/target/caveats）的那几个文件；
//   - 文件：用户自己的东西 —— 工具、字典、证书、脚本、样本……
//
// 之前对外只有 /api/payloads 这一个载荷视角的入口（列表+下载），于是"文件管理"实际上被
// 载荷管理取代了：用户没法上传自己的文件。这里把文件管理独立出来，载荷清单退化成这份
// 列表上的一个视图（`payload: true`）。

const (
	// maxLibraryUpload 是单个上传请求的上限。载荷本身只有几 KB，这里是给工具/字典/样本
	// 留的余量；再大就该走任务工作目录（/api/workspace/upload）而不是平台文件库。
	maxLibraryUpload = 256 << 20
	// libraryHashLimit 之上不再为列表计算 sha256：启动时对几百 MB 的文件做全量哈希
	// 只会拖慢启动，而列表并不需要它。
	libraryHashLimit = 8 << 20
)

// libraryName 校验并归一化一个文件库文件名：只允许目录内的**单个**文件名。
// 返回 false 表示这个名字不能用于上传/删除（路径穿越、目录、保留名）。
func libraryName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || name == "." || name == ".." {
		return "", false
	}
	// 先按平台无关的方式取 basename，再要求它和输入完全一致：这样 "a/b"、"..\\c" 都被拒。
	if base := filepath.Base(name); base != name {
		return "", false
	}
	if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return "", false
	}
	if name == payloads.ManifestName {
		return "", false // 清单由平台生成
	}
	return name, true
}

// libraryPath 把文件名解析成文件库内的绝对路径，并确认它确实落在库里。
func (s *Server) libraryPath(name string) (string, bool) {
	clean, ok := libraryName(name)
	if !ok {
		return "", false
	}
	dir := s.m.PayloadDir()
	if dir == "" {
		return "", false
	}
	abs := filepath.Join(dir, clean)
	rel, err := filepath.Rel(dir, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return abs, true
}

// FileEntryDTO 是文件库列表的一行：文件本身的信息 + （如果是载荷）它的投放说明。
type FileEntryDTO struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	SHA256  string `json:"sha256,omitempty"`
	// Payload 为真表示这是平台生成的隧道载荷（重启后会按模板重建）。
	Payload bool `json:"payload"`
	// 下面几项只在 Payload 为真时有意义，直接来自 manifest。
	Kind     string   `json:"kind,omitempty"`
	Backend  string   `json:"backend,omitempty"`
	Deploy   string   `json:"deploy,omitempty"`
	Target   string   `json:"target,omitempty"`
	Requires string   `json:"requires,omitempty"`
	Tunnel   string   `json:"tunnel_url,omitempty"`
	Notes    []string `json:"notes,omitempty"`
	Caveats  []string `json:"caveats,omitempty"`
	// Description 是用户写的"这是什么、怎么用"（agent 也读得到）；Override 表示这个
	// 载荷已被用户用自己的版本替换（Sync 不会再覆盖它）。
	Description string `json:"description,omitempty"`
	Override    bool   `json:"override,omitempty"`
}

type FileListDTO struct {
	Dir     string         `json:"dir"`
	Files   []FileEntryDTO `json:"files"`
	Payload int            `json:"payload_count"`
	Total   int            `json:"total"`
}

// listFiles returns every file in the platform library, marking which ones are
// generated tunnel payloads. It reads the directory (not the manifest) so a file
// dropped in by hand still shows up, and enriches from the manifest when it can.
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	dir := s.m.PayloadDir()
	if dir == "" {
		writeJSON(w, 200, FileListDTO{Files: []FileEntryDTO{}})
		return
	}
	byName := map[string]payloads.Entry{}
	if raw, err := os.ReadFile(filepath.Join(dir, payloads.ManifestName)); err == nil {
		var man payloads.Manifest
		if json.Unmarshal(raw, &man) == nil {
			for _, e := range man.Files {
				byName[e.Name] = e
			}
		}
	}
	out := FileListDTO{Dir: dir, Files: []FileEntryDTO{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, 200, out)
		return
	}
	for _, de := range entries {
		if de.IsDir() || de.Name() == payloads.ManifestName {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		row := FileEntryDTO{
			Name:    de.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		}
		if e, ok := byName[de.Name()]; ok && e.Kind != "" && e.Kind != "file" {
			row.Payload = true
			row.Kind, row.Backend, row.Deploy = e.Kind, e.Backend, string(e.Deploy)
			row.Target, row.Requires, row.Tunnel = e.Target, e.Requires, e.TunnelURL
			row.Notes, row.Caveats = e.Notes, e.Caveats
		}
		if e, ok := byName[de.Name()]; ok {
			row.Description = e.Description
			row.Override = e.Override
		}
		if info.Size() <= libraryHashLimit {
			if b, err := os.ReadFile(filepath.Join(dir, de.Name())); err == nil {
				row.SHA256 = sha256hexBytes(b)
			}
		}
		if row.Payload {
			out.Payload++
		}
		out.Files = append(out.Files, row)
	}
	// 载荷在前（它们是常用项），其余按名字排。
	sort.SliceStable(out.Files, func(i, j int) bool {
		if out.Files[i].Payload != out.Files[j].Payload {
			return out.Files[i].Payload
		}
		return out.Files[i].Name < out.Files[j].Name
	})
	out.Total = len(out.Files)
	writeJSON(w, 200, out)
}

// uploadFiles stores one or more uploaded files in the platform library. The
// manifest is refreshed afterwards so agents see what the user just added.
func (s *Server) uploadFiles(w http.ResponseWriter, r *http.Request) {
	dir := s.m.PayloadDir()
	if dir == "" {
		writeErr(w, 400, "平台文件库未就绪")
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "创建文件库目录失败："+err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLibraryUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制："+err.Error())
		return
	}
	headers := r.MultipartForm.File["file"]
	if len(headers) == 0 {
		writeErr(w, 400, "缺少上传文件（表单字段 file）")
		return
	}
	saved := make([]string, 0, len(headers))
	for _, hdr := range headers {
		clean, ok := libraryName(hdr.Filename)
		if !ok {
			writeErr(w, 400, fmt.Sprintf("非法文件名 %q（只允许单个文件名，且不能覆盖 %s）", hdr.Filename, payloads.ManifestName))
			return
		}
		src, err := hdr.Open()
		if err != nil {
			writeErr(w, 400, "读取上传内容失败："+err.Error())
			return
		}
		// 先写临时文件再改名：中途失败不会留下半个文件顶着正式名字。
		tmp := filepath.Join(dir, "."+clean+".part")
		dst, err := os.Create(tmp)
		if err != nil {
			_ = src.Close()
			writeErr(w, 500, "写入失败："+err.Error())
			return
		}
		_, cerr := io.Copy(dst, src)
		_ = src.Close()
		if err := dst.Close(); err != nil && cerr == nil {
			cerr = err
		}
		if cerr != nil {
			_ = os.Remove(tmp)
			writeErr(w, 500, "写入失败："+cerr.Error())
			return
		}
		if err := os.Rename(tmp, filepath.Join(dir, clean)); err != nil {
			_ = os.Remove(tmp)
			writeErr(w, 500, "保存失败："+err.Error())
			return
		}
		// 说明与"是否替换了平台载荷"一起记进随附元数据：换掉一个不能用的载荷是正常
		// 需求，记成 override 后 Sync 就不会再把它覆盖回去。
		desc := strings.TrimSpace(r.FormValue("description"))
		if desc == "" {
			desc = strings.TrimSpace(r.URL.Query().Get("description"))
		}
		if err := payloads.SetFileMeta(s.m.dir, clean, payloads.FileMeta{
			Description: desc,
			Override:    s.isGeneratedPayload(clean),
		}); err != nil {
			writeErr(w, 500, "文件已保存，但写入说明失败："+err.Error())
			return
		}
		saved = append(saved, clean)
	}
	// 刷新清单：agent 读的是 manifest.json，上传完必须让它立刻看到新文件。
	if _, err := payloads.Sync(s.m.dir); err != nil {
		writeErr(w, 500, "文件已保存，但刷新清单失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"saved": saved, "count": len(saved), "dir": dir})
}

// downloadFile serves one library file by name (jailed to the library directory).
func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.libraryPath(r.URL.Query().Get("name"))
	if !ok {
		writeErr(w, 400, "非法文件名")
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		writeErr(w, 404, "文件不存在")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", info.Name()))
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// deleteFile removes one library file. Generated payloads can go too: Sync
// rebuilds them on the next start (the UI says so).
func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	abs, ok := s.libraryPath(name)
	if !ok {
		writeErr(w, 400, "非法文件名")
		return
	}
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		writeErr(w, 404, "文件不存在")
		return
	}
	// 平台生成的载荷不允许删：它们由模板生成，Sync 会立刻把它重建回来（删了又回来
	// 比不让删更让人困惑）。要让某个载荷消失，得改生成器，不是点删除。
	if s.isGeneratedPayload(info.Name()) && !s.isOverridden(info.Name()) {
		writeErr(w, 400, "这是平台生成的隧道载荷，不能删除；要换掉它请直接上传同名文件（会记为「已替换」）")
		return
	}
	if err := os.Remove(abs); err != nil {
		writeErr(w, 500, "删除失败："+err.Error())
		return
	}
	_ = payloads.DropFileMeta(s.m.dir, info.Name())
	if _, err := payloads.Sync(s.m.dir); err != nil {
		writeErr(w, 500, "已删除，但刷新清单失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": info.Name()})
}

// sha256hexBytes 是文件库自用的哈希：payloads 包的同名函数不导出，且那边语义是载荷校验。
func sha256hexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isGeneratedPayload 判断某个文件是不是平台按模板生成的隧道载荷（manifest 里
// kind != "file" 的那些）。用户自有文件一律 false。
func (s *Server) isGeneratedPayload(name string) bool {
	dir := s.m.PayloadDir()
	if dir == "" {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(dir, payloads.ManifestName))
	if err != nil {
		return false
	}
	var man payloads.Manifest
	if json.Unmarshal(raw, &man) != nil {
		return false
	}
	for _, e := range man.Files {
		if e.Name == name {
			return e.Kind != "" && e.Kind != "file"
		}
	}
	return false
}

// isOverridden 报告某个文件名是否被用户用自己的版本替换过。
func (s *Server) isOverridden(name string) bool {
	return payloads.LoadMeta(s.m.dir).Files[name].Override
}

// updateFileMeta 改一个文件的说明（PUT /api/files/meta {"name","description"}）。
// Override 保持原样：编辑说明不该改变"这是不是用户替换过的载荷"。
func (s *Server) updateFileMeta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON："+err.Error())
		return
	}
	name, ok := libraryName(req.Name)
	if !ok {
		writeErr(w, 400, "非法文件名")
		return
	}
	if _, err := os.Stat(filepath.Join(s.m.PayloadDir(), name)); err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	fm := payloads.LoadMeta(s.m.dir).Files[name]
	fm.Description = strings.TrimSpace(req.Description)
	if err := payloads.SetFileMeta(s.m.dir, name, fm); err != nil {
		writeErr(w, 500, "保存说明失败："+err.Error())
		return
	}
	if _, err := payloads.Sync(s.m.dir); err != nil {
		writeErr(w, 500, "说明已保存，但刷新清单失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"name": name, "description": fm.Description})
}

// revertFile 丢掉用户的替换，让平台生成的版本回来（POST /api/files/revert {"name"}）。
func (s *Server) revertFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON："+err.Error())
		return
	}
	name, ok := libraryName(req.Name)
	if !ok {
		writeErr(w, 400, "非法文件名")
		return
	}
	if !s.isGeneratedPayload(name) {
		writeErr(w, 400, "这不是平台生成的载荷，没有可恢复的版本")
		return
	}
	if err := os.Remove(filepath.Join(s.m.PayloadDir(), name)); err != nil && !os.IsNotExist(err) {
		writeErr(w, 500, "删除替换版本失败："+err.Error())
		return
	}
	if err := payloads.DropFileMeta(s.m.dir, name); err != nil {
		writeErr(w, 500, "清理元数据失败："+err.Error())
		return
	}
	if _, err := payloads.Sync(s.m.dir); err != nil {
		writeErr(w, 500, "已恢复，但刷新清单失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"reverted": name})
}

// getTrafficEgresses 汇总两份流量里实际出现过的出口值（去重、排序），
// 给流量页的出口下拉框用。前端把空值渲染成「直连」。
func (s *Server) getTrafficEgresses(w http.ResponseWriter, r *http.Request) {
	tr := s.m.Traffic()
	if tr == nil {
		writeJSON(w, 200, map[string]any{"egresses": []string{}})
		return
	}
	values, err := tr.EgressValues()
	if err != nil {
		writeErr(w, 500, "汇总出口失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"egresses": values})
}
