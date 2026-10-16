// Package payloads is the platform's agent-facing file library.
//
// The platform materialises the files an agent needs onto disk, next to a
// manifest.json that describes each one. An agent that has just taken a host reads
// the manifest, picks the artefact that matches the target, uploads it itself and
// then asks for a tunnel — so nothing large ever has to travel through a context
// window, and the agent always sees exactly which files exist and what they need.
//
// Files are generated from the shipped Neo-reGeorg templates rather than copied from a
// loose directory: a payload and the client that talks to it are one protocol, so
// shipping them together is what keeps a version bump from pairing a new client with
// an old payload.
package payloads

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/regeorg"
)

const (
	// LibraryDir sits directly under the platform data dir.
	LibraryDir = "files"
	// ManifestName is the description file the agent reads first.
	ManifestName = "manifest.json"
	// ManifestVersion bumps when the manifest's shape changes.
	ManifestVersion = 1
)

// Deploy is how a file gets onto a target. The distinction matters to the agent: a
// drop-in web file is uploaded and fetched by URL, while a standalone process needs
// command execution, and an exploit request is neither.
type Deploy string

const (
	// DeployUploadFile: put it under a web-accessible path and use its URL.
	DeployUploadFile Deploy = "upload-file"
	// DeployRunProcess: execute it on the target (needs a shell or code execution).
	DeployRunProcess Deploy = "run-process"
	// DeployExploitRequest: send the file verbatim as an HTTP request.
	DeployExploitRequest Deploy = "exploit-request"
	// DeployCompileInject: compile it and inject it into a running app domain.
	DeployCompileInject Deploy = "compile-inject"
)

// Entry describes one file in the library.
type Entry struct {
	// Kind 是载荷类型（php/jsp/aspx/…），生成器按它取模板。
	Kind string `json:"kind"`
	// Backend 说明这份载荷配哪个隧道后端；平台当前只有 regeorg。
	Backend string `json:"backend"`
	Name    string `json:"name"`
	// Path is the absolute path of the file in the library, filled in at sync time so
	// the agent can use the manifest without joining anything itself.
	Path      string   `json:"path"`
	Deploy    Deploy   `json:"deploy"`
	Target    string   `json:"target"`
	Requires  string   `json:"requires"`
	TunnelURL string   `json:"tunnel_url"`
	Notes     []string `json:"notes,omitempty"`
	Caveats   []string `json:"caveats,omitempty"`
	SHA256    string   `json:"sha256"`
	Size      int      `json:"size"`
	// Description 是用户给这个文件写的"这是什么、怎么用"（存在随附元数据 meta.go
	// 里，Sync 时合并进来）。agent 只看文件名并不知道 suo5.php 之类的用途。
	Description string `json:"description,omitempty"`
	// Override 为真表示这个文件名被用户用自己的版本替换过：Sync 不会再用平台生成的
	// 字节覆盖它（换了个能用的载荷，下次启动不该被还原）。
	Override bool `json:"override,omitempty"`
}

// Manifest is what the agent reads to find out what exists.
type Manifest struct {
	Version     int     `json:"version"`
	GeneratedAt string  `json:"generated_at"`
	Dir         string  `json:"dir"`
	Usage       string  `json:"usage"`
	Files       []Entry `json:"files"`
}

const usageText = "拿到目标权限后：1) 读本文件挑一个匹配目标运行时的条目；2) 按 deploy 字段的方式把它投放上去（upload-file=上传到 Web 可访问路径；run-process=在目标上执行；exploit-request=原样发送该 HTTP 请求；compile-inject=编译后注入）；3) 上传前后可用 sha256 校验文件是否完整；4) 把可访问的 URL 交给 tunnel_up 建隧道。"

// regeorgCatalog 是平台**生成**的 Neo-reGeorg 载荷（上游模板 + 平台固定参数）。
//
// 与下面那批的区别：那些是内嵌的静态文件，这些必须按模板现场生成——Neo-reGeorg 的载荷里
// 要写进字母表、长度偏移等参数，直接投放原始模板是连不上的。
//
// 平台默认后端就是 Neo-reGeorg：它的 PHP 载荷为"单 Session 多 TCP 连接"而写，实测在真实
// Apache 站点上连续多次请求全部成功；载荷本身只有 5.7KB。
func regeorgCatalog() []Entry {
	return []Entry{
		{
			Kind: "php", Backend: "regeorg", Deploy: DeployUploadFile,
			Target: "PHP 网站（Nginx / Apache + PHP-FPM 或 mod_php）", Requires: "PHP 5.4+（建议 5.6+）",
			TunnelURL: "上传后的可访问 URL，例如 http://target/uploads/tunnel.php",
			Notes: []string{
				"PHP 目标的首选载荷，也是隧道默认后端。",
				"同一个 PHP Session 里可以并存多条 TCP 连接（参考 pivotnacci 的实现），连续多次请求实测都成功。",
				"载荷会 header_remove('set-cookie') 并复用同一 session，所以同一条隧道的多个请求属于同一会话。",
			},
			Caveats: []string{
				"一条 CONNECT 会占住一个 PHP 请求/worker 直到该连接关闭——适合访问内网站点与内网服务，不要拿它并发扫描；用完及时关隧道。",
				"需要目标允许 fsockopen（载荷自己会打开 allow_url_fopen）。",
				"别用 PHP 内置开发服务器（php -S）跑载荷：它是单进程单线程，隧道自连会**死锁**（实测探活超时）。用 php-fpm/Nginx/Apache，或至少给 php -S 加 PHP_CLI_SERVER_WORKERS。",
			},
		},
		{
			Kind: "jsp", Backend: "regeorg", Deploy: DeployUploadFile,
			Target: "Java Servlet 容器（Tomcat/Jetty/Resin/JBoss/Weblogic 等）", Requires: "实现 Servlet 规范即可",
			TunnelURL: "上传后的可访问 URL，例如 http://target:8080/tunnel.jsp",
			Notes: []string{
				"载荷自己开线程，CONNECT 立刻返回，所以客户端是同步确认而不是长轮询。",
				"不依赖 Session，无 Cookie 环境也能用。",
			},
		},
		{
			Kind: "jspx", Backend: "regeorg", Deploy: DeployUploadFile,
			Target: "Java Servlet 容器（.jsp 后缀被过滤时用它）", Requires: "实现 Servlet 规范即可",
			TunnelURL: "上传后的可访问 URL，例如 http://target:8080/tunnel.jspx",
			Notes:     []string{"与 tunnel.jsp 等价，只是后缀不同，用于绕过后缀限制。"},
		},
		{
			Kind: "aspx", Backend: "regeorg", Deploy: DeployUploadFile,
			Target: "IIS + .NET Framework 2.0+", Requires: ".NET Framework 2.0+",
			TunnelURL: "上传后的可访问 URL，例如 http://target/tunnel.aspx",
			Notes:     []string{"不依赖 Session；高并发下 .NET 偶发 503，客户端会自动重试。"},
		},
		{
			Kind: "ashx", Backend: "regeorg", Deploy: DeployUploadFile,
			Target: "IIS + .NET Framework 2.0+（.ashx 处理器）", Requires: ".NET Framework 2.0+",
			TunnelURL: "上传后的可访问 URL，例如 http://target/tunnel.ashx",
			Notes:     []string{"与 tunnel.aspx 等价的处理器形式，用于 .aspx 被拦的场景。"},
		},
		{
			Kind: "go", Backend: "regeorg", Deploy: DeployRunProcess,
			Target: "能执行命令的目标（单文件自带 HTTP 服务）", Requires: "目标上有 Go，或把交叉编译好的二进制传上去",
			TunnelURL: "http://<target>:<端口>/任意路径（端口是启动时给的）",
			Notes: []string{
				"在目标上启动：go run tunnel.go 8000（或交叉编译后执行），它自己起一个 HTTP 服务。",
				"不依赖任何 Web 容器，属于进程式部署。",
			},
		},
		{
			Kind: "js", Backend: "regeorg", Deploy: DeployRunProcess,
			Target: "Node.js 服务（可独立运行，也可做成内存马）", Requires: "Node.js（无第三方依赖）",
			TunnelURL: "http://<target>:<端口>/<path>；内存马形式用文件里改好的 path",
			Notes: []string{
				"可以 node tunnel.js 直接跑，也可以改文件里的 path 后注入已有 Node 服务（内存马形式）。",
				"内存马形式按上游说明需要异步 CONNECT。",
			},
		},
		{
			Kind: "cs", Backend: "regeorg", Deploy: DeployCompileInject,
			Target: "IIS / .NET（需要编译成程序集后投放）", Requires: "能编译 C# 并投放程序集",
			TunnelURL: "取决于投放后的可访问路径",
			Notes:     []string{"这是 C# 源码，需要编译后再投放，不是可以直接上传的文件。"},
		},
		{
			Kind: "java", Backend: "regeorg", Deploy: DeployCompileInject,
			Target: "Java Servlet 容器（内存马类，可注入已有进程）", Requires: "能编译并注入到目标应用",
			TunnelURL: "取决于注入时注册的路径",
			Notes: []string{
				"en 用标准 base64 字母表、de 用平台固定参数里的置换字母表、HTTPCODE 用 200（具体值见 regeorg 包常量）。",
				"属于内存马，目标重启即失效。",
			},
			Caveats: []string{
				"这个类从 args[2..4] 取 en/de/HTTPCODE —— 字母表与状态码必须在**加载时传入**，模板里没有这些字面量，所以生成出来的 .java 不是能直接投放的载荷。",
			},
		},
	}
}

// Dir returns the library directory for a platform data dir.
func Dir(dataDir string) string { return filepath.Join(dataDir, LibraryDir) }

// Sync materialises the library and rewrites the manifest, returning it.
//
// Payload files are (re)written only when their bytes differ, so bumping the
// embedded payload propagates on the next start without a manual step, and a stale
// payload can never sit next to a newer client. The manifest is always rewritten
// because it is generated from code.
func Sync(dataDir string) (*Manifest, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("payloads: 数据目录为空")
	}
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("payloads: 创建文件库目录失败: %w", err)
	}
	m := &Manifest{
		Version:     ManifestVersion,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Dir:         dir,
		Usage:       usageText,
	}
	meta := LoadMeta(dataDir)
	// Neo-reGeorg 载荷按模板现场生成（模板里要写进平台的固定参数）。
	for _, e := range regeorgCatalog() {
		data, p, err := regeorg.Generate(e.Kind)
		if err != nil {
			return nil, fmt.Errorf("payloads: 生成 %s 载荷失败: %w", e.Kind, err)
		}
		sum := sha256hex(data)
		path := filepath.Join(dir, p.Name)
		if fm, ok := meta.Files[p.Name]; ok && fm.Override {
			// 用户用自己的版本替换了这个载荷：绝不覆盖，只登记进清单。
			e.Override = true
		} else if !fileHasSum(path, sum) {
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return nil, fmt.Errorf("payloads: 写入 %s 失败: %w", path, err)
			}
		}
		e.Name, e.SHA256, e.Size = p.Name, sum, len(data)
		if fm, ok := meta.Files[p.Name]; ok && fm.Description != "" {
			e.Description = fm.Description
		}
		e.Path = path
		if e.Backend == "" {
			e.Backend = "regeorg"
		}
		m.Files = append(m.Files, e)
	}
	// 用户自有文件也列进来。agent 读的是这一个 manifest：如果只列隧道载荷，用户上传的
	// 工具/字典/证书对 agent 就等于不存在。按文件名去重（生成的那些优先），大文件不再算
	// 哈希以免拖慢启动。
	known := make(map[string]bool, len(m.Files))
	for _, e := range m.Files {
		known[e.Name] = true
	}
	if entries, rerr := os.ReadDir(dir); rerr == nil {
		for _, de := range entries {
			name := de.Name()
			if de.IsDir() || name == ManifestName || known[name] || strings.HasPrefix(name, ".") {
				continue
			}
			info, ierr := de.Info()
			if ierr != nil {
				continue
			}
			fe := Entry{Kind: "file", Name: name, Size: int(info.Size()), Path: filepath.Join(dir, name)}
			if fm, ok := meta.Files[name]; ok && fm.Description != "" {
				fe.Description = fm.Description
			} else {
				fe.Notes = []string{"用户自有文件（不是隧道载荷）：在平台的「文件管理」里上传，可直接下载使用。"}
			}
			if info.Size() <= userFileHashLimit {
				if b, rerr := os.ReadFile(fe.Path); rerr == nil {
					fe.SHA256 = sha256hex(b)
				}
			}
			m.Files = append(m.Files, fe)
		}
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), append(raw, '\n'), 0o644); err != nil {
		return nil, fmt.Errorf("payloads: 写入 %s 失败: %w", ManifestName, err)
	}
	return m, nil
}

// userFileHashLimit 之上不再算哈希：启动时对几百 MB 的文件做全量哈希只会拖慢启动，
// 而 manifest 里的 sha256 只是给 agent 一个自查依据。
const userFileHashLimit = 8 << 20

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fileHasSum reports whether path already holds exactly these bytes.
func fileHasSum(path, sum string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return sha256hex(b) == sum
}
