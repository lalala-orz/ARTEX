// Package regeorg implements the Neo-reGeorg tunnel protocol (upstream 5.3.0).
//
// 为什么用它而不是继续用 suo5：PHP 目标上 suo5 的载荷只能半双工、每个连接还占住一个
// FPM worker，实测"探活能过、之后每个连接都失败"；Neo-reGeorg 的 PHP 载荷是专门为这个
// 场景写的（单 Session 多 TCP 连接），而且只有 5.7KB（suo5 是 34.7KB）。
//
// 与上游的差别（有意为之，用户决定）：
//   - 参数**固定**，不跟随 neoreg.py 的 key 派生。上游用 key 播种 CPython 的 MT19937 再洗牌
//     字母表，要在 Go 里逐位复刻它既脆弱又没必要；这里改成平台统一的一套固定参数。
//     代价：不能与官方 `neoreg.py generate` 产出的载荷互通，载荷一律由本平台生成。
//   - 因此载荷里不再有 key 的概念：谁拿到载荷谁能用，安全边界靠"载荷放在哪 + 用完删掉"。
package regeorg

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Version 是本包模板所对应的上游版本，改动模板时一并更新。
const Version = "5.3.0"

// 固定协议参数。生成器与客户端必须用同一份——这是唯一真相来源。
const (
	// Base64Chars 是标准字母表，对应载荷里的 $en。
	Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	// TunnelChars 是替换进载荷 $de 的**置换**字母表，也是客户端编码请求时用的映射。
	// 必须是 Base64Chars 的一个真置换（TestTunnelCharsIsPermutation 会盯住这点）。
	TunnelChars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"

	// BLVLOffset 加在每个 BLV 值的长度上（载荷用 BLV_L_OFFSET 还原）。
	BLVLOffset = 0x3f2a91b7

	// Hello 是载荷对"看不懂的请求"的应答，客户端在建连前用它确认载荷在位。
	// 载荷那侧是 base64_decode(strtr(Hello, $de, $en))，所以这里算的也要走同一条路。
	Hello = "<!-- 5f3a9c1e -->"

	// HTTPCode 是载荷设置的状态码（伪装用）。
	HTTPCode = 200
	// ReadBuf 是载荷每轮从目标 socket 读的字节数（fgets 长度）。
	ReadBuf = 513
	// MaxReadSize 是载荷单轮最多缓存多少字节。
	MaxReadSize = 512 * 1024
	// UseRequestTemplate=0：请求体不做前后裁剪（没有请求模板）。
	UseRequestTemplate = 0
	StartIndex         = 0
	EndIndex           = 0
)

// BLV 字段编号，与载荷里的 $DATA/$CMD/... 一一对应。
const (
	FieldData          byte = 1
	FieldCmd           byte = 2
	FieldMark          byte = 3
	FieldStatus        byte = 4
	FieldError         byte = 5
	FieldIP            byte = 6
	FieldPort          byte = 7
	FieldRedirectURL   byte = 8
	FieldForceRedirect byte = 9
)

// 命令值。
const (
	CmdConnect    = "CONNECT"
	CmdDisconnect = "DISCONNECT"
	CmdRead       = "READ"
	CmdForward    = "FORWARD"
)

// 状态值。
const (
	StatusOK   = "OK"
	StatusFail = "FAIL"
)

// HelloBytes 是载荷应答 Hello 时真正吐出的字节（客户端拿它做在位确认）。
//
// 必须走与 DecodeBody 相同的**宽容**路径：Hello 里含有 base64 字母表之外的字符（`<`、`!`、
// 空格、`-`），PHP 与 Python 的解码会忽略它们，而 Go 的严格解码会直接报错——若在这里用严格
// 解码并吞掉错误，就会得到一个空切片，于是"载荷应答对不对"的检查**永远通过**（安全校验被
// 静默废掉）。所以这里过滤+补 padding，并在解不出内容时返回 nil 由调用方 fail-closed。
func HelloBytes() []byte {
	mapped := keepBase64(mapChars(Hello, TunnelChars, Base64Chars))
	b, err := base64.StdEncoding.DecodeString(padBase64(mapped))
	if err != nil {
		return nil
	}
	return b
}

// EncodeBody 把一组 BLV 字段编码成请求体：BLV → 标准 base64 → 换成 TunnelChars 字母表。
//
// 与载荷的 blv_encode 一样插入两个噪声字段（0/39）：它们不参与协议，只是让每次请求体
// 都不完全相同。
func EncodeBody(fields map[byte][]byte) string {
	f := make(map[byte][]byte, len(fields)+2)
	for k, v := range fields {
		f[k] = v
	}
	f[0] = randNoise()
	f[39] = randNoise()
	raw := blvEncode(f)
	return mapChars(base64.StdEncoding.EncodeToString(raw), Base64Chars, TunnelChars)
}

// DecodeBody 把载荷的应答解回 BLV 字段。
//
// 先做一次"过滤字母表外字符 + 补 padding + base64 解码 + BLV 拆解"（PHP 的 base64_decode 与
// Python 的 b64decode 都会忽略表外字符，Go 的会报错，所以要主动洗一遍）。
//
// 但**只洗一次是不够的**：真实环境里应答可能带**前缀噪声**，典型是 PHP 5.6 在自动填充
// $HTTP_RAW_POST_DATA 时先吐一段 Deprecated 的 HTML 警告——那些文本的字母与 "/" 都在 base64
// 字母表里，过滤不掉，会被当成载荷数据一起解码（实测表现成"字段 62 长度 9 亿"这种离谱报错）。
//
// 因此再做"逐字节偏移重试"：载荷真实的应答一定是一个能恰好解到末尾、**且带 STATUS** 的
// BLV 帧。从第 1、2、3… 个字节开始各试一次，第一个满足的就是它。开销 O(n²)，但只在正常
// 解码失败或解出来没有 STATUS 时才走，且偏移上限 4KB（噪声是短的，而 O(n²) 必须有边）。
func DecodeBody(body string) (map[byte][]byte, error) {
	info, firstErr := decodeAt(body)
	if firstErr == nil && len(info[FieldStatus]) > 0 {
		return info, nil
	}
	limit := len(body) - 1
	if limit > maxDecodeScanOffset {
		limit = maxDecodeScanOffset
	}
	for off := 1; off <= limit; off++ {
		if got, err := decodeAt(body[off:]); err == nil && len(got[FieldStatus]) > 0 {
			return got, nil
		}
	}
	if firstErr == nil {
		return info, nil // 没有带 STATUS 的版本，但至少解出了内容
	}
	return nil, fmt.Errorf("%w（为跳过前缀噪声已试过 %d 个偏移量）", firstErr, limit)
}

// maxDecodeScanOffset 是偏移重试的上限：前缀噪声（PHP 警告一类）是短的，而扫描是 O(n²)。
const maxDecodeScanOffset = 4096

// decodeAt 是从某个偏移量开始的一次解码尝试。
func decodeAt(body string) (map[byte][]byte, error) {
	cleaned := keepBase64(body)
	if cleaned == "" {
		return nil, errors.New("regeorg: 应答体里没有可解码内容")
	}
	raw, err := base64.StdEncoding.DecodeString(padBase64(mapChars(cleaned, TunnelChars, Base64Chars)))
	if err != nil {
		return nil, fmt.Errorf("regeorg: base64 解码失败: %w", err)
	}
	return blvDecode(raw)
}

// blvEncode 按 [1字节字段][4字节大端长度][值] 拼接，长度含 BLVLOffset。
func blvEncode(fields map[byte][]byte) []byte {
	out := make([]byte, 0, 64)
	for k, v := range fields {
		l := uint32(len(v) + BLVLOffset)
		out = append(out, k, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
		out = append(out, v...)
	}
	return out
}

// blvDecode 是 blvEncode 的逆过程。长度字段异常时直接报错，不猜。
func blvDecode(data []byte) (map[byte][]byte, error) {
	out := map[byte][]byte{}
	for i := 0; i < len(data); {
		if i+5 > len(data) {
			return nil, fmt.Errorf("regeorg: BLV 头不完整（offset %d）", i)
		}
		k := data[i]
		l := int(uint32(data[i+1])<<24 | uint32(data[i+2])<<16 | uint32(data[i+3])<<8 | uint32(data[i+4]))
		i += 5
		l -= BLVLOffset
		if l < 0 || i+l > len(data) {
			return nil, fmt.Errorf("regeorg: BLV 长度越界（字段 %d 长度 %d，剩余 %d）", k, l, len(data)-i)
		}
		out[k] = append([]byte(nil), data[i:i+l]...)
		i += l
	}
	return out, nil
}

// mapChars 按 from→to 做逐字符置换，语义等同 PHP 的 strtr / Python 的 translate：
// 不在 from 里的字符原样保留。
func mapChars(s, from, to string) string {
	if len(from) != len(to) {
		return s
	}
	table := make(map[rune]rune, len(from))
	for i, c := range from {
		table[c] = rune(to[i])
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if r, ok := table[c]; ok {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// keepBase64 去掉所有非字母表字符（换行、裁剪残留、伪装页面碎片）。
func keepBase64(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if strings.ContainsRune(Base64Chars, c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// padBase64 补齐到 4 的倍数：上游可能把 '=' 去掉（rand_value 就会 rstrip('=')）。
func padBase64(s string) string {
	if n := len(s) % 4; n != 0 {
		s += strings.Repeat("=", 4-n)
	}
	return s
}

// randNoise 造一个 5..20 字节的随机值，对应载荷里的 randstr()。
func randNoise() []byte {
	n := 5 + int(noiseByte()%16)
	b := make([]byte, n)
	for i := range b {
		b[i] = noiseByte()
	}
	return b
}
