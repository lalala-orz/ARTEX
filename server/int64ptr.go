package server

import (
	"strconv"
	"strings"
)

// int64Ptr 解析可选整数：空串 / 非数字 ⇒ nil（未设置）。
// 之所以用指针：resp_len 的 0 是合法边界值，不能拿零值当"没填"。
func int64Ptr(raw string) *int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}
