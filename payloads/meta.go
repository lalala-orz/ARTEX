package payloads

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// 文件库的**随附元数据**：用户给文件写的说明，以及"这个载荷被用户替换过"的标记。
//
// 为什么不写进 manifest.json：manifest 是每次 Sync 从代码重新生成的（见 payloads.go
// 开头的注释），用户的东西写进去会被覆盖掉。所以用户的元数据单独放一个文件，
// Sync 时把它合并进 manifest。
//
// 说明为什么必要：文件库是给 agent 用的，但 agent 看到文件名并不知道"这是什么、
// 怎么用"（suo5.php？tunnel.ashx？next_payload.http？）。所以每份文件都可以带一句
// 说明，随 manifest 一起交给 agent。

const (
	// MetaName 是随附元数据文件名，在**数据目录**下（不放进 files/，免得它自己
	// 出现在文件列表里）。
	MetaName = "filemeta.json"
	// MetaVersion 便于以后改结构。
	MetaVersion = 1
)

// FileMeta 是一个文件的用户元数据。
type FileMeta struct {
	// Description 是"这是什么、怎么用"。给 agent 读，也给人在列表里看。
	Description string `json:"description,omitempty"`
	// Override 表示这个文件名被用户用自己的版本替换过：Sync 不得再用平台生成的
	// 字节覆盖它 —— 否则"我换了个能用的载荷"下次启动就被还原了，这正是要避免的。
	Override  bool   `json:"override,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Meta 是整份随附元数据。
type Meta struct {
	Version int                 `json:"version"`
	Files   map[string]FileMeta `json:"files"`
}

func metaPath(dataDir string) string { return filepath.Join(dataDir, MetaName) }

// LoadMeta 读随附元数据；文件不存在就返回空壳（不是错误）。
func LoadMeta(dataDir string) *Meta {
	m := &Meta{Version: MetaVersion, Files: map[string]FileMeta{}}
	if dataDir == "" {
		return m
	}
	raw, err := os.ReadFile(metaPath(dataDir))
	if err != nil {
		return m
	}
	var got Meta
	if json.Unmarshal(raw, &got) != nil {
		return m
	}
	if got.Files == nil {
		got.Files = map[string]FileMeta{}
	}
	if got.Version == 0 {
		got.Version = MetaVersion
	}
	return &got
}

// SaveMeta 原子写：先写临时文件再改名，避免留下半个 JSON。
func SaveMeta(dataDir string, m *Meta) error {
	if dataDir == "" {
		return fmt.Errorf("payloads: 数据目录为空")
	}
	if m == nil {
		m = &Meta{Version: MetaVersion, Files: map[string]FileMeta{}}
	}
	if m.Files == nil {
		m.Files = map[string]FileMeta{}
	}
	m.Version = MetaVersion
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := metaPath(dataDir) + ".part"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("payloads: 写入 %s 失败: %w", MetaName, err)
	}
	if err := os.Rename(tmp, metaPath(dataDir)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("payloads: 保存 %s 失败: %w", MetaName, err)
	}
	return nil
}

// SetFileMeta 更新一个文件的元数据（description/override 由调用方给全）。
func SetFileMeta(dataDir, name string, fm FileMeta) error {
	if name == "" {
		return fmt.Errorf("payloads: 文件名为空")
	}
	m := LoadMeta(dataDir)
	fm.UpdatedAt = time.Now().Format(time.RFC3339)
	m.Files[name] = fm
	return SaveMeta(dataDir, m)
}

// DropFileMeta 删掉一个文件的元数据（删除文件或恢复平台版本时用）。
func DropFileMeta(dataDir, name string) error {
	m := LoadMeta(dataDir)
	if _, ok := m.Files[name]; !ok {
		return nil
	}
	delete(m.Files, name)
	return SaveMeta(dataDir, m)
}
