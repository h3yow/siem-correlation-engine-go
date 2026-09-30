package snapshot

import (
	"os"
	"path/filepath"
)

// SaveTo 将快照原子落盘：先写同目录临时文件并 fsync，再 rename 到目标路径。
//
// 这样即便导出过程中进程崩溃或磁盘写满，目标路径要么是旧的完整快照、
// 要么是新的完整快照，绝不会留下半写文件被后续 LoadFrom 静默读入。
func (s *Snapshot) SaveTo(path string) (err error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return snapErr(CodeCorrupt, s.env.Version, "create snapshot dir %q: %v", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".snapshot-*"+filepath.Ext(path))
	if err != nil {
		return snapErr(CodeCorrupt, s.env.Version, "create temp snapshot: %v", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	data, err := s.Encode()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return snapErr(CodeCorrupt, s.env.Version, "write temp snapshot: %v", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return snapErr(CodeCorrupt, s.env.Version, "fsync temp snapshot: %v", err)
	}
	if err = tmp.Close(); err != nil {
		return snapErr(CodeCorrupt, s.env.Version, "close temp snapshot: %v", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return snapErr(CodeCorrupt, s.env.Version, "rename snapshot to %q: %v", path, err)
	}
	return nil
}

// LoadFrom 从本地文件读取并解码快照（含格式与版本判定）。
// 返回的错误用 CodeOf 可区分 not_a_snapshot / corrupt /
// unsupported_version / incompatible_version 等原因。
func LoadFrom(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, snapErr(CodeCorrupt, 0, "read snapshot file %q: %v", path, err)
	}
	return Decode(data)
}
