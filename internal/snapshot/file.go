package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
)

// SaveToFile 把状态编码后原子写入 path：先写同目录临时文件再 rename，
// 周期性/反复导出也不会让读取方看到写了一半的快照文件。
//
// 注意：本函数只做磁盘 I/O；调用方应在锁内完成内存状态拷贝、锁外调用本
// 函数，避免慢磁盘把正在进行的摄取一并卡住。临时文件在写完后删除，
// 反复导出也不会在磁盘上累积垃圾文件或让占用一路上涨。
func SaveToFile(path string, st State, engineID string) error {
	data, err := Encode(st, engineID)
	if err != nil {
		return err
	}
	if err := atomicWrite(path, data, 0o600); err != nil {
		return fmt.Errorf("snapshot: write %s: %w", path, err)
	}
	return nil
}

// LoadFromFile 读取并校验一份快照文件，返回其中的状态。
// 文件缺失/无法读取包装 os 错误；内容问题返回可区分的快照错误。
func LoadFromFile(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("snapshot: read %s: %w", path, err)
	}
	st, err := Decode(data)
	if err != nil {
		return State{}, err
	}
	return st, nil
}

// atomicWrite 在目标同目录创建临时文件、fsync 后原子 rename。
// 同目录保证 rename 是原子的（同一文件系统）。
func atomicWrite(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, ".snapshot-*"+filepath.Ext(path))
	if err != nil {
		return err
	}
	tmp := f.Name()
	// 任何失败路径都清理临时文件，避免周期导出时垃圾堆积。
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp, perm); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}
