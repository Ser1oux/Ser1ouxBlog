package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// 导入边界：单个条目 512MB、整包解压总量 2GB。
	// 备份来自管理员，但一个被替换过的 tar.gz 不应能把磁盘写满。
	maxImportEntryBytes int64 = 512 << 20
	maxImportTotalBytes int64 = 2 << 30
)

// exportData 生成一份临时备份包并返回其路径。
// 使用唯一临时文件名：两个管理员并发导出时不会互相截断。
func exportData() (string, error) {
	// 临时文件放进 data/：容器以只读根文件系统运行时，CWD 不可写。
	file, err := os.CreateTemp(dataDir, "backup-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("创建备份文件失败: %w", err)
	}
	name := file.Name()
	fail := func(err error) (string, error) {
		file.Close()
		os.Remove(name)
		return "", err
	}

	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)

	addTree := func(root string) error {
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(path)
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tarWriter, f); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		})
	}

	if err := addTree(dataDir); err != nil {
		return fail(fmt.Errorf("归档数据失败: %w", err))
	}
	if err := addTree("BG"); err != nil {
		return fail(fmt.Errorf("归档背景文件失败: %w", err))
	}

	// Close 的错误必须检查：否则磁盘写满时会“导出成功”但包是残缺的。
	if err := tarWriter.Close(); err != nil {
		return fail(fmt.Errorf("完成归档失败: %w", err))
	}
	if err := gzipWriter.Close(); err != nil {
		return fail(fmt.Errorf("压缩备份失败: %w", err))
	}
	if err := file.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("写入备份失败: %w", err)
	}
	return name, nil
}

// safeArchivePath 只允许解压到 data/ 与 BG/ 目录内部。
// 用路径分段比较，而不是字符串前缀，避免 databak/ 这类同前缀兄弟目录被放行。
// 归档里的名字始终是相对路径，因此这里用字面量而不是运行期 dataDir。
func safeArchivePath(name string) (string, bool) {
	// 先按本机规则 Clean，再统一成正斜杠做前缀判断（Windows 下 Clean 会产出反斜杠）。
	clean := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(name, "/")))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
		return "", false
	}
	if clean == "data" || strings.HasPrefix(clean, "data/") {
		return filepath.FromSlash(clean), true
	}
	if clean == "BG" || strings.HasPrefix(clean, "BG/") {
		return filepath.FromSlash(clean), true
	}
	return "", false
}

func importData(backupPath string) error {
	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("打开备份文件失败: %w", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	var total int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取归档失败: %w", err)
		}

		// 只接受普通文件与目录；符号链接、设备文件等一律跳过。
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			continue
		}

		target, ok := safeArchivePath(header.Name)
		if !ok {
			continue
		}

		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0700); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
			continue
		}

		if header.Size < 0 || header.Size > maxImportEntryBytes {
			return fmt.Errorf("归档条目过大: %s", header.Name)
		}
		total += header.Size
		if total > maxImportTotalBytes {
			return fmt.Errorf("归档解压总量超过上限")
		}

		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}

		outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("创建文件失败: %w", err)
		}
		// 按 header 声明的大小精确拷贝，不信任 tar 里可能超长的流。
		if _, err := io.CopyN(outFile, tarReader, header.Size); err != nil {
			outFile.Close()
			return fmt.Errorf("写入文件失败: %w", err)
		}
		if err := outFile.Close(); err != nil {
			return fmt.Errorf("写入文件失败: %w", err)
		}
	}

	return nil
}
