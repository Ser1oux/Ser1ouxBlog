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

func exportData() error {
	backupFile := "backup.tar.gz"

	// 创建备份文件
	file, err := os.Create(backupFile)
	if err != nil {
		return fmt.Errorf("创建备份文件失败: %w", err)
	}
	defer file.Close()

	// 创建 gzip writer
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	// 创建 tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// 添加 data 目录到归档（包含所有文章、上传文件、metadata.json等）
	err = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 创建 tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		// 使用相对路径
		header.Name = path

		// 写入 header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// 如果是文件，写入内容
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("归档数据失败: %w", err)
	}

	// 添加 BG 目录（如果有自定义背景）
	bgDir := "BG"
	if _, err := os.Stat(bgDir); err == nil {
		err = filepath.Walk(bgDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// 创建 tar header
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}

			// 使用相对路径
			header.Name = path

			// 写入 header
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}

			// 如果是文件，写入内容
			if !info.IsDir() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()

				if _, err := io.Copy(tarWriter, file); err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("归档背景文件失败: %w", err)
		}
	}

	return nil
}

func importData(backupPath string) error {
	// 打开备份文件
	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("打开备份文件失败: %w", err)
	}
	defer file.Close()

	// 创建 gzip reader
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}
	defer gzipReader.Close()

	// 创建 tar reader
	tarReader := tar.NewReader(gzipReader)

	// 提取文件
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取归档失败: %w", err)
		}

		// 确保路径安全 - 允许 data 和 BG 目录
		target := filepath.Clean(header.Name)
		if !strings.HasPrefix(target, dataDir) && !strings.HasPrefix(target, "BG") {
			continue
		}

		// 创建目录
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
			continue
		}

		// 创建文件
		dir := filepath.Dir(target)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}

		outFile, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("创建文件失败: %w", err)
		}

		if _, err := io.Copy(outFile, tarReader); err != nil {
			outFile.Close()
			return fmt.Errorf("写入文件失败: %w", err)
		}
		outFile.Close()
	}

	return nil
}
