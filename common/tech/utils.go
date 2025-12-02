package tech

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/httpx/common/httpx"
)

// responseToDSLMap 将HTTP响应转换为DSL上下文
func responseToDSLMap(resp *httpx.Response, host, matched, rawReq, rawResp, body, headers, favicon string, duration time.Duration, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, 12+len(extra)+len(resp.Headers))

	// 添加额外数据
	for k, v := range extra {
		data[k] = v
	}

	// 添加响应头（标准化键名）
	for k, v := range resp.Headers {
		k = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		data[k] = strings.Join(v, " ")
	}

	// 添加favicon hash
	if favicon != "" {
		data["favicon"] = fmt.Sprintf("%x", md5.Sum([]byte(favicon)))
	}

	// 添加基础字段
	data["host"] = host
	data["matched"] = matched
	data["request"] = rawReq
	data["response"] = rawResp
	data["status_code"] = resp.StatusCode
	data["body"] = body
	data["all_headers"] = headers
	data["header"] = headers
	data["duration"] = duration.Seconds()
	data["content_length"] = calculateContentLength(int64(resp.ContentLength), int64(len(body)))

	return data
}

// calculateContentLength 计算内容长度
func calculateContentLength(contentLength, bodyLength int64) int64 {
	if contentLength > -1 {
		return contentLength
	}
	return bodyLength
}

// exists 检查路径是否存在
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

// isDir 检查路径是否为目录
func isDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

// readDir 递归读取目录下所有文件
func readDir(path string) []string {
	var files []string
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	return files
}
