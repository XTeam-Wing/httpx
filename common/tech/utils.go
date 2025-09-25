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

func responseToDSLMap(resp *httpx.Response, host, matched, rawReq, rawResp, body, headers, favicon string, duration time.Duration, extra map[string]interface{}) map[string]interface{} {
	data := make(map[string]interface{}, 12+len(extra)+len(resp.Headers))
	for k, v := range extra {
		data[k] = v
	}
	for k, v := range resp.Headers {
		k = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		setHashOrDefault(data, k, strings.Join(v, " "))
	}
	if favicon != "" {
		data["favicon"] = fmt.Sprintf("%x", md5.Sum([]byte(favicon)))
	}
	data["host"] = host
	data["matched"] = matched
	setHashOrDefault(data, "request", rawReq)
	setHashOrDefault(data, "response", rawResp)
	data["status_code"] = resp.StatusCode
	setHashOrDefault(data, "body", body)
	setHashOrDefault(data, "all_headers", headers)
	setHashOrDefault(data, "header", headers)
	data["duration"] = duration.Seconds()

	data["content_length"] = calculateContentLength(int64(resp.ContentLength), int64(len(body)))

	return data
}

func calculateContentLength(contentLength, bodyLength int64) int64 {
	if contentLength > -1 {
		return contentLength
	}
	return bodyLength
}

func setHashOrDefault(data map[string]interface{}, k string, v string) {
	data[k] = v
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return os.IsExist(err)
	}
	return true
}

func isDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

func isFile(path string) bool {
	return !isDir(path)
}

func readDir(path string) []string {
	var files []string
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if isFile(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return files
}
