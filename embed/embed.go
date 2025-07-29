package embed

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"strings"
)

//go:embed data
var FS embed.FS

func Asset(name string) ([]byte, error) {
	buf, err := FS.ReadFile(name)
	if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".gzip") {
		buf, err = GzipDeCompress(buf)
	}
	return buf, err
}

func AssetDir(name string) ([]string, error) {
	dir, err := FS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	entries := make([]string, 0, len(dir))
	for _, v := range dir {
		entries = append(entries, v.Name())
	}
	return entries, nil
}

func GzipDeCompress(ret []byte) ([]byte, error) {
	var reader *gzip.Reader
	var err error
	reader, err = gzip.NewReader(bytes.NewBuffer(ret))
	if err != nil {
		return nil, err
	}
	var bufBytes bytes.Buffer
	_, err = io.Copy(&bufBytes, reader)
	reader.Close()
	if err != nil {
		return bufBytes.Bytes(), err
	}
	return bufBytes.Bytes(), nil
}
