package common

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
)

// GZipDecompress gzip decompress
func GZipDecompress(binary []byte) ([]byte, error) {
	byteReader := bytes.NewReader(binary)
	gReader, err := gzip.NewReader(byteReader)
	defer gReader.Close()

	if err != nil {
		return []byte{}, err
	}

	return ioutil.ReadAll(gReader)
}

// GZipCompress gzip compress
func GZipCompress(p []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(p); err != nil {
		return nil, err
	}
	gz.Flush()
	gz.Close()

	return buf.Bytes(), nil
}
