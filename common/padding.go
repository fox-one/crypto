package common

import "bytes"

const (
	defaultBlockSize = 16
)

/**
 *  PKCS7补码
 *  这里可以参考下http://blog.studygolang.com/167.html
 */
func PKCS7Padding(data []byte, blockSizes ...int) []byte {
	var blockSize = defaultBlockSize
	if len(blockSizes) > 0 && blockSizes[0] > 0 {
		blockSize = blockSizes[0]
	}

	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

/**
 *  去除PKCS7的补码
 */
func UnPKCS7Padding(data []byte) []byte {
	length := len(data)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(data[length-1])
	if length <= unpadding {
		return nil
	}
	return data[:(length - unpadding)]
}

func Split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)

	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}

	if len(buf) > 0 {
		chunks = append(chunks, buf)
	}
	return chunks
}
