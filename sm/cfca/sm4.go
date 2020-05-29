package cfca

/*
#cgo CFLAGS: -I./
#cgo LDFLAGS: -lstdc++ -ldl -L./ -lSADK_CNERT
#include <stdlib.h>
#include <dlfcn.h>
#include "SADK.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func (f smFactory) Sm4CBCEncrypt(key, iv [16]byte, plainText []byte) ([]byte, error) {
	var (
		sm4Key  = append(iv[:], key[:]...)
		data    = (*C.uchar)(nil)
		dataLen = C.int(0)
	)

	result := int(C.SM4EncryptData((*C.uchar)(unsafe.Pointer(&plainText[0])), C.int(len(plainText)),
		(*C.uchar)(unsafe.Pointer(&sm4Key[0])), C.int(len(sm4Key)),
		&data, &dataLen))

	defer C.FreeMemory(unsafe.Pointer(data))
	if result != 0 {
		return nil, fmt.Errorf("SM4EncryptData failed: Error code[0x%8x].", result)
	}

	dst := make([]byte, dataLen)
	copy(dst, C.GoBytes(unsafe.Pointer(data), dataLen))
	return dst, nil
}

func (f smFactory) Sm4CBCDecrypt(key, iv [16]byte, encryptedText []byte) ([]byte, error) {
	var (
		sm4Key  = append(iv[:], key[:]...)
		data    = (*C.uchar)(nil)
		dataLen = C.int(0)
	)

	result := int(C.SM4DecryptData((*C.uchar)(unsafe.Pointer(&encryptedText[0])), C.int(len(encryptedText)),
		(*C.uchar)(unsafe.Pointer(&sm4Key[0])), C.int(len(sm4Key)),
		&data, &dataLen))
	defer C.FreeMemory(unsafe.Pointer(data))
	if result != 0 {
		return nil, fmt.Errorf("SM4DecryptData failed: Error code[0x%8x].", result)
	}

	dst := make([]byte, dataLen)
	copy(dst, C.GoBytes(unsafe.Pointer(data), dataLen))
	return dst, nil
}
