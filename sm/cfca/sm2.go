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
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/fox-one/crypto/sm"
)

func (f smFactory) Sm2Sign(random io.Reader, p *sm.PrivateKey, message []byte) ([64]byte, error) {
	var (
		pub               = p.PublicKey()
		byteSM2PublicKey  = append(pub.X.Bytes(), pub.Y.Bytes()...)
		nSM2PublicKey     = C.int(len(byteSM2PublicKey))
		byteSM2PrivateKey = p.D.Bytes()
		nSM2PrivateKey    = C.int(len(byteSM2PrivateKey))
		pbySignature      = (*C.uchar)(nil)
		nSignature        C.int
		sig               [64]byte
	)

	result := int(C.SM2SignData((*C.uchar)(unsafe.Pointer(&message[0])), C.int(len(message)),
		(*C.uchar)(unsafe.Pointer(&byteSM2PublicKey[0])), nSM2PublicKey,
		(*C.uchar)(unsafe.Pointer(&byteSM2PrivateKey[0])), nSM2PrivateKey,
		&pbySignature, &nSignature))
	defer C.FreeMemory(unsafe.Pointer(pbySignature))
	if result != 0 {
		return sig, fmt.Errorf("SM2SignData failed: Error code[0x%8x].", result)
	}

	bts := C.GoBytes(unsafe.Pointer(pbySignature), nSignature)
	copy(sig[:], bts)
	return sig, nil
}

func (f smFactory) Sm2Verify(pub *sm.PublicKey, message []byte, signature [64]byte) bool {
	byteSM2PublicKey := append(pub.X.Bytes(), pub.Y.Bytes()...)

	result := int(C.SM2VerifySignature((*C.uchar)(unsafe.Pointer(&signature[0])), C.int(len(signature)),
		(*C.uchar)(unsafe.Pointer(&message[0])), C.int(len(message)),
		(*C.uchar)(unsafe.Pointer(&byteSM2PublicKey[0])), C.int(len(byteSM2PublicKey))))

	return result == 0
}

func (f smFactory) Sm2Encrypt(random io.Reader, pub *sm.PublicKey, plainText []byte) ([]byte, error) {
	var (
		pbyEncryptedData = (*C.uchar)(nil)
		nEncryptedData   = C.int(0)
		byteSM2PublicKey = append(pub.X.Bytes(), pub.Y.Bytes()...)
	)
	result := int(C.SM2EncryptData((*C.uchar)(unsafe.Pointer(&plainText[0])), C.int(len(plainText)),
		(*C.uchar)(unsafe.Pointer(&byteSM2PublicKey[0])), C.int(len(byteSM2PublicKey)),
		&pbyEncryptedData, &nEncryptedData))
	defer C.FreeMemory(unsafe.Pointer(pbyEncryptedData))
	if result != 0 {
		return nil, fmt.Errorf("SM2EncryptData failed:Error code[0x%8x].", result)
	}

	data := make([]byte, 1+nEncryptedData)
	data[0] = 0x4
	copy(data[1:], C.GoBytes(unsafe.Pointer(pbyEncryptedData), nEncryptedData))
	return data, nil
}

func (f smFactory) Sm2Decrypt(p *sm.PrivateKey, encryptedText []byte) ([]byte, error) {
	if encryptedText[0] != 4 {
		return nil, errors.New("Sm2Decrypt failed: public key should not be compressed")
	}

	if len(encryptedText) < 98 {
		return nil, errors.New("Sm2Decrypt failed: invalid encrypted length")
	}

	var (
		pbyDecryptedData  = (*C.uchar)(nil)
		nDecryptedData    = C.int(0)
		byteSM2PrivateKey = p.D.Bytes()
	)

	result := int(C.SM2DecryptData((*C.uchar)(unsafe.Pointer(&encryptedText[1])), C.int(len(encryptedText)-1),
		(*C.uchar)(unsafe.Pointer(&byteSM2PrivateKey[0])), C.int(len(byteSM2PrivateKey)),
		&pbyDecryptedData, &nDecryptedData))
	defer C.FreeMemory(unsafe.Pointer(pbyDecryptedData))
	if result != 0 {
		return nil, fmt.Errorf("SM2DecryptData failed:Error code[0x%8x].", result)
	}

	data := make([]byte, nDecryptedData)
	copy(data, C.GoBytes(unsafe.Pointer(pbyDecryptedData), nDecryptedData))
	return data, nil
}
