package fsm

import (
	"crypto/cipher"

	"github.com/fox-one/crypto/common"
	"github.com/tjfoc/gmsm/sm4"
)

func (f smFactory) Sm4CBCEncrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData := common.PKCS7Padding(plainText)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func (f smFactory) Sm4CBCDecrypt(key, iv, encryptedText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encryptedText))
	blockMode.CryptBlocks(origData, encryptedText)
	origData = common.UnPKCS7Padding(origData)
	return origData, nil
}
