package sm

var (
	defaultIV = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
)

func CBCEncrypt(key, iv [16]byte, plainText []byte) ([]byte, error) {
	if len(iv) == 0 {
		iv = defaultIV
	}
	return factory.Sm4CBCEncrypt(key, iv, plainText)
}

func CBCDecrypt(key, iv [16]byte, cipherText []byte) ([]byte, error) {
	if len(iv) == 0 {
		iv = defaultIV
	}
	return factory.Sm4CBCDecrypt(key, iv, cipherText)
}
