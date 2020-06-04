package sm

var (
	defaultIV = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
)

func CBCEncrypt(key, iv, plainText []byte) ([]byte, error) {
	if len(iv) != 16 {
		iv = defaultIV
	}
	return factory.Sm4CBCEncrypt(key, iv, plainText)
}

func CBCDecrypt(key, iv, cipherText []byte) ([]byte, error) {
	if len(iv) != 16 {
		iv = defaultIV
	}
	return factory.Sm4CBCDecrypt(key, iv, cipherText)
}
