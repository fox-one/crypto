package sm

import "io"

type KeyFactory interface {
	// sm2
	Sm2Sign(random io.Reader, p *PrivateKey, message []byte) (signature [64]byte, err error)
	Sm2Verify(pub *PublicKey, message []byte, signature [64]byte) bool
	Sm2Encrypt(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error)
	Sm2Decrypt(p *PrivateKey, encryptedText []byte) (plainText []byte, err error)

	// sm3
	Sm3Sum(message []byte) (digest [32]byte)

	// sm4
	Sm4CBCEncrypt(key, iv [16]byte, plainText []byte) ([]byte, error)
	Sm4CBCDecrypt(key, iv [16]byte, cipherText []byte) ([]byte, error)
}

var factory KeyFactory

func SetupKeyFactory(f KeyFactory) {
	factory = f
}
