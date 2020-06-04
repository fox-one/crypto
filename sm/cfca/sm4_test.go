package cfca

import (
	"bytes"
	"crypto/rand"
	mathRand "math/rand"
	"testing"
)

func BenchmarkSM4(b *testing.B) {
	b.ResetTimer()

	factory := smFactory{}
	for i := 0; i < b.N; i++ {
		var (
			raw = make([]byte, 1+mathRand.Int()%1688)
			key = make([]byte, 16)
			iv  = make([]byte, 16)
		)
		rand.Reader.Read(raw)
		rand.Reader.Read(key)
		rand.Reader.Read(iv)

		encryptedText, err := factory.Sm4CBCEncrypt(key, iv, raw)
		if err != nil {
			b.Fatal(err)
		}

		plainText, err := factory.Sm4CBCDecrypt(key, iv, encryptedText)
		if err != nil {
			b.Fatal(err)
		}

		if bytes.Compare(raw, plainText) != 0 {
			b.Fatal("encrypt & decrypt failed")
		}
	}
}
