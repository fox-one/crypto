package cfca

import (
	"crypto/rand"
	mathRand "math/rand"
	"testing"

	"github.com/fox-one/crypto/sm"
)

func BenchmarkSM2Sign(b *testing.B) {
	b.ResetTimer()

	f := smFactory{}
	var raw = make([]byte, mathRand.Int()%1688)
	rand.Reader.Read(raw)

	d, err := rand.Int(rand.Reader, N)
	if err != nil {
		b.Fatal(err)
	}
	p := sm.PrivateKey{D: d.Mod(d, N)}
	for i := 0; i < b.N; i++ {
		sig, err := f.Sm2Sign(rand.Reader, &p, raw)
		if err != nil {
			b.Fatal(err)
		}

		if !f.Sm2Verify(p.PublicKey(), raw, sig) {
			b.Fatalf("Sm2Verify failed")
		}
	}
}
