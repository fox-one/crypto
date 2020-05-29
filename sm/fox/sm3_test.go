package fsm

import (
	"crypto/rand"
	mathRand "math/rand"
	"testing"
)

func BenchmarkSM3Sum(b *testing.B) {
	b.ResetTimer()

	factory := smFactory{}
	for i := 0; i < b.N; i++ {
		var raw = make([]byte, 1+mathRand.Int()%1688)
		rand.Reader.Read(raw)
		factory.Sm3Sum(raw)
	}
}
