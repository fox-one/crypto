package fsm

import (
	"crypto/rand"
	"encoding/hex"
	mathRand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func BenchmarkSm3Sum(b *testing.B) {
	b.ResetTimer()

	factory := smFactory{}
	for i := 0; i < b.N; i++ {
		var raw = make([]byte, 1+mathRand.Int()%1688)
		rand.Reader.Read(raw)
		factory.Sm3Sum(raw)
	}
}

func TestSm3Sum(t *testing.T) {
	assert := assert.New(t)

	raw := []byte("just a test!!!")
	sum := smFactory{}.Sm3Sum(raw)
	assert.Equal("87977a07b53a393107be0b16e4c6295f6f7e88a2d71453a432145442bd9d0af4", hex.EncodeToString(sum[:]))
}
