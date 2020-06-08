package fsm

import (
	"crypto/rand"
	"math/big"
	mathRand "math/rand"
	"testing"

	"github.com/fox-one/crypto/sm"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
)

func init() {
	Load()
}

func BenchmarkSM2Sign(b *testing.B) {
	b.ResetTimer()

	f := smFactory{}
	var raw = make([]byte, mathRand.Int()%1688)
	rand.Reader.Read(raw)

	d, err := rand.Int(rand.Reader, N)
	if err != nil {
		b.Fatal(err)
	}
	p := sm.PrivateKey{D: d}
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

func TestSm2(t *testing.T) {
	assert := assert.New(t)

	var (
		f          = smFactory{}
		defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
		raw        = make([]byte, mathRand.Int()%1688)

		priv1 = sm.NewPrivateKey(rand.Reader)
		pub1  = priv1.PublicKey()
		pub2  = sm2.PublicKey{
			Curve: sm2P256,
			X:     pub1.X,
			Y:     pub1.Y,
		}
		priv2 = sm2.PrivateKey{
			PublicKey: pub2,
			D:         priv1.D,
		}
	)

	rand.Reader.Read(raw)

	{
		sig, err := f.Sm2Sign(rand.Reader, priv1, raw)
		assert.Nil(err)

		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])

		assert.True(sm2.Sm2Verify(&pub2, raw, defaultUID, r, s))
	}

	{
		r, s, err := sm2.Sm2Sign(&priv2, raw, defaultUID)
		assert.Nil(err)

		var sig [64]byte
		copy(sig[32-len(r.Bytes()):], r.Bytes())
		copy(sig[64-len(s.Bytes()):], s.Bytes())

		assert.True(f.Sm2Verify(pub1, raw, sig))
	}

	{
		encryptedText, err := f.Sm2Encrypt(rand.Reader, pub1, raw)
		assert.Nil(err)

		plainText, err := sm2.Decrypt(&priv2, encryptedText)
		assert.Nil(err)
		assert.Equal(raw, plainText)
	}

	{
		encryptedText, err := sm2.Encrypt(&pub2, raw)
		assert.Nil(err)

		plainText, err := f.Sm2Decrypt(priv1, encryptedText)
		assert.Nil(err)
		assert.Equal(raw, plainText)
	}
}
