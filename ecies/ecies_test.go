package ecies

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECIES(t *testing.T) {
	const (
		m = "just a test"
	)

	assert := assert.New(t)
	pri := NewPrivateKey(rand.Reader)
	pub := pri.PublicKey

	// encrypt & decrypt
	{
		bts, err := Encrypt(rand.Reader, &pub, []byte(m), nil, nil)
		assert.Nil(err, "ecies encrypt")

		plain, err := pri.Decrypt(bts, nil, nil)
		assert.Nil(err, "ecies decrypt")
		assert.Equal(m, string(plain), "decrypted message not matched")
	}
}
