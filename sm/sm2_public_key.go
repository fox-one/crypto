package sm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

type (
	PublicKey struct {
		X, Y *big.Int
		key  *[33]byte
	}
)

func PublicKeyFromBytes(key *[33]byte) (*PublicKey, error) {
	if key[0] != 2 && key[0] != 3 {
		return nil, fmt.Errorf("invalid key with prefix: %d", key[0])
	}

	pub := &PublicKey{}
	X := new(big.Int).SetBytes(key[1:])
	pub.X = X.Mod(X, P)

	{
		xCubed := new(big.Int).Exp(pub.X, three, P)
		threeX := new(big.Int).Mul(pub.X, three)
		ySqured := new(big.Int).Sub(xCubed, threeX)
		ySqured.Add(ySqured, B)
		pub.Y = new(big.Int).ModSqrt(ySqured, P)
		if pub.Y == nil || !CheckKey(pub) {
			return nil, fmt.Errorf("invalid key value: %s", hex.EncodeToString(key[:]))
		}

		if key[0] != byte(pub.Y.Bit(0)+2) {
			pub.Y.Sub(P, pub.Y)
		}
	}

	// update key
	if pub.X.Cmp(X) != 0 {
		var k [33]byte
		k[0] = key[0]
		copy(k[33-len(pub.X.Bytes()):], pub.X.Bytes())
		*key = k
	}

	return pub, nil
}

func (p *PublicKey) Bytes() [33]byte {
	if p.key == nil {
		var key [33]byte
		xBts := p.X.Bytes()
		copy(key[len(key)-len(xBts):], xBts)
		key[0] = byte(2 + p.Y.Bit(0))
		p.key = &key
	}
	return *p.key
}

func (p *PublicKey) String() string {
	data := p.Bytes()
	return hex.EncodeToString(data[:])
}

func CheckKey(p *PublicKey) bool {
	if p.X.Sign() == 0 || (Gnx.Cmp(p.X) == 0 && Gny.Cmp(p.Y) == 0) {
		return false
	}
	return true
}

func AddPublic(p, p1 *PublicKey) (*PublicKey, error) {
	s := &PublicKey{}
	s.X, s.Y = sm2P256.Add(p.X, p.Y, p1.X, p1.Y)
	if !CheckKey(s) {
		return s, errors.New("invalid public key")
	}
	return s, nil
}

func (p PublicKey) SubPublic(p1 *PublicKey) (*PublicKey, error) {
	s := &PublicKey{}
	Y1 := new(big.Int).Neg(p1.Y)
	s.X, s.Y = sm2P256.Add(p.X, p.Y, p1.X, Y1)
	if !CheckKey(s) {
		return s, errors.New("invalid public key")
	}
	return s, nil
}

func ScalarHash(p PublicKey, outputIndex uint64) *PrivateKey {
	data := append(p.X.Bytes(), big.NewInt(int64(outputIndex)).Bytes()...)
	data = append(data, p.Y.Bytes()...)
	h := Sm3Sum(data)
	h = Sm3Sum(append(data, h[:]...))

	priv := &PrivateKey{}
	for {
		priv.D = new(big.Int).SetBytes(h[:])
		priv.D.Mod(priv.D, N)
		if CheckScalar(priv) {
			break
		}
		h = Sm3Sum(append(h[:], h[:]...))
	}
	return priv
}

func (p PublicKey) DeterministicHashDerive() *PrivateKey {
	data := append(p.X.Bytes(), p.Y.Bytes()...)
	h := Sm3Sum(data)

	priv := &PrivateKey{}
	for {
		priv.D = new(big.Int).SetBytes(h[:])
		priv.D.Mod(priv.D, N)
		if CheckScalar(priv) {
			break
		}
		h = Sm3Sum(append(h[:], h[:]...))
	}
	return priv
}

func Verify(p *PublicKey, message []byte, sig [64]byte) bool {
	return factory.Sm2Verify(p, message, sig)
}

func Encrypt(p *PublicKey, plainText []byte) ([]byte, error) {
	return factory.Sm2Encrypt(rand.Reader, p, plainText)
}
