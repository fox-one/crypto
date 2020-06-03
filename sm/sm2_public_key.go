package sm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

type (
	PublicKey struct {
		X, Y *big.Int
		key  *[33]byte
	}
)

func PublicKeyFromBytes(key [33]byte) (*PublicKey, error) {
	if key[0] != 2 && key[0] != 3 {
		return nil, fmt.Errorf("invalid key with prefix: %d", key[0])
	}

	var X, Y *big.Int
	X = new(big.Int).SetBytes(key[1:])
	X.Mod(X, P)

	xCubed := new(big.Int).Exp(X, three, P)
	threeX := new(big.Int).Mul(X, three)
	ySqured := new(big.Int).Sub(xCubed, threeX)
	ySqured.Add(ySqured, B)
	Y = new(big.Int).ModSqrt(ySqured, P)
	if Y == nil {
		return nil, fmt.Errorf("invalid key value: %s", hex.EncodeToString(key[:]))
	}

	if key[0] != byte(Y.Bit(0)+2) {
		Y.Sub(P, Y)
	}
	return &PublicKey{
		X:   X,
		Y:   Y,
		key: &key,
	}, nil
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

func (p PublicKey) CheckKey() bool {
	return sm2P256.IsOnCurve(p.X, p.Y)
}

func (p PublicKey) AddPublic(p1 PublicKey) (*PublicKey, error) {
	s := PublicKey{}
	s.X, s.Y = sm2P256.Add(p.X, p.Y, p1.X, p1.Y)
	return &s, nil
}

func (p PublicKey) SubPublic(p1 PublicKey) (*PublicKey, error) {
	s := PublicKey{}
	Y1 := new(big.Int).Neg(p1.Y)
	s.X, s.Y = sm2P256.Add(p.X, p.Y, p1.X, Y1)
	return &s, nil
}

func (p PublicKey) ScalarHash(outputIndex uint64) *PrivateKey {
	data := append(p.X.Bytes(), big.NewInt(int64(outputIndex)).Bytes()...)
	data = append(data, p.Y.Bytes()...)
	h := Sm3Sum(data)
	h = Sm3Sum(append(data, h[:]...))

	priv := PrivateKey{}
	for {
		priv.D = new(big.Int).SetBytes(h[:])
		priv.D = priv.D.Mod(priv.D, N)
		if priv.CheckScalar() {
			break
		}
		h = Sm3Sum(append(h[:], h[:]...))
	}
	return &priv
}

func (p PublicKey) DeterministicHashDerive() *PrivateKey {
	data := append(p.X.Bytes(), p.Y.Bytes()...)
	h := Sm3Sum(data)

	priv := PrivateKey{}
	for {
		priv.D = new(big.Int).SetBytes(h[:])
		priv.D = priv.D.Mod(priv.D, N)
		if priv.CheckScalar() {
			break
		}
		h = Sm3Sum(append(h[:], h[:]...))
	}
	return &priv
}

func (p PublicKey) Verify(message []byte, sig [64]byte) bool {
	return factory.Sm2Verify(&p, message, sig)
}

func (p *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	return factory.Sm2Encrypt(rand.Reader, p, plainText)
}
