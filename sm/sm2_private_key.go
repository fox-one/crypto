package sm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
)

type (
	PrivateKey struct {
		D *big.Int

		publicKey *PublicKey
		key       *[33]byte
	}
)

func NewPrivateKey(rand io.Reader) *PrivateKey {
	var key [33]byte
	for {
		_, err := rand.Read(key[1:])
		if err != nil {
			continue
		}

		if priv, err := PrivateKeyFromBytes(&key); err == nil && priv.D.Cmp(prvThreshold) >= 0 {
			return priv
		}
	}
}

func PrivateKeyFromInteger(d *big.Int) (*PrivateKey, error) {
	var priv PrivateKey
	priv.D = new(big.Int).Mod(d, N)
	if !priv.CheckScalar() {
		return nil, fmt.Errorf("invalid key: %v", d)
	}
	return &priv, nil
}

func PrivateKeyFromBytes(key *[33]byte) (*PrivateKey, error) {
	if key[0] != 0 {
		return nil, fmt.Errorf("invalid key with prefix: %d", key[0])
	}
	d := new(big.Int).SetBytes(key[1:])
	priv, err := PrivateKeyFromInteger(d)
	if err != nil {
		return nil, err
	}

	// update key
	if d.Cmp(priv.D) == 0 {
		priv.key = key
	}
	return priv, nil
}

func (p PrivateKey) CheckScalar() bool {
	return p.D.Sign() != 0 && p.D.Cmp(nMinus) != 0
}

func (p *PrivateKey) Bytes() [33]byte {
	if p.key == nil {
		var key [33]byte
		dBts := p.D.Bytes()
		copy(key[len(key)-len(dBts):], dBts)
		p.key = &key
	}
	return *p.key
}

func (p *PrivateKey) String() string {
	data := p.Bytes()
	return hex.EncodeToString(data[:])
}

func (p *PrivateKey) PublicKey() *PublicKey {
	if p.publicKey == nil {
		var pub PublicKey
		pub.X, pub.Y = sm2P256.ScalarBaseMult(p.D.Bytes())
		p.publicKey = &pub
	}
	return p.publicKey
}

func (p PrivateKey) AddPrivate(p1 *PrivateKey) (*PrivateKey, error) {
	s := PrivateKey{}
	s.D = new(big.Int).Add(p.D, p1.D)
	s.D.Mod(s.D, N)
	if !s.CheckScalar() {
		return &s, errors.New("invalid private key")
	}
	return &s, nil
}

func (p PrivateKey) ScalarMult(pub *PublicKey) (*PublicKey, error) {
	var s PublicKey
	s.X, s.Y = sm2P256.ScalarMult(pub.X, pub.Y, p.D.Bytes())
	return &s, nil
}

func (p *PrivateKey) Sign(random io.Reader, message []byte) ([64]byte, error) {
	return factory.Sm2Sign(random, p, message)
}

func (p *PrivateKey) Decrypt(encryptedText []byte) ([]byte, error) {
	return factory.Sm2Decrypt(p, encryptedText)
}
