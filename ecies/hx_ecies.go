package ecies

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

var (
	N            *big.Int
	P            *big.Int
	B            *big.Int
	prvThreshold *big.Int
	nMinus       *big.Int
	defaultCurve elliptic.Curve

	one   = new(big.Int).SetInt64(1)
	three = new(big.Int).SetInt64(3)
)

func init() {
	defaultCurve = elliptic.P256()
	N = defaultCurve.Params().N
	P = defaultCurve.Params().P
	B = defaultCurve.Params().B
	prvThreshold = new(big.Int).Sqrt(N)
	nMinus = new(big.Int).Sub(N, one)
}

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

func PrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	h := sha256.New().Sum(seed)
	var key [33]byte
	copy(key[1:], h)
	return PrivateKeyFromBytes(&key)
}

func PrivateKeyFromBytes(key *[33]byte) (*PrivateKey, error) {
	if key[0] != 0 {
		return nil, fmt.Errorf("invalid key with prefix: %d", key[0])
	}
	var priv = PrivateKey{
		PublicKey: PublicKey{
			Curve:  defaultCurve,
			Params: ParamsFromCurve(defaultCurve),
		},
	}

	d := new(big.Int).SetBytes(key[1:])
	priv.D = d.Mod(d, N)
	if priv.D.Sign() == 0 {
		return nil, fmt.Errorf("invalid key: %s", hex.EncodeToString(key[:]))
	}

	// update key
	if d.Cmp(priv.D) != 0 {
		var k [33]byte
		copy(k[33-len(priv.D.Bytes()):], priv.D.Bytes())
		*key = k
	}

	priv.X, priv.Y = priv.Curve.ScalarBaseMult(key[1:])
	return &priv, nil
}

func PublicKeyFromBytes(key *[33]byte) (*PublicKey, error) {
	if key[0] != 2 && key[0] != 3 {
		return nil, fmt.Errorf("invalid key with prefix: %d", key[0])
	}

	pub := PublicKey{
		Curve:  defaultCurve,
		Params: ParamsFromCurve(defaultCurve),
	}

	X := new(big.Int).SetBytes(key[1:])
	pub.X = X.Mod(X, P)

	{
		xCubed := new(big.Int).Exp(pub.X, three, P)
		threeX := new(big.Int).Mul(pub.X, three)
		ySqured := new(big.Int).Sub(xCubed, threeX)
		ySqured.Add(ySqured, B)
		pub.Y = new(big.Int).ModSqrt(ySqured, P)
		if pub.Y == nil {
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
	return &pub, nil
}
