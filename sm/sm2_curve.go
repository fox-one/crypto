package sm

import (
	"crypto/elliptic"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

var (
	sm2P256      elliptic.Curve
	N, P, B      *big.Int
	Gnx, Gny     *big.Int
	prvThreshold *big.Int

	one       = new(big.Int).SetInt64(1)
	two       = new(big.Int).SetInt64(2)
	three     = new(big.Int).SetInt64(3)
	nMinus    *big.Int
	nMinusTwo *big.Int
)

func init() {
	sm2P256 = sm2.P256Sm2()
	N = sm2P256.Params().N
	P = sm2P256.Params().P
	B = sm2P256.Params().B

	nMinus = new(big.Int).Sub(N, one)
	nMinusTwo = new(big.Int).Sub(nMinus, one)
	prvThreshold = new(big.Int).Sqrt(N)
	Gnx, Gny = sm2P256.ScalarBaseMult(nMinus.Bytes())

	// A: FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
	// ==>
	// A: -3
}
