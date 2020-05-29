package sm

import (
	"crypto/elliptic"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

var (
	sm2P256 elliptic.Curve
	N, P, B *big.Int

	one    = new(big.Int).SetInt64(1)
	two    = new(big.Int).SetInt64(2)
	three  = new(big.Int).SetInt64(3)
	nMinus *big.Int
)

func init() {
	sm2P256 = sm2.P256Sm2()
	N = sm2P256.Params().N
	P = sm2P256.Params().P
	B = sm2P256.Params().B

	nMinus = new(big.Int).Sub(N, one)

	// A: FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
	// ==>
	// A: -3
}
