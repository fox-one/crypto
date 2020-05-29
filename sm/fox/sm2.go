package fsm

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/fox-one/crypto/sm"
	"github.com/tjfoc/gmsm/sm2"
)

var (
	sm2P256 elliptic.Curve
	N, P    *big.Int

	one      = new(big.Int).SetInt64(1)
	zaPrefix []byte
)

func init() {
	sm2P256 = sm2.P256Sm2()
	N = sm2P256.Params().N
	P = sm2P256.Params().P

	var (
		defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
		entla      = len(defaultUID) * 8

		a, _ = hex.DecodeString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
	)

	zaPrefix = []byte{byte((entla >> 8) & 0xFF), byte(entla & 0xFF)}
	zaPrefix = append(zaPrefix, defaultUID...)
	zaPrefix = append(zaPrefix, a...)
	zaPrefix = append(zaPrefix, sm2P256.Params().B.Bytes()...)
	zaPrefix = append(zaPrefix, sm2P256.Params().Gx.Bytes()...)
	zaPrefix = append(zaPrefix, sm2P256.Params().Gy.Bytes()...)
}

func (f smFactory) za(pub *sm.PublicKey) [32]byte {
	var xBts [32]byte
	copy(xBts[32-len(pub.X.Bytes()):], pub.X.Bytes())
	msg := append(zaPrefix, xBts[:]...)
	msg = append(msg, pub.Y.Bytes()...)
	return f.Sm3Sum(msg)
}

func (f smFactory) Sm2Sign(random io.Reader, p *sm.PrivateKey, message []byte) (signature [64]byte, err error) {
	za := f.za(p.PublicKey())
	sum := f.Sm3Sum(append(za[:], message...))
	e := new(big.Int).SetBytes(sum[:])

	var (
		k *big.Int
		r *big.Int
		s *big.Int
	)
	for {
		for {
			k, err = rand.Int(random, N)
			if err != nil {
				return
			}

			r, _ = sm2P256.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if new(big.Int).Add(r, k).Cmp(N) != 0 {
					break
				}
			}
		}
		rD := new(big.Int).Mul(p.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(p.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}

	signature = [64]byte{}
	copy(signature[32-len(r.Bytes()):], r.Bytes())
	copy(signature[64-len(s.Bytes()):], s.Bytes())
	return
}

func (f smFactory) Sm2Verify(pub *sm.PublicKey, message []byte, signature [64]byte) bool {
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	za := f.za(pub)
	sum := f.Sm3Sum(append(za[:], message...))
	e := new(big.Int).SetBytes(sum[:])

	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	x1, y1 := sm2P256.ScalarBaseMult(s.Bytes())
	x2, y2 := sm2P256.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = sm2P256.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func (f smFactory) kdf(x, y []byte, length int) ([]byte, bool) {
	x = append(x, y...)

	var (
		round = 1

		data []byte
		buf  = make([]byte, 4)
	)
	for i, j := 0, (length+31)/32; i < j; i++ {
		binary.BigEndian.PutUint32(buf, uint32(round))
		hash := sm.Sm3Sum(append(x, buf...))
		data = append(data, hash[:]...)
		round++
	}

	data = data[:length]
	for i := 0; i < length; i++ {
		if data[i] != 0 {
			return data, true
		}
	}
	return nil, false
}

func (f smFactory) Sm2Encrypt(random io.Reader, pub *sm.PublicKey, plainText []byte) ([]byte, error) {
	length := len(plainText)

	for {
		k, err := rand.Int(random, N)
		if err != nil {
			return nil, err
		}

		c := make([]byte, 97)
		c[0] = 0x04
		{
			x1, y1 := sm2P256.ScalarBaseMult(k.Bytes())
			copy(c[33-len(x1.Bytes()):], x1.Bytes())
			copy(c[65-len(y1.Bytes()):], y1.Bytes())
		}

		var x2Bts [32]byte
		var y2Bts [32]byte
		{
			x2, y2 := sm2P256.ScalarMult(pub.X, pub.Y, k.Bytes())
			copy(x2Bts[32-len(x2.Bytes()):], x2.Bytes())
			copy(y2Bts[32-len(y2.Bytes()):], y2.Bytes())

			tm := []byte{}
			tm = append(tm, x2Bts[:]...)
			tm = append(tm, plainText...)
			tm = append(tm, y2Bts[:]...)
			h := sm.Sm3Sum(tm)
			copy(c[65:], h[:])
		}

		ct, ok := f.kdf(x2Bts[:], y2Bts[:], length) // 密文
		if !ok {
			continue
		}
		for i := 0; i < length; i++ {
			ct[i] ^= plainText[i]
		}
		c = append(c, ct...)
		return c, nil
	}
}

func (f smFactory) Sm2Decrypt(p *sm.PrivateKey, encryptedText []byte) (plainText []byte, err error) {
	if encryptedText[0] != 4 {
		return nil, errors.New("Sm2Decrypt failed: public key should not be compressed")
	}

	if len(encryptedText) < 98 {
		return nil, errors.New("Sm2Decrypt failed: invalid encrypted length")
	}

	length := len(encryptedText) - 97

	var x2Bts [32]byte
	var y2Bts [32]byte
	{
		x := new(big.Int).SetBytes(encryptedText[1:33])
		y := new(big.Int).SetBytes(encryptedText[33:65])
		x2, y2 := sm2P256.ScalarMult(x, y, p.D.Bytes())
		copy(x2Bts[32-len(x2.Bytes()):], x2.Bytes())
		copy(y2Bts[32-len(y2.Bytes()):], y2.Bytes())
	}
	c, ok := f.kdf(x2Bts[:], y2Bts[:], length)
	if !ok {
		return nil, errors.New("Sm2Decrypt failed: failed to decrypt")
	}

	for i := 0; i < length; i++ {
		c[i] ^= encryptedText[i+97]
	}

	{
		tm := []byte{}
		tm = append(tm, x2Bts[:]...)
		tm = append(tm, c...)
		tm = append(tm, y2Bts[:]...)
		hash := sm.Sm3Sum(tm)
		if bytes.Compare(hash[:], encryptedText[65:97]) != 0 {
			return c, errors.New("Sm2Decrypt failed: failed to decrypt")
		}
	}

	plainText = c
	return
}
