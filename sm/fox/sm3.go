package fsm

import "github.com/tjfoc/gmsm/sm3"

func (f smFactory) Sm3Sum(message []byte) (digest [32]byte) {
	hash := sm3.Sm3Sum(message)
	digest = *new([32]byte)
	copy(digest[:], hash)
	return
}
