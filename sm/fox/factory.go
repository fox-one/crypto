package fsm

import (
	"github.com/fox-one/crypto/sm"
)

type smFactory struct{}

func Load() {
	sm.SetupKeyFactory(smFactory{})
}
