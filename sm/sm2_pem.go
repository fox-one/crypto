package sm

import (
	"github.com/tjfoc/gmsm/sm2"
)

func PrivateKeyFromPem(pemBts []byte) (*PrivateKey, error) {
	priv, err := sm2.ReadPrivateKeyFromMem(pemBts, nil)
	if err != nil {
		return nil, err
	}

	return PrivateKeyFromInteger(priv.D)
}

func PrivateKeyToPem(priv *PrivateKey) ([]byte, error) {
	pub := priv.PublicKey()
	return sm2.WritePrivateKeytoMem(&sm2.PrivateKey{
		D: priv.D,
		PublicKey: sm2.PublicKey{
			Curve: sm2P256,
			X:     pub.X,
			Y:     pub.Y,
		},
	}, nil)
}

func PublicKeyFromPem(pemBts []byte) (*PublicKey, error) {
	pub, err := sm2.ReadPublicKeyFromMem(pemBts, nil)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		X: pub.X,
		Y: pub.Y,
	}, nil
}

func PublicKeyToPem(pub *PublicKey) ([]byte, error) {
	return sm2.WritePublicKeytoMem(&sm2.PublicKey{
		Curve: sm2P256,
		X:     pub.X,
		Y:     pub.Y,
	}, nil)
}
