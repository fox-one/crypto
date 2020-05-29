package sm

func Sm3Sum(bts []byte) [32]byte {
	return factory.Sm3Sum(bts)
}
