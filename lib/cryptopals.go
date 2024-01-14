package cryptopals

func FixedXOR(b1 []byte, b2 []byte) []byte {
	if len(b1) != len(b2) {
		panic("inputs are not same length")
	}
	xor := make([]byte, len(b1))
	for i := range b1 {
		xor[i] = b1[i] ^ b2[i]
	}

	return xor
}
