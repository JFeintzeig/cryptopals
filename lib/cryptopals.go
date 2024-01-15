package cryptopals

import (
	"crypto/aes"
  "encoding/hex"
  "fmt"
)

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

func PKCS7(input []byte, blocksize int) []byte {
	padLength := (blocksize - (len(input) % blocksize))
	if padLength == blocksize {
		return input
	}

	padding := make([]byte, padLength)
	for i := range padding {
		padding[i] = byte(padLength)
	}
	return append(input, padding...)
}

func PKCS7Unpad(input []byte, blocksize int) []byte {
	paddingLength := input[len(input)-1]
	for i := range input {
		if (i >= (len(input) - int(paddingLength))) && input[i] != paddingLength {
			return input
		}
	}
	return input[:len(input)-int(paddingLength)]
}

func AESDecrypt(input []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
  blockSize := block.BlockSize()

	if err != nil {
		fmt.Printf("problem creating block\n")
	}

  decrypted := make([]byte, 0)
	out := make([]byte, block.BlockSize())

	for i := 0; i < len(input); i += blockSize {
		thisblock := input[i : i+blockSize]
		block.Decrypt(out, thisblock)
    decrypted = append(decrypted, out...)
	}
  return PKCS7Unpad(decrypted, blockSize)
}

func AESEncrypt(input []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
  blockSize := block.BlockSize()

	if err != nil {
		fmt.Printf("problem creating block\n")
	}

  paddedInput := PKCS7(input, blockSize)
  encrypted := make([]byte, 0)
	out := make([]byte, block.BlockSize())

	for i := 0; i < len(paddedInput); i += blockSize {
		thisblock := paddedInput[i : i+blockSize]
		block.Encrypt(out, thisblock)
    encrypted = append(encrypted, out...)
	}
  return encrypted
}

func CountMatches(input []byte) int {
		nSame := 0
		segment := make(map[string]int)
		for j := 0; j < len(input); j += 16 {
			inputString := hex.EncodeToString(input[j : j+16])
			if _, ok := segment[inputString]; ok {
				segment[inputString] += 1
			} else {
				segment[inputString] = 1
			}

			for _, v := range segment {
				if v > nSame {
					nSame = v
				}
			}
  }
  return nSame
}
