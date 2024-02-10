package cryptopals

import (
	"crypto/aes"
  "encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
  "math/rand"
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

	padding := make([]byte, padLength)
	for i := range padding {
		padding[i] = byte(padLength)
	}
	return append(input, padding...)
}

func PKCS7Unpad(input []byte, blocksize int) ([]byte, error) {
	paddingLength := input[len(input)-1]

  if paddingLength == 0x00 || int(paddingLength) > blocksize {
    return nil, errors.New("invalid pkcs7 padding: should always be between 1 and <BLOCKSIZE> bytes")
  }
	for i := range input {
		if (i >= (len(input) - int(paddingLength))) && input[i] != paddingLength {
			return nil, errors.New("invalid pkcs7 padding")
		}
	}
	return input[:len(input)-int(paddingLength)], nil
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
	unpadded, err := PKCS7Unpad(decrypted, blockSize)
	if err != nil {
		panic("problem unpadding result")
	}
	return unpadded
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

func CountMatches(input []byte, blockSize int) int {
	if blockSize == 0 {
		fmt.Printf("can't have blocksize of 0, returning\n")
		return 0
	}
	nSame := 0
	segment := make(map[string]int)
	for j := 0; j < len(input)-blockSize; j += blockSize {
		inputString := hex.EncodeToString(input[j : j+blockSize])
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

func MakeSingleByteSlice(value byte, length int) []byte {
	var slice []byte
	for i := 0; i < length; i++ {
		slice = append(slice, value)
	}
	return slice
}

func GenerateRandomBytes(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = uint8(rand.Intn(255))
	}
	return out
}

func RandomAESKey() []byte {
	return GenerateRandomBytes(16)
}

func CBCEncrypt(payload []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	blockSize := block.BlockSize()
	if err != nil {
		fmt.Printf("problem creating block\n")
	}

	paddedPayload := PKCS7(payload, blockSize)

	out := make([]byte, len(paddedPayload))

	for i := 0; i < len(paddedPayload); i += blockSize {
		var input []byte
		if i == 0 {
			input = FixedXOR(iv, paddedPayload[i:i+blockSize])
		} else {
			input = FixedXOR(out[i-blockSize:i], paddedPayload[i:i+blockSize])
		}
		block.Encrypt(out[i:i+blockSize], input)
	}
	return out
}

func CBCDecrypt(payload []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	blockSize := block.BlockSize()
	if err != nil {
		fmt.Printf("problem creating block\n")
	}

	out := make([]byte, len(payload))
	rawDecryptedBlock := make([]byte, len(key))
	decryptedBlock := make([]byte, len(key))

	for i := 0; i < len(payload); i += blockSize {
		block.Decrypt(rawDecryptedBlock, payload[i:i+blockSize])
		if i == 0 {
			decryptedBlock = FixedXOR(iv, rawDecryptedBlock)
		} else {
			decryptedBlock = FixedXOR(payload[i-blockSize:i], rawDecryptedBlock)
		}
		copy(out[i:i+blockSize], decryptedBlock)
	}
	return PKCS7Unpad(out, blockSize)
}

func CTRDecrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
  if err != nil {
    panic("problem creating aes cipher for key")
  }
	blockSize := block.BlockSize()

	decrypted := make([]byte, 0)
	out := make([]byte, block.BlockSize())
  counterBytes := make([]byte, 8)

	for i := 0; i < len(ciphertext); i += blockSize {
    binary.LittleEndian.PutUint64(counterBytes, uint64(i/blockSize))
    keystream := append(nonce, counterBytes...)
		block.Encrypt(out, keystream)

    end := i+blockSize
    if end > len(ciphertext) {
      end = len(ciphertext)
    }

		thisblock := ciphertext[i : end]
    out = FixedXOR(out[:len(thisblock)], thisblock)
		decrypted = append(decrypted, out...)
	}

	return decrypted
}
