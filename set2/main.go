package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"

	"jfeintzeig/cryptopals/lib"
)

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

func Challenge9() {
	input := []byte("YELLOW SUBMARINE")
	length := 81
	padded := PKCS7(input, length)
	fmt.Printf("Challenge 9: %s\n", padded)
	if string(padded) != "YELLOW SUBMARINEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		panic("problem w challenge 9")
	}

	pad := PKCS7(input, 16)
	if !reflect.DeepEqual(input, pad) {
		panic("pkcs7 w/no pad required doesn't work")
	}
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
			input = cryptopals.FixedXOR(iv, paddedPayload[i:i+blockSize])
		} else {
			input = cryptopals.FixedXOR(out[i-blockSize:i], paddedPayload[i:i+blockSize])
		}
		block.Encrypt(out[i:i+blockSize], input)
	}
	return out
}

func CBCDecrypt(payload []byte, key []byte, iv []byte) []byte {
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
			decryptedBlock = cryptopals.FixedXOR(iv, rawDecryptedBlock)
		} else {
			decryptedBlock = cryptopals.FixedXOR(payload[i-blockSize:i], rawDecryptedBlock)
		}
		copy(out[i:i+blockSize], decryptedBlock)
	}
	return PKCS7Unpad(out, blockSize)
}

func Challenge10() {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	file, err := os.ReadFile("10.txt")
	if err != nil {
		panic("problem opening file")
	}
	input, err := base64.StdEncoding.DecodeString(string(file))

	fmt.Printf("\n ********** Challenge 10 ************\n")

	test := []byte("this is a string and another one what ya now")
	encrypted := CBCEncrypt(test, key, iv)
	decrypted := CBCDecrypt(encrypted, key, iv)
	if !reflect.DeepEqual(test, decrypted) {
		fmt.Printf("%s %v\n", test, test)
		fmt.Printf("%v\n", encrypted)
		fmt.Printf("%s %v\n", decrypted, decrypted)
		panic("CBC mode roundtrip doesn't work")
	}

	decrypted = CBCDecrypt(input, key, iv)
	fmt.Printf("%s\n", decrypted)

	fmt.Printf("********** END Challenge 10 ***********\n")
}

func main() {
	Challenge9()
	Challenge10()
}
