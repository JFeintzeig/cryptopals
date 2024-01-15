package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
  "math/rand"
	"os"
	"reflect"

	"jfeintzeig/cryptopals/lib"
)


func Challenge9() {
	input := []byte("YELLOW SUBMARINE")
	length := 81
	padded := cryptopals.PKCS7(input, length)
	fmt.Printf("Challenge 9: %s\n", padded)
	if string(padded) != "YELLOW SUBMARINEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		panic("problem w challenge 9")
	}

	pad := cryptopals.PKCS7(input, 16)
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

	paddedPayload := cryptopals.PKCS7(payload, blockSize)

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
	return cryptopals.PKCS7Unpad(out, blockSize)
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

func EncryptionOracle(input []byte) ([]byte, string) {
  nPrepend := 5 + rand.Intn(5)
  nAppend :=  5 + rand.Intn(5)
  payload := append(GenerateRandomBytes(nPrepend), input...)
  payload = append(payload, GenerateRandomBytes(nAppend)...)

  key := RandomAESKey()

  if rand.Intn(2) == 0 {
    return cryptopals.AESEncrypt(payload, key), "ECB"
  } else {
    iv := GenerateRandomBytes(16)
    return CBCEncrypt(payload, key, iv), "CBC"
  }
}


func Challenge11() {
  key := []byte("YELLOW SUBMARINE")
  input := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  encrypted := cryptopals.AESEncrypt(input, key)
  decrypted := cryptopals.AESDecrypt(encrypted, key)
  if !reflect.DeepEqual(input, decrypted) {
    panic("AES roundtrip fails")
  }

  nRounds := 10000
  var guessedMethod string
  for i := 0; i < nRounds; i++ {
    encrypted, actualMethod := EncryptionOracle(input)
    nSame := cryptopals.CountMatches(encrypted)
    if nSame > 1 {
      guessedMethod = "ECB"
    } else {
      guessedMethod = "CBC"
    }

    if guessedMethod != actualMethod {
      panic("uh oh my oracle guessing fails")
    }
  }

  fmt.Printf("********** Challenge 11 ***********\n")
  fmt.Printf("Guessed ECB / CBC correct for %d rounds\n", nRounds)
  fmt.Printf("********** END Challenge 11 ***********\n")
}

func main() {
	Challenge9()
	Challenge10()
	Challenge11()
}
