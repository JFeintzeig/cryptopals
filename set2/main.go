package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"

	"jfeintzeig/cryptopals/lib"
)

func PKCS7(block []byte, length int) []byte {
  padLength := length - len(block)

  padding := make([]byte, padLength)
  for i := range padding {
    padding[i] = byte(padLength)
  }
  return append(block, padding...)
}

func Challenge9() {
  input := []byte("YELLOW SUBMARINE")
  length := 81
  padded := PKCS7(input, length)
  fmt.Printf("Challenge 9: %s\n", padded)
  if string(padded) != "YELLOW SUBMARINEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
    panic("problem w challenge 9")
  }
}

func CBCEncrypt(payload []byte, key []byte, iv []byte) []byte {
  block, err := aes.NewCipher(key)
  blockSize := block.BlockSize()
  if err != nil {
    fmt.Printf("problem creating block\n")
  }

  out := make([]byte, len(payload))

  for i := 0; i < len(payload); i += blockSize {
    var input []byte
    if i == 0 {
      input = cryptopals.FixedXOR(iv, payload[i:i+blockSize])
    } else {
      input = cryptopals.FixedXOR(out[i-blockSize:i], payload[i:i+blockSize])
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
  return out
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

  test := []byte("this is a string and another one what dya knowww")
  encrypted := CBCEncrypt(test, key, iv)
  decrypted := CBCDecrypt(encrypted, key, iv)
  if !reflect.DeepEqual(test, decrypted) {
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
