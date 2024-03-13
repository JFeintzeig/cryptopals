package main

import (
  "fmt"
  "strings"
	cryptopals "jfeintzeig/cryptopals/lib"
)

var ch26AESKey []byte
var ch26Nonce []byte

func init() {
	ch26Nonce = cryptopals.RandomAESKey()
	ch26AESKey = cryptopals.RandomAESKey()
}

func Ch26Oracle(input []byte) []byte {
	prependBytes := []byte("comment1=cooking%20MCs;userdata=")
	appendBytes := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	sanitizedInput := strings.ReplaceAll(string(input), ";", "/;/")
	sanitizedInput = strings.ReplaceAll(sanitizedInput, "=", "/=/")

	payload := append(prependBytes, sanitizedInput...)
	payload = append(payload, appendBytes...)

	return cryptopals.CTREncrypt(payload, ch26AESKey, ch26Nonce)
}

func Ch26CheckAdmin(ciphertext []byte) bool {
	decrypted := cryptopals.CTREncrypt(ciphertext, ch26AESKey, ch26Nonce)
	return strings.Contains(string(decrypted), ";admin=true;")
}

func FlipBit(b byte, bitNumber uint8) byte {
	magicBit := (b >> bitNumber) & 0x01
	if magicBit == 1 {
		return 0b01111111 & b
	} else {
		return 0b10000000 | b
	}
}

func main() {
	encrypted := Ch26Oracle([]byte(";admin=true;"))
	hasAdmin := Ch26CheckAdmin(encrypted)
	if hasAdmin {
		panic("ch 16 test fails: shouldnt be able to set admin=true directly")
	}

  // Assumption: oracle prepends 32 bytes
  // Assumption: blocksize is 16 bytes
  // Assumption: oracle re-uses same nonce
  payload := []byte(";admin=true;AAAA") // pad out to 16
  known := cryptopals.MakeSingleByteSlice(0x41, 16)
  cipher := Ch26Oracle(known)
  keystream := cryptopals.FixedXOR(cipher[32:48], known)
  newCipherBlock := cryptopals.FixedXOR(keystream,payload)
  newCipher := append(cipher[0:32], newCipherBlock...)
  newCipher = append(newCipher, cipher[48:]...)
  isAdmin := Ch26CheckAdmin(newCipher)
  if isAdmin != true {
    panic("challenge 26 failed!")
  }

	fmt.Printf("\nisAdmin: %t\n\n", isAdmin)
}
