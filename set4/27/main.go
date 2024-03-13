package main

import (
	"fmt"
	"reflect"
	"strings"

	cryptopals "jfeintzeig/cryptopals/lib"
)

type MyError struct {
  plaintext []byte
}

func (e MyError) Error() string {
  return fmt.Sprintf("%v\n", e.plaintext)
}

var ch27AESKey []byte

func init() {
	ch27AESKey = cryptopals.RandomAESKey()
}

func Ch27Oracle(input []byte) []byte {
	prependBytes := []byte("comment1=cooking%20MCs;userdata=")
	appendBytes := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	sanitizedInput := strings.ReplaceAll(string(input), ";", "/;/")
	sanitizedInput = strings.ReplaceAll(sanitizedInput, "=", "/=/")

	payload := append(prependBytes, sanitizedInput...)
	payload = append(payload, appendBytes...)

	paddedPayload := cryptopals.PKCS7(payload, 16)

	return cryptopals.CBCEncrypt(paddedPayload, ch27AESKey, ch27AESKey)
}

func CheckASCII(plaintext []byte) bool {
  for _, value := range plaintext {
    if value > 127 {
      return false
    }
  }

  return true
}

func Ch27CheckAdmin(ciphertext []byte) (bool, error) {
	decrypted, err := cryptopals.CBCDecrypt(ciphertext, ch27AESKey, ch27AESKey)
  if err != nil {
    fmt.Printf(err.Error())
    panic("problem w CBC decrypt padding")
  }

  if !CheckASCII(decrypted) {
    return false, MyError{decrypted}
  }

	return strings.Contains(string(decrypted), ";admin=true;"), nil
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
	encrypted := Ch27Oracle([]byte(";admin=true;"))
	hasAdmin, _ := Ch27CheckAdmin(encrypted)
	if hasAdmin {
		panic("ch 27 test fails: shouldnt be able to set admin=true directly")
	}

  input := cryptopals.MakeSingleByteSlice(0x41, 16)
  input = append(input, cryptopals.MakeSingleByteSlice(0x42, 16)...)
  input = append(input, cryptopals.MakeSingleByteSlice(0x43, 16)...)

	cipher := Ch27Oracle(input)
  newCipher := make([]byte, 0)
  newCipher = append(newCipher, cipher[:16]...)
  newCipher = append(newCipher, cryptopals.MakeSingleByteSlice(0x00, 16)...)
  newCipher = append(newCipher, cipher[:16]...)
  newCipher = append(newCipher, cipher[48:]...)

	_, err := Ch27CheckAdmin(newCipher)
  if err != nil {
    fmt.Printf("ASCII Error\n") 
    me, ok := err.(MyError)
    if ok {
      pt := me.plaintext
      recoveredKey := cryptopals.FixedXOR(pt[:16], pt[32:48])
      fmt.Printf("%v\n%v\n", ch27AESKey, recoveredKey)
      if !reflect.DeepEqual(recoveredKey, ch27AESKey) {
        panic("Ch 27 didnt work!")
      }
      fmt.Printf("\nChallenge 27 Success!\n")
    }
  }
}
