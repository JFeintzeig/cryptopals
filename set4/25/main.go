package main

import (
	"encoding/base64"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"os"
	"reflect"
)

var key []byte
var nonce []byte

func init() {
  key = cryptopals.RandomAESKey()
  nonce = cryptopals.RandomAESKey()
}

func editCipher(ciphertext []byte, key []byte, offset int, newtext []byte) []byte {
  plaintext := cryptopals.CTREncrypt(ciphertext, key, nonce)

  for i := 0; i < len(newtext); i++ {
    plaintext[offset + i] = newtext[i] 
  }
  return cryptopals.CTREncrypt(plaintext, key, nonce)
}

func main() {
	key := []byte("YELLOW SUBMARINE")
	file, err := os.ReadFile("input.txt")
	if err != nil {
		panic("problem opening file")
	}
	input, err := base64.StdEncoding.DecodeString(string(file))

  decrypted := cryptopals.AESDecrypt(input, key)

  cipher := cryptopals.CTREncrypt(decrypted, key, nonce)

  // if we replace the whole payload with text we know,
  // then we'll know our plaintext and get the resulting
  // cipher, and we can just XOR them to get every byte of the
  // keystream. then XOR'ing the keystream with the original cipher
  // gives us the original plaintext.
  // Assumption: this requires the editCipher function re-encrypts
  // using the same nonce.
  known := cryptopals.MakeSingleByteSlice(0x41, len(cipher))
  newCipher := editCipher(cipher, key, 0, known)
  keystream := cryptopals.FixedXOR(newCipher, known)
  plaintext := cryptopals.FixedXOR(keystream, cipher)

  if !reflect.DeepEqual(plaintext, decrypted) {
    panic("didn't recover plaintext input!")
  }

  fmt.Printf("%s\n", plaintext)
}
