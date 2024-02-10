package main

import (
	"encoding/base64"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"reflect"
)

func main() {
  ciphertext, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
  fmt.Printf("length of cipher: %d\n", len(ciphertext))
  if err != nil {
    panic("error b64 decoding ciphertext")
  }

  decrypted := cryptopals.CTREncrypt(ciphertext, []byte("YELLOW SUBMARINE"), []byte{0, 0, 0, 0, 0, 0, 0, 0})
  recrypted := cryptopals.CTREncrypt(decrypted, []byte("YELLOW SUBMARINE"), []byte{0, 0, 0, 0, 0, 0, 0, 0})
  doubleDecrypted := cryptopals.CTREncrypt(recrypted, []byte("YELLOW SUBMARINE"), []byte{0, 0, 0, 0, 0, 0, 0, 0})
  if !reflect.DeepEqual(decrypted, doubleDecrypted) {
    panic("CTR encrypt round trip fails")
  }

  fmt.Printf("Decrypted: %s\n", decrypted)
}
