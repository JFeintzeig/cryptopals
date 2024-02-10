package main

import (
	"encoding/base64"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
)

func main() {
  ciphertext, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
  fmt.Printf("length of cipher: %d\n", len(ciphertext))
  if err != nil {
    panic("error b64 decoding ciphertext")
  }

  decrypted := cryptopals.CTRDecrypt(ciphertext, []byte("YELLOW SUBMARINE"), []byte{0, 0, 0, 0, 0, 0, 0, 0})

  fmt.Printf("Decrypted: %s\n", decrypted)
}
