package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	cryptopals "jfeintzeig/cryptopals/lib"
) 

var Ch19Key []byte
var Ch20Key []byte

func init() {
  Ch19Key = cryptopals.RandomAESKey()
  Ch20Key = cryptopals.RandomAESKey()
}

// i dont like that i put the b64 and ciphertext in the same place
// because it confuses whether im using info from the b64 in the attack
// or not. im not. i only need ciphertext (and length is length of ciphertext)
type Entry struct {
  b64 []byte
  ciphertext []byte
  length int
}

type ByteContainer struct {
  cipher byte
  decrypted byte
  index int
}

type ByteWithSameKey struct {
  index int
  data []ByteContainer
}

func (b *ByteWithSameKey) getBytes() []byte {
  out := make([]byte, 0)
  for _, bc := range b.data {
    out = append(out, bc.cipher)
  }
  return out
}

func (b *ByteWithSameKey) addDecrypted(decrypted []byte) {
  if len(decrypted) != len(b.data) {
    panic("mismatched length between decrypted and ByteContainer slice")
  }
  for i, v := range decrypted {
    b.data[i].decrypted = v
  }
}

func Transpose(entries []Entry, maxLength int) []ByteWithSameKey {
  out := make([]ByteWithSameKey, maxLength)

  for i := 0; i < maxLength; i++ {
    transposed := make([]ByteContainer, 0)
    for ei, e := range entries {
      if i >= e.length {
        continue
      }

      bc := ByteContainer{cipher: e.ciphertext[i], index: ei}
      transposed = append(transposed, bc)
    }
    out[i] = ByteWithSameKey{index: i, data: transposed}
  }

  return out
}

func Reconstruct(ciphertextIndex int, ciphertextLength int, transposed []ByteWithSameKey) []byte {
  out := make([]byte, ciphertextLength)
  for i := 0; i < ciphertextLength; i++ {
    t := transposed[i]
    if i != t.index {
      panic("problem with order")
    }
    for _, bc := range t.data {
      if bc.index == ciphertextIndex {
        out[i] = bc.decrypted
      }
    }
  }
  return out
}

func EncryptStringsWithCTR(fileName string, key []byte) ([]Entry, int) {
  file, err := os.ReadFile(fileName)
  if err != nil {
    panic(err)
  }
  lines := strings.Split(string(file),"\n")
  nonce := cryptopals.MakeSingleByteSlice(0x0, 8)

  entries := make([]Entry, len(lines))

  maxLength := 0
  for i, line := range lines {
    decoded, err := base64.StdEncoding.DecodeString(line)
    if err != nil {
      panic("problem b64 decoding")
    }

    cipher := cryptopals.CTREncrypt(decoded, key, nonce)
    if len(cipher) != len(decoded) {
      fmt.Printf("***** uh oh problem with length from CTR *****\n")
    }

    entries[i] = Entry{[]byte(line), cipher, len(cipher)}
    if len(cipher) > maxLength {
      maxLength = len(cipher)
    }
  }

  return entries, maxLength
}

func DecryptStringsWithCTR(entries []Entry, maxLength int) [][]byte {
  transposed := Transpose(entries, maxLength)

  for i, item := range transposed {
    d, _, _ := cryptopals.DecryptSingleByteXOR(item.getBytes())
    transposed[i].addDecrypted([]byte(d))

    if len(d) != len(item.data) {
      fmt.Printf("*****uh oh losing bytes*****\n")
    }
    if len(item.getBytes()) < 3 {
      fmt.Printf("")
    }
  }

  decrypted := make([][]byte, len(entries))
  for i := range entries {
    decrypted[i] = Reconstruct(i, len(entries[i].ciphertext), transposed)
  }
  return decrypted
}

func Challenge19() {
  fmt.Printf("*************** Challenge 19 ****************\n")
  entries, maxLength := EncryptStringsWithCTR("19.txt", Ch19Key)
  decrypted := DecryptStringsWithCTR(entries, maxLength)
  for i := range decrypted {
  fmt.Printf("%s\n", decrypted[i])
    if i == 0 && string(decrypted[i]) != "i have met them at close of day" {
      panic("problem with challenge 19")
    }
  }
  fmt.Printf("*************** END Challenge 19 ****************\n")
}

func Challenge20() {
  fmt.Printf("*************** Challenge 20 ****************\n")
  entries, maxLength := EncryptStringsWithCTR("20.txt", Ch19Key)
  decrypted := DecryptStringsWithCTR(entries, maxLength)
  for i := range decrypted {
  fmt.Printf("%s\n", decrypted[i])
    if i == 0 && string(decrypted[i]) != "i'm rated \"R\"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed" {
      panic("problem with challenge 20")
    }
  }
  fmt.Printf("*************** END Challenge 20 ****************\n")
}
func main() {
  Challenge19()
  Challenge20()
}
