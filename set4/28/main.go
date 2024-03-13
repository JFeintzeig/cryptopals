package main

import (
	"encoding/hex"
	"fmt"
	"reflect"

	sha1 "jfeintzeig/cryptopals/lib/sha1"
  cryptopals "jfeintzeig/cryptopals/lib"
)

var key []byte

func init() {
  key = cryptopals.RandomAESKey()
}

func authenticate(message []byte) []byte {
  input := append(key, message...)
  hasher := sha1.New()
  hasher.Write(input)
  return hasher.Sum(nil)
}

func main() {

  testInput := []byte("hello hello")
  truth, _ := hex.DecodeString("dccf719f8dad2d6f4d4d9c9e1eb6592ed8acbf24")

  hasher := sha1.New()
  hasher.Write(testInput)
  output := hasher.Sum(nil)

  fmt.Printf("%x\n%x\n", truth, output)

  if !reflect.DeepEqual(output, truth) {
    panic("sha1 doesn't work")
  }

  mac := authenticate(testInput)
  mac2 := authenticate([]byte("hello hellp"))
  fmt.Printf("%x\n", mac)
  fmt.Printf("%x\n", mac2)
}
