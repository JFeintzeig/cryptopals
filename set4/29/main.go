package main

import (
	"crypto/sha1"
	"fmt"
	"math/rand"
	"reflect"

	cryptopals "jfeintzeig/cryptopals/lib"
	mysha1 "jfeintzeig/cryptopals/lib/sha1"
)

var secretKey []byte
var secretKeyLength int

func init() {
  secretKeyLength = rand.Intn(20)
  secretKey = cryptopals.GenerateRandomBytes(secretKeyLength)
}

func authenticate(message []byte) []byte {
  input := append(secretKey, message...)
  hasher := sha1.New()
  hasher.Write(input)
  output := hasher.Sum(nil)
  return output
}

func CalcPadding(message []byte, keyLengthBytes int) []byte {
  ml := uint64((len(message) + keyLengthBytes)*8)
  nZeros := 512 - (ml % 512) - 64 - 8 // subtract 8 b/c of the 0x80 byte
  padding := make([]byte, 0)
  padding = append(padding, 0x80) // a 1 bit followed by 7 zeros
  for i := uint64(0); i < nZeros / 8; i++ {
    padding = append(padding, 0x00)
  }

  for i := 1; i <= 8; i++ {
    shift := 64 - i*8
    padding = append(padding, uint8((ml >> shift) & 0xFF))
  }

  return padding
}

func MacToRegisters(input []byte) []uint32 {
  output := make([]uint32, 5)

  for i, val := range input {
    output[i/4] |= uint32(val) << int(8*(3-(i%4)))
  }

  return output
}

func ForgeMessage(original []byte, originalMac []byte, keyLengthBytes int, payload []byte) ([]byte, []byte) {
  padding := CalcPadding(original, keyLengthBytes)

  newMessage := append(original, padding...)
  newMessage = append(newMessage, payload...)

  sha := mysha1.New()
  sha.SetRegisters([5]uint32(MacToRegisters(originalMac)))
  sha.Write(payload)
  extraLen := len(newMessage) - len(payload) + keyLengthBytes

  output := sha.CheckSumWithExtraLength(extraLen)
  return output[:], newMessage
}

func main() {
  fmt.Printf("Challenge 29\n")

  original := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
  originalMac := authenticate(original)

  payload := []byte(";admin=true")

  for keyLength := 0; keyLength < 50; keyLength++ {
    forgedMac, message := ForgeMessage(original, originalMac, keyLength, payload)
    realMac := authenticate(message)
    if reflect.DeepEqual(realMac, forgedMac) {
      if keyLength != secretKeyLength {
        panic("problem: reconstructed key length does not match truth")
      }
      fmt.Printf("Found the key length: %d\n", keyLength)
      fmt.Printf("  Real Mac: %x\n", realMac)
      fmt.Printf("Forged Mac: %x\n", forgedMac)
      fmt.Printf("Check this against actual message:%x\n", append(secretKey, message...))
      break
    }
  }
}
