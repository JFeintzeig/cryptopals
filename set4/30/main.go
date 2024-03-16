package main

import (
	"fmt"
	"math/rand"
	"reflect"

	"golang.org/x/crypto/md4"
	cryptopals "jfeintzeig/cryptopals/lib"
)

var secretKey []byte
var secretKeyLength int

func init() {
  secretKeyLength = rand.Intn(20)
  secretKey = cryptopals.GenerateRandomBytes(secretKeyLength)
}

func authenticate(message []byte) []byte {
  input := append(secretKey, message...)
  hasher := md4.New()
  hasher.Write(input)
  output := hasher.Sum(nil)
  return output
}

func CalcPadding(message []byte, keyLengthBytes int) []byte {
  ml := uint64((len(message) + keyLengthBytes)*8)
  nZeros := 512 - (ml % 512) - 64 - 8 // subtract 8 b/c of the 0x80 byte
  // tricky: if 512 - (ml % 512) is less than 64+8, then we underflow
  // and get a _huge_ nZeros. i think this means we need to add another
  // whole block of 512 zeros to it to wrap around.
  if nZeros > 512 {
    nZeros += 512
  }
  if nZeros > 512 {
    panic("problem w nzeros")
  }
  padding := make([]byte, 0)
  padding = append(padding, 0x80) // a 1 bit followed by 7 zeros
  for i := uint64(0); i < nZeros / 8; i++ {
    padding = append(padding, 0x00)
  }

  for i := 0; i < 8; i++ {
    shift := i*8 // NB: reverse order from SHA1
    padding = append(padding, uint8((ml >> shift) & 0xFF))
  }

  return padding
}

func MacToRegisters(input []byte) []uint32 {
  output := make([]uint32, 4)

  for i, val := range input {
    // NB: reverse order from MD4
    output[i/4] |= uint32(val) << int(8*(i%4))
  }

  return output
}

func ForgeMessage(original []byte, originalMac []byte, keyLengthBytes int, payload []byte) ([]byte, []byte) {
  padding := CalcPadding(original, keyLengthBytes)

  newMessage := append(original, padding...)
  newMessage = append(newMessage, payload...)

  mymd4 := New()
  mymd4.SetRegisters([4]uint32(MacToRegisters(originalMac)))
  mymd4.Write(payload)
  extraLen := len(newMessage) - len(payload) + keyLengthBytes

  output := mymd4.SumWithExtraLength(nil, extraLen)
  return output[:], newMessage
}

func main() {
  fmt.Printf("Challenge 30\n")

  original := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
  originalMac := authenticate(original)

  payload := []byte(";admin=true")

  found := false
  for keyLength := 0; keyLength < 100; keyLength++ {
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
      found = true
      break
    }
  }

  if !found {
    fmt.Printf("failed to solve it\n")
  }
}
