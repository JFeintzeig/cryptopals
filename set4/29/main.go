package main

import (
  "fmt"

	sha1 "jfeintzeig/cryptopals/lib/sha1"
  cryptopals "jfeintzeig/cryptopals/lib"
)

var key []byte

func init() {
  //key = cryptopals.RandomAESKey()
  key = cryptopals.MakeSingleByteSlice(0x61, 16)
}

func authenticate(message []byte) []byte {
  input := append(key, message...)
  hasher := sha1.New()
  hasher.Write(input)
  output := hasher.Sum(nil)
  hasher.GetRegisters()
  return output
}

func CalcPadding(message []byte) []byte {
  ml := uint64(len(message)*8)
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

func ForgeMessage(original []byte, originalMac []byte, payload []byte) ([]byte, []byte) {
  padding := CalcPadding(original)

  newMessage := append(original, padding...)
  newMessage = append(newMessage, payload...)

  sha := sha1.New()
  sha.SetRegisters([5]uint32(MacToRegisters(originalMac)))
  sha.Write(payload)
  sha.GetRegisters()

  return sha.Sum(nil), newMessage
}

func main() {
  fmt.Printf("Challenge 29\n")
  //testInput := []byte("hello hello")
  //hasher := sha1.New()
  //hasher.Write(testInput)
  //output := hasher.Sum(nil)
  //fmt.Printf("Demonstrating we can split a SHA1 into registers:\n")
  //fmt.Printf("%x\n", output)
  //fmt.Printf("%x\n", MacToRegisters(output))

  original := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
  originalMac := authenticate(original)
  fmt.Printf("Original Length: %d\n", len(original))
  fmt.Printf("Origin Mac: %x\n", originalMac)

  payload := []byte(";admin=true")
  forgedMac, message := ForgeMessage(original, originalMac, payload)
  realMac := authenticate(message)
  fmt.Printf("  Real Mac: %x\n", realMac)
  fmt.Printf("Forged Mac: %x\n", forgedMac)
  //fmt.Printf("Forged Message: %x\n%s\n", message, message)
}
