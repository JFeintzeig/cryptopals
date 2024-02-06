package main

import (
	"encoding/base64"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"math/rand"
)

var Ch17AESKey []byte
var Ch17IV []byte
var Ch17Corpus []string

func init() {
  Ch17AESKey = cryptopals.RandomAESKey()
  Ch17IV = cryptopals.RandomAESKey()
  Ch17Corpus = []string{
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
  }
}

func Ch17Encrypt(stringNumber int) ([]byte, []byte) {
  var chosenString string
  if stringNumber < 0 {
    chosenString = Ch17Corpus[rand.Intn(len(Ch17Corpus))]
  } else {
    chosenString = Ch17Corpus[stringNumber]
  }

  decodedString, err := base64.StdEncoding.DecodeString(chosenString)
  if err != nil {
    panic("problem decoding base64")
  }

  iv := cryptopals.GenerateRandomBytes(16)
  return cryptopals.CBCEncrypt([]byte(decodedString), Ch17AESKey, iv), iv
}

func Ch17Decrypt(ciphertext []byte, iv []byte) (bool, error) {
  _, err := cryptopals.CBCDecrypt(ciphertext, Ch17AESKey, iv)
  if err != nil {
    return false, err
  } else {
    return true, err
  }
}

func Challenge17DecodeBlock(ciphertext []byte, iv []byte, blockSize int) []byte {
  decodedBytes := make([]byte, 0)
  for j := 1; j <= 16; j++ {
    foundByte := false
    // this is the original byte in the ciphertext that is 1 block
    // ahead of the last byte
    blockBehindByte := ciphertext[len(ciphertext) - j - blockSize]
    for i := 0; i < 256; i++ {
      if i == int(blockBehindByte) && (len(decodedBytes) % blockSize) == 0 {
        continue
      }
      // replace that byte with random byte
      ciphertext[len(ciphertext)-j-blockSize] = byte(i)
      validPadding, _ := Ch17Decrypt(ciphertext, iv)
      if validPadding {
        // we find i that leads to to 0x1 in plaintext.
        // i ^ (i ^ block_cipher_decryption = 0x1), so i ^ 0x1 gives the output of the block decrypt function,
        // which then needs to be xor'd with the original block-behind byte to get the truth
        decoded := byte(i) ^ byte(j) ^ blockBehindByte
        decodedBytes = append([]byte{decoded}, decodedBytes...)

        // for next phase of loop, i want to try 0x2 padding.
        // so need last byte that corresponds to 0x2,
        // then solve for next-to-last byte. last should be:
        // decrypted ^ blockBehindByte ^ 0x02
        // not increase the dummy padding? no maybe not...
        for k := j; k > 0; k-- {
          ciphertext[len(ciphertext)-k-blockSize] ^= (byte(j) ^ byte(j+1))
        }
        foundByte = true
        break
      }
    }
    if !foundByte {
      fmt.Printf("no match found for byte %d\n", j)
    }
  }

  return decodedBytes
}

func Challenge17() {
  fmt.Printf("************** Challenge 17 ****************\n\n")
  Ch17Truth := make(map[string]bool, len(Ch17Corpus))
  for _, s := range Ch17Corpus {
    decoded, err := base64.StdEncoding.DecodeString(s)
    if err != nil {
      panic("problem decoding base64 truth")
    }
    Ch17Truth[string(decoded)] = true
  }

  for i := range Ch17Corpus {
    blockSize := 16
    cipher, iv := Ch17Encrypt(i)

    nBlocks := len(cipher) / blockSize

    decodedBytes := make([]byte, 0)
    IvCipher := append(iv, cipher...)
    for i := 1; i <= nBlocks; i++ {
      // first block is 16 in, so we grab 0:16 and 16:32
      start := (i-1)*blockSize
      end := (i+1)*blockSize
      subCipher := IvCipher[start:end]
      decodedBytes = append(decodedBytes, Challenge17DecodeBlock(subCipher, iv, blockSize)...)
    }

    unpadded, err := cryptopals.PKCS7Unpad(decodedBytes, blockSize)
    if err != nil {
      panic(err)
    }
    fmt.Printf("Decoded: %s\n", string(unpadded))

    if _, ok := Ch17Truth[string(unpadded)]; !ok {
      panic("Challenge 17: Decoded string differs from truth")
    }
  }

  fmt.Printf("\nChallenge 17 completed successfully\n")

  fmt.Printf("\n************** END Challenge 17 ****************\n")
}

func main() {
  Challenge17()
}
