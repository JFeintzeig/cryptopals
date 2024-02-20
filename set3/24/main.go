package main

import (
	"errors"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"math/rand"
	"reflect"
	"time"
)

var trueseed uint16

func init() {
	seed := cryptopals.GenerateRandomBytes(2)
	trueseed = (uint16(seed[0]) << 8) | uint16(seed[1])
}

func MT19937StreamEncrypt(input []byte, seed uint16) []byte {
	// prepend random number of random characters
	prepend := cryptopals.GenerateRandomBytes(rand.Intn(1000))
	payload := append(prepend, input...)

	// xor with as many random numbers as needed
	prng := cryptopals.NewMT19937(32, uint64(trueseed))
	keystream := make([]byte, len(payload))
	for i := 0; i < len(keystream); i++ {
		keystream[i] = byte(prng.Rand() & 0xFF)
	}

	return cryptopals.FixedXOR(payload, keystream)
}

func BruteForceMT19937Stream(ciphertext []byte) (uint16, error) {
	for i := 0; i < (1 << 16); i++ {
		prng := cryptopals.NewMT19937(32, uint64(i))
		decrypted := make([]byte, len(ciphertext))
		for j := 0; j < len(ciphertext); j++ {
			decrypted[j] = ciphertext[j] ^ byte(prng.Rand()&0xFF)
		}
		if reflect.DeepEqual(decrypted[len(ciphertext)-14:], []byte("AAAAAAAAAAAAAA")) {
			return uint16(i), nil
		}
	}
	return 0, errors.New("failed to find seed")
}

func GeneratePasswordResetToken() uint64 {
	prng := cryptopals.NewMT19937(32, uint64(time.Now().Unix()))
	return prng.Rand()
}

func ValidateToken(token uint64) bool {
	now := uint64(time.Now().Unix())
	lookback := uint64(1000)
	for i := now - lookback; i < now; i++ {
		prng := cryptopals.NewMT19937(32, uint64(time.Now().Unix()))
		r := prng.Rand()
		if r == token {
			return true
		}
	}
	return false
}

func main() {
	fmt.Printf("Challenge 24\n")

	cipher := MT19937StreamEncrypt([]byte("AAAAAAAAAAAAAA"), trueseed)

	seed, err := BruteForceMT19937Stream(cipher)

	fmt.Printf("Part 1: True Seed: %d Guessed Seed: %d\n", trueseed, seed)
	if err != nil {
		panic(err)
	} else if seed != trueseed {
		panic("found wrong seed")
	}

	fmt.Printf("Part 2: ")
	token := GeneratePasswordResetToken()
	isFromPRNG := ValidateToken(token)
	fmt.Printf("%d, is from PRNG? %t\n", token, isFromPRNG)
	if !isFromPRNG {
		panic("couldn't validate token is from PRNG")
	}

	fmt.Printf("Challenge 24 Solved!\n")
}
