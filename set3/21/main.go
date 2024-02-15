package main

import (
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
)

func main() {
	fmt.Printf("Challenge 20\n")

	seed := uint64(123)
	mt := cryptopals.NewMT19937(32, seed)
	fmt.Printf("Seed %d, the first random numbers: %d %d %d \n", seed, mt.Rand(), mt.Rand(), mt.Rand())
}
