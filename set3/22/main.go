package main

import (
	"errors"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"math/rand"
	"time"
)

func MTRoutine() (uint64, uint64) {
  tWait := rand.Intn(1000) + 40
  time.Sleep(time.Duration(tWait) * time.Second)

	seed := uint64(time.Now().Unix())
	mt := cryptopals.NewMT19937(32, seed)

  time.Sleep(time.Duration(rand.Intn(1000) + 40) * time.Second)

  return mt.Rand(), seed
}

func CrackSeed(firstRand uint64, lookback int) (uint64, error) {
  now := uint64(time.Now().Unix())
  for i := 0; i < lookback; i++ {
    seed := now - uint64(lookback) + uint64(i)
	  mt := cryptopals.NewMT19937(32, seed)
    if mt.Rand() == firstRand {
      return seed, nil
    }
  }

  return 0, errors.New("no seed found")
}

func main() {
  fmt.Printf("starting at %v", time.Now())
  r, seed := MTRoutine()
  fmt.Printf("first random number: %d\n", r)

  crackedSeed, err := CrackSeed(r, 10000)
  if err != nil {
    panic(err)
  }

  fmt.Printf("true seed: %d\ncracked:   %d\n", seed, crackedSeed)

  if crackedSeed != seed {
    panic("problem cracking seed")
  }

  fmt.Printf("Challenge 22 Success, seeds match!")
  fmt.Printf("ending at %v\n", time.Now())
}
