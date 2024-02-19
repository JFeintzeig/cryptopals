package main

import (
	"fmt"
  "math/rand"

	cryptopals "jfeintzeig/cryptopals/lib"
)

func untemper(input uint64) uint64 {
  //u := 11
  s := 7
  t := 15
  l := 18
  b := uint64(0x9D2C5680)
  //d := uint64(0xFFFFFFFF)
  c := uint64(0xEFC60000)

	// (4) y := x ^ ((x >> mt.u) & mt.d)

  // (1) input = y1 ^ (y1 >> l)
  // since top 64-l bits of (y1 >> l) are 0, and we know input 
  // we can figure out top 64-l bits of y1
  y1 := uint64(0)
  mask1 := uint64((1 << l) - 1)
  y1 |= ((input & ^mask1) ^ 0x0)
  // then bottom l bits of y1 are xor'd against
  // bottom l bits of input to get orig.
  y1 |= (input & mask1) ^ (y1 >> l)

  // (2) y1 = y2 ^ ((y2 << t) & c)
  y2 := unwindshiftleft(y1, t, c)
	// (3) y2 = y3 ^ ((y3 << mt.s) & mt.b)
  //y3 := unwindshiftleft(y2, s, b)
  y3 := uint64(0)
  mask2 := uint64(1 << s) - 1
  //fmt.Printf("%064b\n", mask2)
  mask2 |= (^b)
  //fmt.Printf("%064b\n", mask2)
  y3 |= (y2 & mask2) ^ 0x0
  //fmt.Printf("%064b\n", y3)
  // TODO: problem seems to be consistently with treating
  // the bits of the RH operand that were not zero
  // for RHS below, the only bits of y3 that are correct
  // are the oes that are zero?
  fmt.Printf("%064b\n%064b\n",mask2,y3)
  y3 |= (y2 & ^mask2) ^ ((y3 << s) & b)
  fmt.Printf("%064b\n", y3)
  fmt.Printf("%d\n", s)

  return 0
}

func unwindshiftleft(input uint64, nBits int, mask uint64) uint64 {
  // (2) y1 = y2 ^ ((y2 << t) & c)
  // call this y1 = a ^ b
  // if we know certain bits of b are 0
  // then y1 ^ 0 should give those bits of a
  out := uint64(0)
  // mask is all the bits of (y2 << t) & c that are zero
  // we can XOR those bits w/zero to get bits of y2
  mask2 := uint64(1 << nBits) - 1
  mask2 |= (^mask)
  out |= (input & mask2) ^ 0x0

  // then select all the bits that were not zero
  // and xor with RHS "b" to reconstruct original
  out |= (input & ^mask2) ^ ((out << nBits) & mask)
  return out
}

func main() {
  fmt.Printf("challenge 23\n")

  mt := cryptopals.NewMT19937(32, uint64(rand.Intn(100000)))

  r := mt.Rand()
  untemper(r)

  //rands := make([]uint64, 624)
  //state := make([]uint64, 624)

  //for i := 0; i < 624; i++ {
  //  rands[i] = mt.Rand()
  //  state[i] = untemper(rands[i])
  //}
}
