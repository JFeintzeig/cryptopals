package main

import (
	"fmt"
  "math/rand"

	cryptopals "jfeintzeig/cryptopals/lib"
)

func untemper(input uint64) uint64 {
  u := 11
  s := 7
  t := 15
  l := 18
  b := uint64(0x9D2C5680)
  d := uint64(0xFFFFFFFF)
  c := uint64(0xEFC60000)

  // (1) input = y1 ^ (y1 >> l)
  // no mask, so just use all 1's
  y1 := unwindShiftRight(input, l, 0xFFFFFFFFFFFFFFFF)
  // (2) y1 = y2 ^ ((y2 << t) & c)
  y2 := unwindShiftLeft(y1, t, c)
	// (3) y2 = y3 ^ ((y3 << mt.s) & mt.b)
  y3 := unwindShiftLeft(y2, s, b)
	// (4) y := x ^ ((x >> mt.u) & mt.d)
  y4 := unwindShiftRight(y3, u, d)

  return y4
}

func unwindShiftLeftInner(input uint64, output uint64, nBits int, mask uint64, known uint64) uint64 {
  // solve input = output ^ ((output << nBits) & mask)
  // we recursively solve for bits of output that are
  // (i) unknown AND (ii) known in the shifted+masked
  // representations
  next := (^known & ((known << nBits) & mask))
  output |= next & (input ^ ((output << nBits) & mask))
  known |= next
  // if we now know all bits, return. otherwise, recursively
  // do this again until we know all bits
  if known == 0xFFFFFFFFFFFFFFFF {
    return output
  } else {
    return unwindShiftLeftInner(input, output, nBits, mask, known)
  }
}

func unwindShiftLeft(input uint64, nBits int, mask uint64) uint64 {
  // solve input = output ^ ((output << nBits) & mask)
  // (a) first identify all bits of RHOperand that are 0,
  //     use that to get corresponding bits of output
  output := uint64(0)
  mask2 := uint64(1 << nBits) - 1
  mask2 |= (^mask)
  output |= mask2 & (input ^ 0x0)
  known := mask2

  // (b) recursively solve for the bits of output
  //     where we now know bits of RHOperand
  return unwindShiftLeftInner(input, output, nBits, mask, known)
}

// same as unwindShiftLeft[Inner], but with opposite shift
func unwindShiftRightInner(input uint64, output uint64, nBits int, mask uint64, known uint64) uint64 {
  next := (^known & ((known >> nBits) & mask))
  output |= next & (input ^ ((output >> nBits) & mask))
  known |= next
  if known == 0xFFFFFFFFFFFFFFFF {
    return output
  } else {
    return unwindShiftRightInner(input, output, nBits, mask, known)
  }
}

func unwindShiftRight(input uint64, nBits int, mask uint64) uint64 {
  output := uint64(0)
  mask2 := ^(uint64(0xFFFFFFFFFFFFFFFF) >> nBits)
  mask2 |= (^mask)
  output |= mask2 & (input ^ 0x0)
  known := mask2

  return unwindShiftRightInner(input, output, nBits, mask, known)
}

func main() {
  fmt.Printf("Starting Challenge 23\n")

  mt := cryptopals.NewMT19937(32, uint64(rand.Intn(100000)))

  r := mt.Rand()
  untemper(r)

  rands := make([]uint64, 624)
  state := make([]uint64, 624)

  for i := 0; i < 624; i++ {
    rands[i] = mt.Rand()
    state[i] = untemper(rands[i])
  }

  cloned := cryptopals.NewMT19937(32, 123)
  cloned.SetState(624, state)

  for i := 0; i < 1000; i++ {
    o := mt.Rand()
    n := cloned.Rand()
    if o != n {
      panic("problem")
    }
    if i % 100 == 0 {
      fmt.Printf("output: i: %03d original: %d cloned: %d\n", i, o, n)
    }
  }
  fmt.Printf("Challenge 23 Successful!\n")
}
