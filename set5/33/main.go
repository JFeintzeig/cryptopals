package main

import (
  "fmt"
  "math/rand"
)

type DiffieHellman struct {
  P int
  G int
  a int
  b int
  A int
  B int
}

func (dh *DiffieHellman) GeneratePrivate() {

}

func (dh *DiffieHellman) GeneratePublic(private int) {

}

func NewDiffieHellman(p int, g int) *DiffieHellman {
  return &DiffieHellman{P: p, G: g}
}

func main() {
  dh := NewDiffieHellman(37, 5)
  fmt.Printf("hello\n")
}
