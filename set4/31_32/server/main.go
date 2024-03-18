package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"net/http"
	"reflect"
	"time"
  "strconv"
)

type HmacSha1 struct {
  key []byte
  blockSize int
  outputSize int
  blockSizedKey []byte
  oKeyPad []byte
  iKeyPad []byte
}

func (h *HmacSha1) MakeHmac(message []byte) []byte {
  first := h.hash(append(h.iKeyPad, message...))
  return h.hash(append(h.oKeyPad, first...))
}

func (h *HmacSha1) hash(message []byte) []byte {
  sha := sha1.New()
  sha.Write(message)
  return sha.Sum(nil)
}

func (h *HmacSha1) computeBlockSizedKey() []byte {
  if len(h.key) > h.blockSize {
    return h.hash(h.key)
  } else if len(h.key) < h.blockSize {
    return append(h.key, cryptopals.MakeSingleByteSlice(0x00, h.blockSize - len(h.key))...)
  } else {
    return h.key
  }
}

func NewHmacSha1(key []byte) *HmacSha1 {
  hmac := HmacSha1{key: key, blockSize: 64, outputSize: 20}
  hmac.blockSizedKey = hmac.computeBlockSizedKey()
  oPad := cryptopals.MakeSingleByteSlice(0x5C, hmac.blockSize)
  iPad := cryptopals.MakeSingleByteSlice(0x36, hmac.blockSize)
  hmac.oKeyPad = cryptopals.FixedXOR(hmac.blockSizedKey, oPad)
  hmac.iKeyPad = cryptopals.FixedXOR(hmac.blockSizedKey, iPad)

  return &hmac
}

func InsecureCompare(b1 []byte, b2[]byte, sleep int) bool {
  for i := range b1 {
    if b1[i] != b2[i] {
      return false
    }
    time.Sleep(time.Duration(sleep) * time.Microsecond)
  }
  return true
}

func endpoint(w http.ResponseWriter, r *http.Request, hmac *HmacSha1) {
  params := r.URL.Query()
  file := params.Get("file")
  signature, _ := hex.DecodeString(params.Get("signature"))
  sleep, err := strconv.Atoi(params.Get("sleep"))
  if err != nil {
    panic(err)
  }

  trueSignature := hmac.MakeHmac([]byte(file))
  matches := InsecureCompare([]byte(signature), []byte(trueSignature), sleep)

  if !matches {
    w.WriteHeader(http.StatusInternalServerError)
  }
  fmt.Fprintf(w, "matches: %t", matches)
}

func main() {
  key := []byte("key")
  hmac := NewHmacSha1(key)
  testHmac := hmac.MakeHmac([]byte("The quick brown fox jumps over the lazy dog"))
  truth, _ := hex.DecodeString("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
  if !reflect.DeepEqual(testHmac, truth) {
    panic("HMAC for quick brown fox fails")
  }
  fmt.Printf("hmac: %x\n", hmac.MakeHmac([]byte("The quick brown fox jumps over the lazy dog")))

  endpointHandler := func(w http.ResponseWriter, r *http.Request) {
    endpoint(w, r, hmac)
  }

  http.HandleFunc("/test", endpointHandler)

  fmt.Println("Server is listening on port 8080...")
  http.ListenAndServe(":8080", nil)
}
