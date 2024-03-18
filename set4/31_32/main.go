package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	cryptopals "jfeintzeig/cryptopals/lib"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"time"
)

func MakeRequest(baseURL string, endpoint string, file string, signature []byte, sleepms int) (int, time.Duration, error) {
  queryParams := url.Values{}
  queryParams.Set("file", file)
  queryParams.Set("signature", hex.EncodeToString(signature))
  queryParams.Set("sleepms", fmt.Sprintf("%d",sleepms))
  fullURL := fmt.Sprintf("%s%s?%s", baseURL, endpoint, queryParams.Encode())

  // Make the GET request
  start := time.Now()
  resp, err := http.Get(fullURL)
  if err != nil {
    panic(err)
  }
  defer resp.Body.Close()
  duration := time.Now().Sub(start)
  if err != nil {
      fmt.Println("This Error:", err, resp)
      return 0, time.Duration(0), errors.New("problem")
  }

  return resp.StatusCode, duration, nil
}

func CrackEasy(baseURL string, endpoint string, testFile string) ([]byte, error) {
  sleepms := 50
  signature := cryptopals.MakeSingleByteSlice(0x00, 20)

  for i := range signature {
    found := false
    for j := 0; j < 256; j++ {
      signature[i] = byte(j)
      rc, d, _ := MakeRequest(baseURL, endpoint, testFile, signature, sleepms)

      if rc == 200 {
        fmt.Printf("Got a 200!\n")
        fmt.Printf("Signature for %s:\n%x\n", testFile, signature)
        return signature, nil
      } else {
        if d > time.Duration(sleepms*(i+1)) * time.Millisecond {
          // this byte matches!
          fmt.Printf("found byte %d: value %x duration %v\n", i, j, d)
          found = true
          break
        }
      }
    }
    // no match found
    if !found {
      fmt.Printf("no match found for byte %d :(\n", i)
      break
    }
  }

  return signature, errors.New("failed to find signature")
}

func TestByte(baseURL string, endpoint string, testFile string, signature []byte, sleepms int, nsamples int) float64 {
  vals := make([]float64, 0)
  for i := 0; i < nsamples; i++ {
    _, d, _ := MakeRequest(baseURL, endpoint, testFile, signature, sleepms)
    vals = append(vals, d.Seconds())
  }

  sort.Float64s(vals)
  avg := cryptopals.Average(vals[:nsamples-5])
  //fmt.Printf("%x: %v elapsed time, avg: %3.3f\n", signature[:5], ela, avg*1000)
  return avg
}

func CrackHard(baseURL string, endpoint string, testFile string, sleepms int, trueSignature []byte) ([]byte, error) {
  signature := cryptopals.MakeSingleByteSlice(0x00, 20)
  nsamples := 10

  for i := range signature {
    durations := make(map[int]float64)
    prev := -1
    iteration := 0
    for {
      for j := 0; j < 256; j++ {
        signature[i] = byte(j)
        rc, _, _ := MakeRequest(baseURL, endpoint, testFile, signature, sleepms)
        if rc == 200 {
          fmt.Printf("Got a 200!\n")
          fmt.Printf("Signature for %s:\n%x\n", testFile, signature)
          return signature, nil
        }

        durations[j] = TestByte(baseURL, endpoint, testFile, signature, sleepms, nsamples)
      }

      maxDuration := 0.0
      meanDuration := 0.0
      meanSquared := 0.0
      maxKey := 256
      for k, v := range durations {
        meanDuration += v
        meanSquared += v*v
        if v > maxDuration {
          maxDuration = v
          maxKey = k
        }
      }

      meanDuration = (meanDuration - maxDuration) / float64(len(durations) - 1)
      meanSquared = (meanSquared - maxDuration*maxDuration) / float64(len(durations) - 1)
      stdDev := math.Sqrt(meanSquared - meanDuration*meanDuration)

      fmt.Printf("Min Key %d iteration %d with duration %3.2f vs. mean %3.2f +/- %3.2f\n", maxKey, iteration, maxDuration*1000, meanDuration*1000, stdDev*1000)

      if prev == maxKey {
        fmt.Printf("Next byte!\n")
        break
      }
      prev = maxKey
      iteration += 1
    }

    signature[i] = byte(prev)
    if signature[i] != trueSignature[i] {
      fmt.Printf("problem:\n")
      fmt.Printf("durations: %v", durations)
    }
  }

  return signature, errors.New("failed to find signature")
}

func main() {
  baseURL := "http://localhost:8080"
  endpoint := "/test"

  testFile := "The quick brown fox jumps over the lazy dog"
  testSignature, _ := hex.DecodeString("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")

  fmt.Printf("True Signature: %v\n", testSignature)
  fmt.Printf("True Signature: %x\n", testSignature)
  rc, dt, _ := MakeRequest(baseURL, endpoint, testFile, testSignature, 50)
  fmt.Printf("RC: %d %v\n", rc, dt)

  crackEasy := false
  if crackEasy {
    fmt.Printf("\n\nStarting CrackEasy(), 50ms sleep\n\n")
    start := time.Now()
    signature, err := CrackEasy(baseURL, endpoint, testFile)
    d := time.Now().Sub(start)
    fmt.Printf("%v to run CrackEasy()\n", d)

    if err != nil {
      fmt.Print(err)
    }

    if !reflect.DeepEqual(signature, testSignature) {
      fmt.Printf("no match found, cracked signature: %x\n   real signature: %x\n", signature, testSignature)
    } else {
      fmt.Printf("SUCCESS!\ncracked signature: %x\n   real signature: %x\n", signature, testSignature)
    }
  }

  sleepms := 5
  fmt.Printf("\n\nStarting CrackHard(), %d ms sleep\n\n", sleepms)
  startH := time.Now()
  signatureH, err := CrackHard(baseURL, endpoint, testFile, sleepms, testSignature)
  dH := time.Now().Sub(startH)
  fmt.Printf("%v to run CrackHard()\n", dH)

  if err != nil {
    fmt.Print(err)
  }

  if !reflect.DeepEqual(signatureH, testSignature) {
    fmt.Printf("no match found, cracked signature: %x\n   real signature: %x\n", signatureH, testSignature)
  } else {
    fmt.Printf("SUCCESS!\ncracked signature: %x\n   real signature: %x\n", signatureH, testSignature)
  }

}
