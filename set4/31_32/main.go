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

func CrackHard(baseURL string, endpoint string, testFile string, sleepms int, trueSignature []byte) ([]byte, error) {
  signature := cryptopals.MakeSingleByteSlice(0x00, 20)
  nsamples := 11

  for i := range signature {
    durations := make(map[int]float64)
    for j := 0; j < 256; j++ {
      signature[i] = byte(j)
      rc, d1, _ := MakeRequest(baseURL, endpoint, testFile, signature, sleepms)
      if rc == 200 {
        fmt.Printf("Got a 200!\n")
        fmt.Printf("Signature for %s:\n%x\n", testFile, signature)
        return signature, nil
      } else {
        maxD := d1.Seconds()
        meanD := d1.Seconds()
        for i := 1; i < nsamples; i++ {
          _, dur, _ := MakeRequest(baseURL, endpoint, testFile, signature, sleepms)
          meanD += dur.Seconds()
          if dur.Seconds() > maxD {
            maxD = dur.Seconds()
          }
        }

        durations[j] = (meanD - maxD) / float64(nsamples-1)
      }
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

    fmt.Printf("Min Key %d with duration %3.2f vs. mean %3.2f +/- %3.2f\n", maxKey, maxDuration*1000, meanDuration*1000, stdDev*1000)

    signature[i] = byte(maxKey)
    if signature[i] != trueSignature[i] {
      fmt.Printf("problem:\n")
      fmt.Printf("durations: %v\n", durations)
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
  rc, dt, _ := MakeRequest(baseURL, endpoint, testFile, testSignature, 50)
  fmt.Printf("RC: %d %v\n", rc, dt)

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
