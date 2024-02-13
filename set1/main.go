package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"jfeintzeig/cryptopals/lib"
	"math"
	"os"
	"strings"
)

func HexToBase64(hexString string) string {
	byteArray, err := hex.DecodeString(hexString)
	if err != nil {
		panic("problem decoding hex")
	}
	return base64.StdEncoding.EncodeToString(byteArray)
}

func Challenge1() {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b64 := HexToBase64(input)

	fmt.Printf("Challenge 1: %s\n", b64)
	if b64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		panic("problem with challenge 1")
	}
}

func Challenge2() {
	s1 := "1c0111001f010100061a024b53535009181c"
	s2 := "686974207468652062756c6c277320657965"

	b1, err := hex.DecodeString(s1)
	if err != nil {
		panic("problem decoding first string")
	}
	b2, err := hex.DecodeString(s2)
	if err != nil {
		panic("problem decoding second string")
	}

	xor := cryptopals.FixedXOR(b1, b2)
	xorString := hex.EncodeToString(xor)
	fmt.Printf("Challenge 2: %s\n", xorString)
	if xorString != "746865206b696420646f6e277420706c6179" {
		panic("problem with challenge 2")
	}

}


func Challenge3() {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		panic("error decoding hex string")
	}

	decrypted, minKey, minScore := cryptopals.DecryptSingleByteXOR(inputBytes)
	fmt.Printf("Challenge 3: key: %02X score: %3.3f decrypted message: %s\n", minKey, minScore, decrypted)
	if decrypted != "Cooking MC's like a pound of bacon" {
		panic("problem with challenge 3")
	}
}

func Challenge4() {
	file, err := os.ReadFile("4.txt")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(strings.Trim(string(file), "\n"), "\n")

	var key uint8
	var minScore float64 = 10000
	var decrypted string
	var input string
	for _, line := range lines {
		inputBytes, err := hex.DecodeString(line)
		if err != nil {
			panic("error decoding hex string")
		}
		thisDecrypted, thisKey, thisScore := cryptopals.DecryptSingleByteXOR(inputBytes)
		if thisScore < minScore {
			key = thisKey
			decrypted = thisDecrypted
			minScore = thisScore
			input = line
		}
	}
	fmt.Printf("Challenge 4: input:%s decrypted:%s key:%02X score:%3.3f\n", input, decrypted, key, minScore)
	if input != "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f" && key != 0x34 {
		panic("problem w challenge 4")
	}
}

func Challenge5() {
	data := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"

	keyLen := len(key)

	output := make([]byte, len(data))
	for i, b := range data {
		output[i] = byte(b) ^ byte(key[i%keyLen])
	}
	fmt.Printf("Challenge 5: %x\n", output)
	if hex.EncodeToString(output) != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		panic("problem w challenge 5")
	}
}

func HammingDistance(b1 []byte, b2 []byte) int {
	xor := make([]byte, len(b1))
	for i := range b1 {
		xor[i] = b1[i] ^ b2[i]
	}

	var output int
	for _, b := range xor {
		for j := 0; j < 8; j++ {
			output += int((b >> j) & 0x01)
		}

	}
	return output
}

// this seems like overkill but i needed to do this to get the right
// keysize. instead of calculating the difference for the first two
// keysize-length chunks, i take the cross product of all chunks.
// this makes the average for all the wrong ones to be tightly
// distributed around ~3.21 +/0 ~0.005, vs. the correct one is ~2.7
func CalcDistanceForKeySize(input []byte, keysize int) float64 {
	chunks := make([][]byte, 0)
	for i := 0; i < len(input)/keysize; i++ {
		chunks = append(chunks, input[keysize*i:keysize*(i+1)])
	}

	var numerator float64
	var denominator float64
	for i, b1 := range chunks {
		for j, b2 := range chunks {
			if i != j {
				numerator += float64(HammingDistance(b1, b2))
				denominator += 1
			}
		}
	}
	return numerator / (denominator * float64(keysize))
}

func TransposeByteArrayByKeySize(byteArray []byte, keysize int) [][]byte {
	// Break `byteArray` into `keysize` pieces, each of length `byteArray/keysize`
	// Except some pieces could be 1 entry longer, if byteArray is not equally
	// divisible by keysize

	output := make([][]byte, keysize)
	for i := 0; i < keysize; i++ {
		output[i] = make([]byte, 0)
	}

	iterate := true
	// stride through `keysize`-length chunks, i is the chunk number
	// j is the byte number within each chunk, which represents which
	// output piece it should be put into
	var i int
	for iterate {
		var chunk []byte
		// if our next stride of length `keysize` goes beyond the end of the array
		// then just grab whatever's remaining, and this is last iteration of loop
		if (i+1)*keysize > len(byteArray) {
			iterate = false
			chunk = byteArray[i*keysize:]
		} else {
			chunk = byteArray[i*keysize : (i+1)*keysize]
		}
		for j, b := range chunk {
			output[j] = append(output[j], b)
		}
		i += 1
	}
	return output
}

func Challenge6() {
	fmt.Printf("Challenge 6:\n")
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	if HammingDistance([]byte(s1), []byte(s2)) != 37 {
		panic("hamming distance wokka wokka test fails")
	}

	file, err := os.ReadFile("6.txt")
	if err != nil {
		panic("problem opening file")
	}

	input, err := base64.StdEncoding.DecodeString(string(file))
	if err != nil {
		panic("problem decoding b64")
	}

	minDist := 10.0
	distSlice := make([]float64, 0)
	var actualKeySize int
	var idxForKey int
	for keysize := 2; keysize <= 40; keysize++ {
		dist := CalcDistanceForKeySize(input, keysize)
		if dist < minDist {
			minDist = dist
			actualKeySize = keysize
			idxForKey = keysize - 2
		}
		distSlice = append(distSlice, dist)
	}

	// remove minimum
	distSlice = append(distSlice[:idxForKey], distSlice[idxForKey+1:]...)

	var distSum float64
	for _, v := range distSlice {
		distSum += v
	}
	avgDist := distSum / float64(len(distSlice))

	variance := 0.0
	for _, v := range distSlice {
		variance += math.Pow(v-avgDist, 2)
	}

	fmt.Printf("\nKeysize: %d MinDist: %3.3f vs others have %3.3f +/- %3.3f\n", actualKeySize, minDist, avgDist, math.Sqrt(variance))

	// here i use chunk to signify the transposed result, but inside this
	// function i use chunk to signify a stride of the original. sorry for
	// the confused naming
	transposedChunks := TransposeByteArrayByKeySize(input, actualKeySize)
	decryptedChunks := make([][]byte, actualKeySize)
	for i, tc := range transposedChunks {
		thisDecrypted, _, _ := cryptopals.DecryptSingleByteXOR(tc)
		decryptedChunks[i] = []byte(thisDecrypted)
	}

	output := make([]byte, 0)
	// if some chunks have 1 extra entry, the first chunk will
	for i := 0; i < len(decryptedChunks[0]); i++ {
		for j := range decryptedChunks {
			// so make sure to escape once we've used up all extra entries
			if i >= len(decryptedChunks[j]) {
				break
			}
			output = append(output, decryptedChunks[j][i])
		}
	}

	fmt.Printf("\nSolution:\n%s\n", string(output))

	if len(input) != len(output) {
		panic("uh oh, challenge 6 input + output have different lengths")
	}
}

func Challenge7() {
	key := []byte("YELLOW SUBMARINE")
	file, err := os.ReadFile("7.txt")
	if err != nil {
		panic("problem opening file")
	}
	input, err := base64.StdEncoding.DecodeString(string(file))

	fmt.Printf("\n ********** Challenge 7 ************\n")
  decrypted := cryptopals.AESDecrypt(input, key)
  fmt.Printf("%s\n", decrypted)
	fmt.Printf("********** END Challenge 7 ***********\n")
}

func Challenge8() {
	fmt.Printf("********* Challenge 8 ***********\n")
	file, err := os.ReadFile("8.txt")
	if err != nil {
		panic("problem opening file")
	}

	lines := strings.Split(strings.Trim(string(file), "\n"), "\n")
	for i, line := range lines {
		input, err := hex.DecodeString(line)
		if err != nil {
			panic("can't decode line to hex")
		}

    nSame := cryptopals.CountMatches(input, 16)
		if nSame > 1 {
			fmt.Printf("Line %d has a segment repeated %d times out of %d total segments:\n", i, nSame, len(input)/16)
			for j := 0; j < len(input); j += 16 {
				fmt.Printf("%s\n", hex.EncodeToString(input[j:j+16]))
			}
		}
	}
	fmt.Printf("******** END Challenge 8 ***********\n")
}

func main() {
	Challenge1()
	Challenge2()
	Challenge3()
	Challenge4()
	Challenge5()
	Challenge6()
	Challenge7()
	Challenge8()
}
