package main

import (
  "crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
  "strings"
  "jfeintzeig/cryptopals/lib"
)

var CharFreq map[rune]float64

func init() {

	// ascii table character frequencies, including
	// punctuation, spaces, etc., not just a-z
	// https://opendata.stackexchange.com/a/19792
	CharFreq = map[rune]float64{
		32:  0.167564443682168,
		101: 0.08610229517681191,
		116: 0.0632964962389326,
		97:  0.0612553996079051,
		110: 0.05503703643138501,
		105: 0.05480626188138746,
		111: 0.0541904405334676,
		115: 0.0518864979648296,
		114: 0.051525029341199825,
		108: 0.03218192615049607,
		100: 0.03188948073064199,
		104: 0.02619237267611581,
		99:  0.02500268898936656,
		10:  0.019578060965172565,
		117: 0.019247776378510318,
		109: 0.018140172626462205,
		112: 0.017362092874808832,
		102: 0.015750347191785568,
		103: 0.012804659959943725,
		46:  0.011055184780313847,
		121: 0.010893686962847832,
		98:  0.01034644514338097,
		119: 0.009565830104169261,
		44:  0.008634492219614468,
		118: 0.007819143740853554,
		48:  0.005918945715880591,
		107: 0.004945712204424292,
		49:  0.004937789430804492,
		83:  0.0030896915651553373,
		84:  0.0030701064687671904,
		67:  0.002987392712176473,
		50:  0.002756237869045172,
		56:  0.002552781042488694,
		53:  0.0025269211093936652,
		65:  0.0024774830020061096,
		57:  0.002442242504945237,
		120: 0.0023064144740073764,
		51:  0.0021865587546870337,
		73:  0.0020910417959267183,
		45:  0.002076717421222119,
		54:  0.0019199098857390264,
		52:  0.0018385271551164353,
		55:  0.0018243295447897528,
		77:  0.0018134911904778657,
		66:  0.0017387002075069484,
		34:  0.0015754276887500987,
		39:  0.0015078622753204398,
		80:  0.00138908405321239,
		69:  0.0012938206232079082,
		78:  0.0012758834637326799,
		70:  0.001220297284016159,
		82:  0.0011037374385216535,
		68:  0.0010927723198318497,
		85:  0.0010426370083657518,
		113: 0.00100853739070613,
		76:  0.0010044809306127922,
		71:  0.0009310209736100016,
		74:  0.0008814561018445294,
		72:  0.0008752446473266058,
		79:  0.0008210528757671701,
		87:  0.0008048270353938186,
		106: 0.000617596049210692,
		122: 0.0005762708620098124,
		47:  0.000519607185080999,
		60:  0.00044107665296153596,
		62:  0.0004404428310719519,
		75:  0.0003808001912620934,
		41:  0.0003314254660634964,
		40:  0.0003307916441739124,
		86:  0.0002556203680692448,
		89:  0.00025194420110965734,
		58:  0.00012036277683200988,
		81:  0.00010001709417636208,
		90:  8.619977698342993e-05,
		88:  6.572732994986532e-05,
		59:  7.41571610813331e-06,
		63:  4.626899793963519e-06,
		127: 3.1057272589618137e-06,
		94:  2.2183766135441526e-06,
		38:  2.0282300466689395e-06,
		43:  1.5211725350017046e-06,
		91:  6.97204078542448e-07,
		93:  6.338218895840436e-07,
		36:  5.070575116672349e-07,
		33:  5.070575116672349e-07,
		42:  4.436753227088305e-07,
		61:  2.5352875583361743e-07,
		126: 1.9014656687521307e-07,
		95:  1.2676437791680872e-07,
		9:   1.2676437791680872e-07,
		123: 6.338218895840436e-08,
		64:  6.338218895840436e-08,
		5:   6.338218895840436e-08,
		27:  6.338218895840436e-08,
		30:  6.338218895840436e-08,
	}
}

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

func SingleByteXOR(byteArray []byte, key byte) []byte {
  output := make([]byte, len(byteArray))
	for i := range byteArray {
		output[i] = byteArray[i] ^ key
	}
	return output
}

// K-L divergence
func ScoreString(input string) float64 {
	hist := make(map[rune]float64)
	for _, r := range input {
		if _, ok := hist[r]; ok {
			hist[r] += 1.0 / float64(len(input))
		} else {
			hist[r] = 1.0 / float64(len(input))
		}
	}

	var score float64
	for _, r := range input {
		if _, ok := CharFreq[r]; ok {
			score += hist[r] * math.Log(hist[r]/CharFreq[r])
		} else {
			score += hist[r] * math.Log(hist[r]/1e-10)
		}
	}

	return score
}

func DecryptSingleByteXOR(inputBytes []byte) (string, uint8, float64) {
	var minScore float64 = 1000000
	var minKey uint8
	var decrypted string
	for key := uint8(0); key != 255; key++ {
		output := SingleByteXOR(inputBytes, key)
		outputString := string(output)
		thisScore := ScoreString(outputString)
		if thisScore < minScore {
			minScore = thisScore
			minKey = key
			decrypted = outputString
		}
	}
  return decrypted, minKey, minScore
}

func Challenge3() {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	inputBytes, err := hex.DecodeString(input)
	if err != nil {
		panic("error decoding hex string")
	}

  decrypted, minKey, minScore := DecryptSingleByteXOR(inputBytes)
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
  lines := strings.Split(strings.Trim(string(file),"\n"), "\n")

  var key uint8
  var minScore float64 = 10000
  var decrypted string
  var input string
  for _, line := range lines {
    inputBytes, err := hex.DecodeString(line)
    if err != nil {
      panic("error decoding hex string")
    }
    thisDecrypted, thisKey, thisScore := DecryptSingleByteXOR(inputBytes)
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
    output[i] = byte(b) ^ byte(key[i % keyLen])
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
      chunk = byteArray[i*keysize:(i+1)*keysize]
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
    variance += math.Pow(v - avgDist, 2)
  }

  fmt.Printf("\nKeysize: %d MinDist: %3.3f vs others have %3.3f +/- %3.3f\n", actualKeySize, minDist, avgDist, math.Sqrt(variance))

  // here i use chunk to signify the transposed result, but inside this
  // function i use chunk to signify a stride of the original. sorry for
  // the confused naming
  transposedChunks := TransposeByteArrayByKeySize(input, actualKeySize)
  decryptedChunks := make([][]byte, actualKeySize)
  for i, tc := range transposedChunks {
    thisDecrypted, _, _ := DecryptSingleByteXOR(tc)
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
  block, err := aes.NewCipher(key)
  if err != nil {
    fmt.Printf("problem creating block\n")
  }
  out := make([]byte, block.BlockSize())

  for i := 0; i < len(input); i += 16 {
    input := input[i:i+16]
    block.Decrypt(out, input)
    fmt.Printf("%s", out)
  }
  fmt.Printf("********** END Challenge 7 ***********\n")
}

func Challenge8() {
  fmt.Printf("********* Challenge 8 ***********\n")
  file, err := os.ReadFile("8.txt")
  if err != nil {
    panic("problem opening file")
  }

  lines := strings.Split(strings.Trim(string(file),"\n"), "\n")
  for i, line := range lines {
    input, err := hex.DecodeString(line)
    if err != nil {
      panic("can't decode line to hex")
    }

    nSame := 0
    segment := make(map[string]int)
    for j := 0; j < len(input); j += 16 {
      inputString := hex.EncodeToString(input[j:j+16])
      if _, ok := segment[inputString]; ok {
        segment[inputString] += 1
      } else {
        segment[inputString] = 1
      }

      for _, v := range segment {
        if v > nSame {
          nSame = v
        }
      }
    }
    if nSame > 1 {
      fmt.Printf("Line %d has a segment repeated %d times out of %d total segments:\n", i, nSame, len(input) / 16)
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
