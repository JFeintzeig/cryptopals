package cryptopals

import (
	"crypto/aes"
  "encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
  "math"
  "math/rand"
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

func FixedXOR(b1 []byte, b2 []byte) []byte {
	if len(b1) != len(b2) {
		panic("inputs are not same length")
	}
	xor := make([]byte, len(b1))
	for i := range b1 {
		xor[i] = b1[i] ^ b2[i]
	}

	return xor
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

func PKCS7(input []byte, blocksize int) []byte {
	padLength := (blocksize - (len(input) % blocksize))

	padding := make([]byte, padLength)
	for i := range padding {
		padding[i] = byte(padLength)
	}
	return append(input, padding...)
}

func PKCS7Unpad(input []byte, blocksize int) ([]byte, error) {
	paddingLength := input[len(input)-1]

  if paddingLength == 0x00 || int(paddingLength) > blocksize {
    return nil, errors.New("invalid pkcs7 padding: should always be between 1 and <BLOCKSIZE> bytes")
  }
	for i := range input {
		if (i >= (len(input) - int(paddingLength))) && input[i] != paddingLength {
			return nil, errors.New("invalid pkcs7 padding")
		}
	}
	return input[:len(input)-int(paddingLength)], nil
}

func AESDecrypt(input []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	blockSize := block.BlockSize()

	if err != nil {
		fmt.Printf("problem creating block\n")
	}

	decrypted := make([]byte, 0)
	out := make([]byte, block.BlockSize())

	for i := 0; i < len(input); i += blockSize {
		thisblock := input[i : i+blockSize]
		block.Decrypt(out, thisblock)
		decrypted = append(decrypted, out...)
	}
	unpadded, err := PKCS7Unpad(decrypted, blockSize)
	if err != nil {
		panic("problem unpadding result")
	}
	return unpadded
}

func AESEncrypt(input []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	blockSize := block.BlockSize()

	if err != nil {
		fmt.Printf("problem creating block\n")
	}

	paddedInput := PKCS7(input, blockSize)
	encrypted := make([]byte, 0)
	out := make([]byte, block.BlockSize())

	for i := 0; i < len(paddedInput); i += blockSize {
		thisblock := paddedInput[i : i+blockSize]
		block.Encrypt(out, thisblock)
		encrypted = append(encrypted, out...)
	}
	return encrypted
}

func CountMatches(input []byte, blockSize int) int {
	if blockSize == 0 {
		fmt.Printf("can't have blocksize of 0, returning\n")
		return 0
	}
	nSame := 0
	segment := make(map[string]int)
	for j := 0; j < len(input)-blockSize; j += blockSize {
		inputString := hex.EncodeToString(input[j : j+blockSize])
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
	return nSame
}

func MakeSingleByteSlice(value byte, length int) []byte {
	var slice []byte
	for i := 0; i < length; i++ {
		slice = append(slice, value)
	}
	return slice
}

func GenerateRandomBytes(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = uint8(rand.Intn(255))
	}
	return out
}

func RandomAESKey() []byte {
	return GenerateRandomBytes(16)
}

func CBCEncrypt(payload []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	blockSize := block.BlockSize()
	if err != nil {
		fmt.Printf("problem creating block\n")
	}

	paddedPayload := PKCS7(payload, blockSize)

	out := make([]byte, len(paddedPayload))

	for i := 0; i < len(paddedPayload); i += blockSize {
		var input []byte
		if i == 0 {
			input = FixedXOR(iv, paddedPayload[i:i+blockSize])
		} else {
			input = FixedXOR(out[i-blockSize:i], paddedPayload[i:i+blockSize])
		}
		block.Encrypt(out[i:i+blockSize], input)
	}
	return out
}

func CBCDecrypt(payload []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	blockSize := block.BlockSize()
	if err != nil {
		fmt.Printf("problem creating block\n")
	}

	out := make([]byte, len(payload))
	rawDecryptedBlock := make([]byte, len(key))
	decryptedBlock := make([]byte, len(key))

	for i := 0; i < len(payload); i += blockSize {
		block.Decrypt(rawDecryptedBlock, payload[i:i+blockSize])
		if i == 0 {
			decryptedBlock = FixedXOR(iv, rawDecryptedBlock)
		} else {
			decryptedBlock = FixedXOR(payload[i-blockSize:i], rawDecryptedBlock)
		}
		copy(out[i:i+blockSize], decryptedBlock)
	}
	return PKCS7Unpad(out, blockSize)
}

func CTREncrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
  if err != nil {
    panic("problem creating aes cipher for key")
  }
	blockSize := block.BlockSize()

	decrypted := make([]byte, 0)
	out := make([]byte, block.BlockSize())
  counterBytes := make([]byte, 8)

	for i := 0; i < len(ciphertext); i += blockSize {
    binary.LittleEndian.PutUint64(counterBytes, uint64(i/blockSize))
    keystream := append(nonce, counterBytes...)
		block.Encrypt(out, keystream)

    end := i+blockSize
    if end > len(ciphertext) {
      end = len(ciphertext)
    }

		thisblock := ciphertext[i : end]
    out = FixedXOR(out[:len(thisblock)], thisblock)
		decrypted = append(decrypted, out...)
	}

	return decrypted
}

func Average(xs []float64) float64 {
  total := float64(0)
  for _, x := range xs {
    total += x
  }
  return total / float64(len(xs))
}

// Returns smallest number in a series
func Min(xs []float64) float64 {
  min := xs[0]
  for _, x := range xs {
    if min > x {
      min = x
    }
  }
  return min
}

// Returns largest number in a series
func Max(xs []float64) float64 {
  max := xs[0]
  for _, x := range xs {
    if max < x {
      max = x
    }
  }
  return max
}
