package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strings"

	"jfeintzeig/cryptopals/lib"
)

var ch12AESKey []byte
var ch13AESKey []byte
var ch14AESKey []byte
var ch14Prepend []byte
var ch16IV []byte
var ch16AESKey []byte

func init() {
	ch12AESKey = cryptopals.RandomAESKey()
	ch13AESKey = cryptopals.RandomAESKey()
	ch14AESKey = cryptopals.RandomAESKey()
	nBytesPrepend := uint8(rand.Intn(14))
	ch14Prepend = cryptopals.GenerateRandomBytes(int(nBytesPrepend))

	ch16IV = cryptopals.RandomAESKey()
	ch16AESKey = cryptopals.RandomAESKey()
}

func Challenge9() {
	input := []byte("YELLOW SUBMARINE")
	length := 81
	padded := cryptopals.PKCS7(input, length)
	fmt.Printf("Challenge 9: %s\n", padded)
	if string(padded) != "YELLOW SUBMARINEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		panic("problem w challenge 9")
	}

	pad := cryptopals.PKCS7(input, 16)
  paddedInput := append(input, cryptopals.MakeSingleByteSlice(0x10, 16)...)
	if !reflect.DeepEqual(paddedInput, pad) {
    fmt.Printf("%v\n%v", pad, paddedInput)
		panic("pkcs7 w/no pad required doesn't work")
	}
}

func Challenge10() {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	file, err := os.ReadFile("10.txt")
	if err != nil {
		panic("problem opening file")
	}
	input, err := base64.StdEncoding.DecodeString(string(file))

	fmt.Printf("\n ********** Challenge 10 ************\n")

	test := []byte("this is a string and another one what ya now")
	encrypted := cryptopals.CBCEncrypt(test, key, iv)
	decrypted, err := cryptopals.CBCDecrypt(encrypted, key, iv)
  if err != nil {
    panic("problem w CBC decrypt padding")
  }
	if !reflect.DeepEqual(test, decrypted) {
		fmt.Printf("%s %v\n", test, test)
		fmt.Printf("%v\n", encrypted)
		fmt.Printf("%s %v\n", decrypted, decrypted)
		panic("CBC mode roundtrip doesn't work")
	}

	decrypted, err = cryptopals.CBCDecrypt(input, key, iv)
  if err != nil {
    panic("problem w CBC decrypt padding")
  }
	fmt.Printf("%s\n", decrypted)

	fmt.Printf("********** END Challenge 10 ***********\n")
}

func EncryptionOracle(input []byte) ([]byte, string) {
	nPrepend := 5 + rand.Intn(5)
	nAppend := 5 + rand.Intn(5)
	payload := append(cryptopals.GenerateRandomBytes(nPrepend), input...)
	payload = append(payload, cryptopals.GenerateRandomBytes(nAppend)...)

	key := cryptopals.RandomAESKey()

	if rand.Intn(2) == 0 {
		return cryptopals.AESEncrypt(payload, key), "ECB"
	} else {
		iv := cryptopals.GenerateRandomBytes(16)
		return cryptopals.CBCEncrypt(payload, key, iv), "CBC"
	}
}

func Challenge11() {
	key := []byte("YELLOW SUBMARINE")
	input := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	encrypted := cryptopals.AESEncrypt(input, key)
	decrypted := cryptopals.AESDecrypt(encrypted, key)
	if !reflect.DeepEqual(input, decrypted) {
		panic("AES roundtrip fails")
	}

	nRounds := 10000
	var guessedMethod string
	for i := 0; i < nRounds; i++ {
		encrypted, actualMethod := EncryptionOracle(input)
		nSame := cryptopals.CountMatches(encrypted, 16)
		if nSame > 1 {
			guessedMethod = "ECB"
		} else {
			guessedMethod = "CBC"
		}

		if guessedMethod != actualMethod {
			panic("uh oh my oracle guessing fails")
		}
	}

	fmt.Printf("********** Challenge 11 ***********\n\n")
	fmt.Printf("Guessed ECB / CBC correct for %d rounds\n\n", nRounds)
	fmt.Printf("********** END Challenge 11 ***********\n")
}

func Ch12Oracle(input []byte) []byte {
	b64secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret, err := base64.StdEncoding.DecodeString(string(b64secret))
	if err != nil {
		panic("problem b64 decoding secret")
	}
	toEncrypt := append(input, secret...)
	return cryptopals.AESEncrypt(toEncrypt, ch12AESKey)
}

// NB: this one only works if the oracle does not prepend bytes before encrypting
func CalculateBlockSize(oracle func([]byte) []byte) int {
	//var input []byte
	// if we start with less than 6 a's, statistical noise can trip us up
	input := []byte("aaaaa")
	fmt.Printf("calculating block size\n")
	for {
		input = append(input, []byte("a")...)
		encrypted := oracle(input)
		// we expect to get matches when our input is 2x the blocksize
		// could just pass in encrypted[:len(input)]
		nMatches := cryptopals.CountMatches(encrypted, len(input)/2)
		if nMatches > 1 {
			return len(input) / 2
		}

		if len(input) > 50 {
			panic("made it to 50 but no blocksize found :(")
		}
	}
}

// NB: this gives the total length of what the oracle prepends + appends to the input
func CalculateLengthSecret(oracle func([]byte) []byte) int {
	// figure out how long the secret is by looking at padding/blocksize
	// if blockSize is 16 and the length of _just_ the secret post-encryption
	// is 144, then we pre-pend with a's until we hit 144 -> 160.
	// say that happens with 5 a's. 5 a's made us overflow to the next block.
	// so 4 a's are needed to pad the secret to the current block. so the
	// length of the secret is 144 - 4 = 140
	filler := make([]byte, 0)
	rawEncryptedSecret := oracle(filler)
	lenEncrypted := len(rawEncryptedSecret)

	var lenSecret int
	for {
		filler = append(filler, []byte("a")...)
		encryptedSecret := oracle(filler)
		if len(encryptedSecret) != lenEncrypted {
			fmt.Printf("length of secret is %d\n", lenEncrypted-(len(filler)-1))
			lenSecret = lenEncrypted - (len(filler) - 1)
			break
		}
	}
	return lenSecret
}

func CreateDictionary(oracle func([]byte) []byte, seed []byte, nBytesKeep int) map[string]byte {
	dict := make(map[string]byte)
	for i := 0; i < 256; i++ {
		input := append(seed, byte(i))
		key := string(oracle(input))[:nBytesKeep]
		dict[key] = byte(i)
	}
	return dict
}

// 3. inner loop: make input 1 byte short of block, make dictionary,
// decrypt character, repeat recursively
// `offset`: the # of characters the oracle prepends to the input before encrypting
func DecryptByteAtATimeECB(oracle func([]byte) []byte, blockSize int, lenSecret int, seed []byte, offset int, decryptedBytes []byte) []byte {
	// keep track of how many blocks we've decrypted
	nBlock := 1 + len(decryptedBytes)/blockSize
	if offset != 0 {
		nBlock += 1
	}

	// dictionary needs to take in a seed that's a
	// combination of a's and already decodedBytes
	// but the last block is 1-byte short
	dictSeed := append(seed, decryptedBytes...)
	seedLength := nBlock*blockSize - 1 - offset
	dictSeed = dictSeed[len(dictSeed)-seedLength:]

	decoderMap := CreateDictionary(oracle, dictSeed, nBlock*blockSize)
	encrypted := oracle(seed)
	decodedByte, ok := decoderMap[string(encrypted)[:nBlock*blockSize]]

	if !ok {
		fmt.Printf("nblock: %d, len(dictSeed): %d dictSeed: %v decryptedBytes: %v\n", nBlock, len(dictSeed), dictSeed, decryptedBytes)
		fmt.Printf("encrypted: %v\n", encrypted)
		fmt.Printf("%d %d\n", lenSecret, len(decryptedBytes))
		panic("failed to decode byte")
	}
	decryptedBytes = append(decryptedBytes, decodedByte)

	// seed "a"*15 -> "a"*14 -> "a"*13 -> ...
	// as we give it fewer a's, the first block gets filled with
	// bytes from the secret key. once the first block entirely consists
	// of the secret key, we need to start a new block, so seed becomes
	// "a"*16 + 15 decoded bytes. this allows us to decode the 32nd byte.
	if len(seed) == 0 {
		seed = cryptopals.MakeSingleByteSlice(0x61, blockSize-1)
	} else if offset != 0 && len(seed) == blockSize-offset {
		seed = cryptopals.MakeSingleByteSlice(0x61, blockSize-offset+blockSize-1)
	} else {
		seed = seed[1:]
	}

	// if we've decoded all bytes, return. otherwise, decode next byte
	if len(decryptedBytes) == lenSecret {
		return decryptedBytes
	} else {
		return DecryptByteAtATimeECB(oracle, blockSize, lenSecret, seed, offset, decryptedBytes)
	}
}

func Challenge12() {
	fmt.Printf("********** Challenge 12 ***********\n")
	// steps
	// 1. calculate block size
	// 2. detect ecb (same as 1?): if we get repeats, we know it's ECB

	blockSize := CalculateBlockSize(Ch12Oracle)
	fmt.Printf("blockSize: %d\n", blockSize)
	if blockSize != 16 {
		panic("failed to detect ECB // failed to find block size")
	}

	// 4. outer loop to do (3) for whole secret

	seedCharacter := byte(0x61)
	initialSeed := cryptopals.MakeSingleByteSlice(seedCharacter, blockSize-1)
	decryptedBytes := make([]byte, 0)

	lenSecret := CalculateLengthSecret(Ch12Oracle)
	decrypted := DecryptByteAtATimeECB(Ch12Oracle, blockSize, lenSecret, initialSeed, 0, decryptedBytes)
  decrypted, err := cryptopals.PKCS7Unpad(decrypted, blockSize)
  if err != nil {
    panic("pkcs7 unpadding failed for challenge 12")
  }

	fmt.Printf("decrypted:\n\n%s\n", decrypted)

	truth := []byte{82, 111, 108, 108, 105, 110, 39, 32, 105, 110, 32, 109, 121, 32, 53, 46, 48, 10, 87, 105, 116, 104, 32, 109, 121, 32, 114, 97, 103, 45, 116, 111, 112, 32, 100, 111, 119, 110, 32, 115, 111, 32, 109, 121, 32, 104, 97, 105, 114, 32, 99, 97, 110, 32, 98, 108, 111, 119, 10, 84, 104, 101, 32, 103, 105, 114, 108, 105, 101, 115, 32, 111, 110, 32, 115, 116, 97, 110, 100, 98, 121, 32, 119, 97, 118, 105, 110, 103, 32, 106, 117, 115, 116, 32, 116, 111, 32, 115, 97, 121, 32, 104, 105, 10, 68, 105, 100, 32, 121, 111, 117, 32, 115, 116, 111, 112, 63, 32, 78, 111, 44, 32, 73, 32, 106, 117, 115, 116, 32, 100, 114, 111, 118, 101, 32, 98, 121, 10}
	if string(decrypted) != string(truth) {
    fmt.Printf("%v\n%v\n", decrypted, truth)
		panic("failed to decrypt")
	}
	fmt.Printf("********** END Challenge 12 ***********\n")
}

func ParseParams(input string) map[string]string {
	out := make(map[string]string)
	for _, val := range strings.Split(input, "&") {
		sp := strings.Split(val, "=")
		out[sp[0]] = sp[1]
	}
	return out
}

func EncodeParamsAsString(params map[string]string) string {
	var keys []string
	for k, _ := range params {
		keys = append(keys, k)
	}

	// make it so the email/user/role struct is always in order
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i] == "email" {
			return true
		} else if keys[i] == "role" {
			return false
		} else if keys[j] == "email" {
			return false
		} else if keys[j] == "role" {
			return true
		} else {
			return keys[i][0] < keys[j][0]
		}
	})

	var sb strings.Builder
	for _, k := range keys {
		s := fmt.Sprintf("%s=%s&", k, params[k])
		sb.WriteString(s)
	}
	return sb.String()[:len(sb.String())-1]
}

func GetProfile(email string) string {
	// NB: to decode the secret string, i need to add & and = into the byte-by-byte decrypting seeds
	// so we can't sanitize
	//sanitizedEmail := strings.ReplaceAll(strings.ReplaceAll(string(email), "&", ""), "=", "")
	return fmt.Sprintf("email=%s&uid=10&role=user", email)
}

func CalculateBlockSizeWithOffset(oracle func([]byte) []byte) (int, int) {
	//var input []byte
	// if we start with less than 6 a's, statistical noise can trip us up
	input := []byte("aaaaaaaaa")
	fmt.Printf("calculating block size\n")
	for {
		input = append(input, []byte("a")...)
		encrypted := oracle(input)
		// if the oracle prepends bytes, then input must be > 2 x blocksize
		// to start seeing repeated patterns. e.g. if blocksize is 16 but 8
		// bytes are prepended, we need 16*2+8 = 40 byte input to find blocksize 16
		// we scan from large to small blocksizes to find the greatest repeating pattern
		for blockSize := len(input)/2 + 1; blockSize > 4; blockSize-- {
			nMatches := cryptopals.CountMatches(encrypted, blockSize)
			if nMatches > 1 {
				offset := blockSize - (len(input) - nMatches*blockSize)
				return blockSize, offset
			}
		}

		if len(input) > 100 {
			panic("made it to 100 but no blocksize found :(")
		}
	}
}

// keep this one as taking []byte so I can use functions from Ch12
func Ch13Oracle(email []byte) []byte {
	return cryptopals.AESEncrypt([]byte(GetProfile(string(email))), ch13AESKey)
}

func Ch13DecryptAndParse(ciphertext []byte) map[string]string {
	decrypted := cryptopals.AESDecrypt(ciphertext, ch13AESKey)
	return ParseParams(string(decrypted))
}

// NB: problems with challenge 13:
//   - i need to be able to encode & and = in GetProfile, because
//     i need it to decrypt the string that gets appended to the hashing
//     theoretically this is needed to know how many characters of this
//     append string i need to push into the next block
//   - i assumed the inputs get padded via PKCS7. i dont know how to get
//     the hash for `admin` without doing this.
func Challenge13() {
	fmt.Printf("*********** Challenge 13 ***********\n\n")
	test := "baz=qux&foo=bar&zap=zazzle"
	testParams := ParseParams(test)

	expectedParams := map[string]string{"foo": "bar", "baz": "qux", "zap": "zazzle"}
	if !reflect.DeepEqual(expectedParams, testParams) {
		panic("problem parsing params")
	}
	if test != EncodeParamsAsString(expectedParams) {
		panic("round trip parsing failed")
	}
	test = "email=foo@bar.com&uid=10&role=user"
	if test != EncodeParamsAsString(ParseParams(test)) {
		panic("round trip parsing failed")
	}

	//profile := GetProfile("test@gmail.com&role=admin")
	//if profile != "email=test@gmail.comroleadmin&uid=10&role=user" {
	//  panic("get profile doesn't work")
	//}

	test2 := []byte("balh@foobarbaz.com")
	cipher := Ch13Oracle(test2)
	output := Ch13DecryptAndParse(cipher)
	fmt.Printf("%v\n", output)

	blockSize, offset := CalculateBlockSizeWithOffset(Ch13Oracle)
	fmt.Printf("blocksize: %d offset: %d\n", blockSize, offset)

	lenSecret := CalculateLengthSecret(Ch13Oracle)
	lenAppendSecret := lenSecret - offset

	seedCharacter := byte(0x61)
	initialSeed := cryptopals.MakeSingleByteSlice(seedCharacter, blockSize-offset+blockSize-1)
	decryptedBytes := make([]byte, 0)

	decrypted := DecryptByteAtATimeECB(Ch13Oracle, blockSize, lenAppendSecret, initialSeed, offset, decryptedBytes)
	fmt.Printf("decrypted secret string: %s\n", string(decrypted))

	// find email that aligns `&role=` with end of block, so new block is just `user` (or `admin`)
	defaultPadding := blockSize - (lenSecret % blockSize)
	// `user` is 4 characters to chop off end, so add 4
	// but i want my email to end in @gmail.com (10 characters), so subtract 10
  // NB: weeks later i fix how my PKCS pad/unpad works so it always adds 1-16 bytes,
  // and now my math is off and somehow adding 5 bytes instead of 4 works.
	lenEmail := defaultPadding + 5 - 10 // `user` is 4 characters to chop off end, but i want my email to end in @gmail.com, which is 10
	email := cryptopals.MakeSingleByteSlice(0x61, lenEmail)
	email = append(email, []byte("@gmail.com")...)
	encryptedNoRole := Ch13Oracle(email)
	encryptedNoRole = encryptedNoRole[:len(encryptedNoRole)-blockSize]

	// find hash for admin + padding (how to do padding???)
	// <offset from secret><blocksize-offset filler><`admin`><fill block>
	fillFirstBlock := cryptopals.MakeSingleByteSlice(0x61, blockSize-offset)
	// NB: we assume PKCS7 padding ... do i need to assume this?
	paddingLength := blockSize - len([]byte("admin"))
	padding := cryptopals.MakeSingleByteSlice(uint8(paddingLength), paddingLength)

	userString := append(fillFirstBlock, []byte("admin")...)
	userString = append(userString, padding...)

	encryptedUserString := Ch13Oracle(userString)

	// just take 2nd block of encryptedpayload
	payload := append(encryptedNoRole, encryptedUserString[blockSize:2*blockSize]...)
	fmt.Printf("encrypted payload: %v\n", payload)
	output = Ch13DecryptAndParse(payload)
	fmt.Printf("output: %v\n", output)
	if output["role"] != "admin" {
    fmt.Printf("%v\n", output)
		panic("challenge 13 role is not admin")
	}
	fmt.Printf("*********** END Challenge 13 ***********\n\n")
}

func Ch14Oracle(input []byte) []byte {
	b64secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secret, err := base64.StdEncoding.DecodeString(string(b64secret))
	if err != nil {
		panic("problem b64 decoding secret")
	}
	toEncrypt := append(ch14Prepend, input...)
	toEncrypt = append(toEncrypt, secret...)
	return cryptopals.AESEncrypt(toEncrypt, ch14AESKey)
}

// TODO: if secret string is longer than blocksize, this fails
func Challenge14() {
	fmt.Printf("********** Challenge 14 ***********\n\n")
  fmt.Printf("Ch14 prepend: %d\n", len(ch14Prepend))
	blockSize, offset := CalculateBlockSizeWithOffset(Ch14Oracle)
	fmt.Printf("blocksize: %d offset: %d\n", blockSize, offset)

	lenSecret := CalculateLengthSecret(Ch14Oracle)
	lenAppendSecret := lenSecret - offset

	seedCharacter := byte(0x61)
	initialSeed := cryptopals.MakeSingleByteSlice(seedCharacter, blockSize-offset+blockSize-1)
	decryptedBytes := make([]byte, 0)

	decrypted := DecryptByteAtATimeECB(Ch14Oracle, blockSize, lenAppendSecret, initialSeed, offset, decryptedBytes)
	fmt.Printf("decrypted secret string:\n%s\n", string(decrypted))
	fmt.Printf("*********** END Challenge 14 ***********\n\n")
}

func Challenge15() {
	fmt.Printf("*********** Challenge 15 ***********\n")

	t1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	t2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	t3 := []byte("ICE ICE BABY\x01\x02\x03\x04")

	_, err := cryptopals.PKCS7Unpad(t1, 16)
	if err != nil {
		panic("pkcs7 valid unpad test failed")
	}
	_, err = cryptopals.PKCS7Unpad(t2, 16)
	if err == nil {
		panic("pkcs7 invalid unpad test 1 failed")
	}
	_, err = cryptopals.PKCS7Unpad(t3, 16)
	if err == nil {
		panic("pkcs7 invalid unpad test 2 failed")
	}

	fmt.Printf("\nChallenge 15 successful\n\n")

	fmt.Printf("*********** END Challenge 15 ***********\n")
}

func Ch16Oracle(input []byte) []byte {
	prependBytes := []byte("comment1=cooking%20MCs;userdata=")
	appendBytes := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	sanitizedInput := strings.ReplaceAll(string(input), ";", "/;/")
	sanitizedInput = strings.ReplaceAll(sanitizedInput, "=", "/=/")

	payload := append(prependBytes, sanitizedInput...)
	payload = append(payload, appendBytes...)

	paddedPayload := cryptopals.PKCS7(payload, 16)

	return cryptopals.CBCEncrypt(paddedPayload, ch16AESKey, ch16IV)
}

func Ch16CheckAdmin(ciphertext []byte) bool {
	decrypted, err := cryptopals.CBCDecrypt(ciphertext, ch16AESKey, ch16IV)
  if err != nil {
    panic("problem w CBC decrypt padding")
  }
	return strings.Contains(string(decrypted), ";admin=true;")
}

func FlipBit(b byte, bitNumber uint8) byte {
	magicBit := (b >> bitNumber) & 0x01
	if magicBit == 1 {
		return 0b01111111 & b
	} else {
		return 0b10000000 | b
	}
}

func Challenge16() {
	fmt.Printf("******************* Challenge 16 *****************\n")
	encrypted := Ch16Oracle([]byte(";admin=true;"))
	hasAdmin := Ch16CheckAdmin(encrypted)
	if hasAdmin {
		panic("ch 16 test fails: shouldnt be able to set admin=true directly")
	}

	// ;admin=true;
	magicString, _ := hex.DecodeString("3B61646D696E3D747275653B")
	magicString[0] = FlipBit(magicString[0], 7)
	magicString[6] = FlipBit(magicString[6], 7)
	magicString[11] = FlipBit(magicString[11], 7)

  // NB: this implicitly assumes the oracle prepend string _is_ an even number of blocks.
  // I'm not sure how to calculate this offset a priori given our methodology only works for
  // ECB mode. Trying to look at when the ciphertext length jumps up works for calculating
  // blocksize, but not for offset since the oracle also append's bytes
	input := append(magicString, cryptopals.MakeSingleByteSlice(0x61, 16-len(magicString))...)
	cipher := Ch16Oracle(input)

	cipher[16] = FlipBit(cipher[16], 7)
	cipher[22] = FlipBit(cipher[22], 7)
	cipher[27] = FlipBit(cipher[27], 7)
	isAdmin := Ch16CheckAdmin(cipher)
	fmt.Printf("\nisAdmin: %t\n\n", isAdmin)
	fmt.Printf("******************* END Challenge 16 *****************\n")
}

func main() {
	Challenge9()
	Challenge10()
	Challenge11()
	Challenge12()
	Challenge13()
	Challenge14()
	Challenge15()
	Challenge16()
}
