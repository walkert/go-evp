package evp

import (
	"encoding/hex"
	"testing"
)

const (
	blockLen    int    = 16
	keyLen      int    = 32
	goodSaltHex string = "8c17a0f39ec8624a"
	badSaltHex  string = "8817b0d30fg4934e"
	goodKey     string = "e2dbc7d5a2ac454743582471c6d9b316fdb55f841632ceef02ad7bc9f559dfae"
	goodIV      string = "fe1377f6c8ac2ece82f71743198bb191"
	goodKey256  string = "640df03bf7576a74789a9cbec5dff5594991c16a786b0c1a54a6c8a386bed508"
	goodIV256   string = "5ac94de87745426a28382e6d495e0992"
	password    string = "password"
)

func getSalt(s string) []byte {
	salt, _ := hex.DecodeString(s)
	return salt
}

func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func getOutputs(key, iv []byte) (hexKey, hexIV string, lenKey, lenIV int) {
	hexKey = bytesToHex(key)
	hexIV = bytesToHex(iv)
	lenKey = len(key)
	lenIV = len(iv)
	return
}

func TestGoodSalt(t *testing.T) {
	salt := getSalt(goodSaltHex)
	key, iv := BytesToKey(salt, []byte(password), keyLen, blockLen)
	hexKey, hexIV, keyLength, ivLength := getOutputs(key, iv)
	if hexKey != goodKey {
		t.Fatalf("Wanted key '%s', got '%s'\n", goodKey, hexKey)
	}
	if hexIV != goodIV {
		t.Fatalf("Wanted IV '%s', got '%s'\n", goodIV, hexIV)
	}
	if keyLength != 32 {
		t.Fatalf("Wanted key length %d, got %d\n", 32, keyLength)
	}
	if ivLength != 16 {
		t.Fatalf("Wanted IV length %d, got %d\n", 16, ivLength)
	}
}

func TestGoodSalt256(t *testing.T) {
	salt := getSalt(goodSaltHex)
	key, iv := BytesToKey256(salt, []byte(password), keyLen, blockLen)
	hexKey, hexIV, keyLength, ivLength := getOutputs(key, iv)
	if hexKey != goodKey256 {
		t.Fatalf("Wanted key '%s', got '%s'\n", goodKey256, hexKey)
	}
	if hexIV != goodIV256 {
		t.Fatalf("Wanted IV '%s', got '%s'\n", goodIV256, hexIV)
	}
	if keyLength != 32 {
		t.Fatalf("Wanted key length %d, got %d\n", 32, keyLength)
	}
	if ivLength != 16 {
		t.Fatalf("Wanted IV length %d, got %d\n", 16, ivLength)
	}
}

func TestBadSalt(t *testing.T) {
	salt := getSalt(badSaltHex)
	key, iv := BytesToKey(salt, []byte(password), keyLen, blockLen)
	hexKey, hexIV, _, _ := getOutputs(key, iv)
	if hexKey == goodKey {
		t.Fatalf("Got a valid key using an invalid Salt!")
	}
	if hexIV == goodIV {
		t.Fatalf("Got a valid IV using an invalid Salt!")
	}
}

func TestBadPassword(t *testing.T) {
	salt := getSalt(goodSaltHex)
	key, iv := BytesToKey(salt, []byte("badpassword"), keyLen, blockLen)
	hexKey, hexIV, _, _ := getOutputs(key, iv)
	if hexKey == goodKey {
		t.Fatalf("Got a valid key using an invalid password!")
	}
	if hexIV == goodIV {
		t.Fatalf("Got a valid IV using an invalid password!")
	}
}
