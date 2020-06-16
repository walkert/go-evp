package evp

import (
	"encoding/hex"
	"testing"
)

const (
	blockLen   int    = 16
	keyLen     int    = 32
	goodKeyMD5 string = "fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f2"
	goodIVMD5  string = "0b5ca7b1081f94b1ac12e3c8ba87d05a"
	goodKey    string = "0c8cde87480244c4d1bbd7401f70b7aebedf5a4453d01a7665db51aaf4d7dd72"
	goodIV     string = "6dea80f410c6fa07183a01eed7efcf6e"
	password   string = "password"
)

var (
	badSalt  = []byte("salt")
	goodSalt = []byte("saltsalt")
)

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
	key, iv := BytesToKeyAES256CBC(goodSalt, []byte(password))
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

func TestGoodSaltMD5(t *testing.T) {
	key, iv := BytesToKeyAES256CBCMD5(goodSalt, []byte(password))
	hexKey, hexIV, keyLength, ivLength := getOutputs(key, iv)
	if hexKey != goodKeyMD5 {
		t.Fatalf("Wanted key '%s', got '%s'\n", goodKeyMD5, hexKey)
	}
	if hexIV != goodIVMD5 {
		t.Fatalf("Wanted IV '%s', got '%s'\n", goodIVMD5, hexIV)
	}
	if keyLength != 32 {
		t.Fatalf("Wanted key length %d, got %d\n", 32, keyLength)
	}
	if ivLength != 16 {
		t.Fatalf("Wanted IV length %d, got %d\n", 16, ivLength)
	}
}

func TestBadSalt(t *testing.T) {
	defer func() { recover() }()
	key, iv := BytesToKeyAES256CBC(badSalt, []byte(password))
	getOutputs(key, iv)
	t.Fatalf("Expected a panic due to invalid salt length but one did not occur")
}

func TestBadPassword(t *testing.T) {
	key, iv := BytesToKeyAES256CBC(goodSalt, []byte("badpassword"))
	hexKey, hexIV, _, _ := getOutputs(key, iv)
	if hexKey == goodKey {
		t.Fatalf("Got a valid key using an invalid password!")
	}
	if hexIV == goodIV {
		t.Fatalf("Got a valid IV using an invalid password!")
	}
}
