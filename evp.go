package evp

import (
	"crypto/md5"
	"crypto/sha256"
	"hash"
)

// bytesToKey implements the Openssl EVP_BytesToKey method
func bytesToKey(salt, data []byte, h hash.Hash, keyLen, blockLen int) (key, iv []byte) {
	var (
		concat   []byte
		lastHash []byte
		totalLen = keyLen + blockLen
	)
	for ; len(concat) < totalLen; h.Reset() {
		// concatenate lastHash, data and salt and write them to the hash
		h.Write(append(lastHash, append(data, salt...)...))
		// passing nil to Sum() will return the current hash value
		lastHash = h.Sum(nil)
		// append lastHash to the running total bytes
		concat = append(concat, lastHash...)
	}
	return concat[:keyLen], concat[keyLen:totalLen]
}

// BytesToKey is the exported implementation of the MD5 version of EVP_BytesToKey
func BytesToKey(salt, data []byte, keyLen, blockLen int) (key []byte, iv []byte) {
	return bytesToKey(salt, data, md5.New(), keyLen, blockLen)
}

// BytesToKey256 is the exported implementation of the SHA256 version of EVP_BytesToKey
func BytesToKey256(salt, data []byte, keyLen, blockLen int) (key []byte, iv []byte) {
	return bytesToKey(salt, data, sha256.New(), keyLen, blockLen)
}
