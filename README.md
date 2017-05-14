# go-evp

An implementation of the Openssl [EVP\_BytesToKey](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3)) function.

## Overview

This library can be used to provide the key and IV for a given salt and passphrase. 

## Usage

The example below demonstrates how you would use go-evp to decrypt a file which has been encrypted with openssl using the aes-256-cbc cipher type with the salt option.

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/walkert/go-evp"
	"io/ioutil"
)

const salted string = "Salted__"

func main() {
	data, _ := ioutil.ReadFile("encrypted.file")
	salt := data[len(salted):aes.BlockSize]
	payload := data[aes.BlockSize:]
	key, iv := evp.BytesToKey(salt, []byte("password"), 32, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(payload, payload)
	fmt.Println("Decrypted =", string(payload))
}
```
