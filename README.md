# go-evp

An implementation of the Openssl [EVP\_BytesToKey](https://www.openssl.org/docs/man1.0.2/man3/EVP_BytesToKey.html) function.

## Overview

This library can be used to provide the key and IV for a given salt and passphrase. Note that although it implements the logic, the function signature does not match. See `BytesToKeyAES256CBC` for a helper function that works with aes-256-cbc.

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
	key, iv := evp.BytesToKeyAES256CBC(salt, []byte("password"))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(payload, payload)
	fmt.Println("Decrypted =", string(payload))
}
```
