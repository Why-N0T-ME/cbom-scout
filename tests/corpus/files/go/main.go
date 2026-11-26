package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/aes"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// sha1.Sum(data) 는 쓰지 않는다
var doc = `md5.New() 예제`
var msg = "des.NewCipher(k) 금지"
var md5Hex = "d41d8cd98f00b204e9800998ecf8427e"

func run(data, k []byte) {
	_ = md5.Sum(data)
	_ = sha256.Sum256(data)
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	block, _ := aes.NewCipher(k)
	tdes, _ := des.NewTripleDESCipher(k)
	_, _, _ = key, block, tdes
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = ek
}
