package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
)

func config() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

func keys() {
	_, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, _ = mlkem.GenerateKey768()
	_ = sha1.Sum([]byte("legacy"))
}
