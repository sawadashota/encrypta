Encrypta
===

[![GoDoc](https://godoc.org/github.com/sawadashota/encrypta?status.svg)](https://godoc.org/github.com/sawadashota/encrypta)
[![codecov](https://codecov.io/gh/sawadashota/encrypta/branch/master/graph/badge.svg)](https://codecov.io/gh/sawadashota/encrypta)

[Keybase](https://keybase.io) friendly, encrypts text by public key.

Example
---

```go
pk, err := encrypta.NewPublicKeyFromKeybase("sawadashota")
if err != nil {
	// error handling
}

enc, err := pk.Encrypt([]byte("I'm encrypted text"))
if err != nil {
	// error handling
}

fmt.Println(enc.Base64Encode())
// Stdout base64 encoded encrypted text
```

To decode this, private key holder executes following command

```
$ go run main.go | base64 --decode | keybase pgp decrypt
I'm encrypted text
```
