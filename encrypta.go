// Package encrypta encrypts text by public key
//
// Example
//	pk, err := encrypta.NewPublicKeyFromKeybase("sawadashota")
//	if err != nil {
//		// error handling
//	}
//
//	enc, err := pk.Encrypt([]byte("I'm encrypted text"))
//	if err != nil {
//		// error handling
//	}
//
//	fmt.Println(enc.Base64Encode())
//	// Stdout base64 encoded encrypted text
//
// To decode this, private key holder executes following command
//	$ go run main.go | base64 --decode | keybase pgp decrypt
//	I'm encrypted text
package encrypta

import (
	"encoding/base64"
)

// Encrypted .
type Encrypted []byte

// String of Encrypted text
func (e *Encrypted) String() string {
	return string(*e)
}

// Base64Encode Encrypted text
func (e *Encrypted) Base64Encode() string {
	return base64.StdEncoding.EncodeToString(*e)
}

// EncryptionKey is public key to encrypt
type EncryptionKey interface {
	Encrypt(value []byte) (Encrypted, error)
}
