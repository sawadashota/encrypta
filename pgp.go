package encrypta

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// pgpEncryptionKey is OpenPGP public key
type pgpEncryptionKey []byte

// Encrypt text using given PGP public key
func (pk *pgpEncryptionKey) Encrypt(value []byte) (Encrypted, error) {
	encryptionKey, err := pk.base64EncodedEncryptionKey()
	if err != nil {
		return nil, err
	}

	entity, err := getEntity(encryptionKey)
	if err != nil {
		return nil, err
	}

	ctBuf := bytes.NewBuffer(nil)
	pt, err := openpgp.Encrypt(ctBuf, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	_, err = pt.Write(value)
	if err != nil {
		return nil, err
	}
	defer pt.Close()

	return ctBuf.Bytes(), nil
}

func (pk *pgpEncryptionKey) base64EncodedEncryptionKey() (string, error) {
	return base64.StdEncoding.EncodeToString(*pk), nil
}

func getEntity(encryptionKey string) (*openpgp.Entity, error) {
	data, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return nil, err
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(data)))
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// NewPublicKey returns new pgpEncryptionKey instance from given key
func NewPublicKey(key io.Reader) (EncryptionKey, error) {
	rawKey, err := ioutil.ReadAll(key)
	if err != nil {
		return nil, err
	}

	ek, err := encryptionKey(rawKey)
	if err != nil {
		return nil, err
	}

	pk := pgpEncryptionKey(ek)
	return &pk, nil
}

func encryptionKey(bundle []byte) ([]byte, error) {
	keyReader := bytes.NewReader(bundle)
	entityList, err := openpgp.ReadArmoredKeyRing(keyReader)

	if err != nil {
		return nil, err
	}

	serializedEntity := bytes.NewBuffer(nil)
	err = entityList[0].Serialize(serializedEntity)
	if err != nil {
		return nil, err
	}

	return serializedEntity.Bytes(), nil
}

// NewPublicKeyFromBase64Encoded returns new EncryptionKey from base64 encoded key
func NewPublicKeyFromBase64Encoded(base64EncodedKey string) (EncryptionKey, error) {
	b, err := base64.StdEncoding.DecodeString(base64EncodedKey)
	if err != nil {
		return nil, err
	}
	return NewPublicKey(bytes.NewBuffer(b))
}

// httpClient for fetch public key from URL
// This might be changed in some cases
var httpClient = http.DefaultClient

// Option for changing global variable
type Option func()

// HTTPClientOption replace http.Client
// Supposes tests, GAE environment or etc...
func HTTPClientOption(client *http.Client) Option {
	return func() {
		httpClient = client
	}
}

// NewPublicKeyFromURL fetches public key from given URL and returns encryption key
func NewPublicKeyFromURL(publicKeyURL string, opts ...Option) (EncryptionKey, error) {
	for _, opt := range opts {
		opt()
	}

	req, err := http.NewRequest("GET", publicKeyURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	key := bytes.NewBuffer(body)
	return NewPublicKey(key)
}

// NewPublicKeyFromKeybase fetches public key from given Keybase's username and returns encryption key
func NewPublicKeyFromKeybase(username string, opts ...Option) (EncryptionKey, error) {
	publicKeyURL := fmt.Sprintf("https://keybase.io/%s/pgp_keys.asc", username)
	return NewPublicKeyFromURL(publicKeyURL, opts...)
}
