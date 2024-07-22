package encrypta_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/sawadashota/encrypta"
)

const encryptionPGPKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: https://keybase.io/sawadashota
Version: Keybase Go 3.1.2 (darwin)

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
J+pIC44bZZli+5U5Bq2WcqKux7++
=NYV7
-----END PGP PUBLIC KEY BLOCK-----`

const encryptionRSAKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwR8tIhkRnt6S/gRbmBDe
MBSsexNBbKajbl9lDtljkO/925pyirFr+TOHtdzvfQbNaoL/zF2nP6syu218KzFJ
Xft3lt/bBXLQ1UVZg/8N4Hj0BxZ87CVLaZ5kx350eNoXdRrIsstfDl/Th/9ind9s
8w9tkqegjTA5s7ccLKQjlUNTi+kCy5Rw+7vSz9wFULVmQC1i5i8C3scndDMp7GFf
5WYyLRyNl/QI6XgeowB6rwhFdKmaLcyuQ0ov1/T/8fsMYUjaBnSK7gTWyFD92A2O
GGJxEccw++XTHz2AJWG/O3o6Rq6pzkxoYksuJSt5kHh8cYbYWjG63Hp8AOfrJNQt
OaXJ4Nz1MjtKC8sbGjLDkeVE9vppEq0Oxj5dNf28mzL/tMQ52euMxNhIYPuWaP/3
eNW7smEACxCmelNl1G7CLMSuiL+fJxmfeZWYp+3Jg1pjHud1/TmoX7TbzUt8CHBy
9pg31HYENR50QT5qNvy+FI+8PYNfShOnkQKF7HYQlZERG1Y9XcdDr/LDG3ygGAk2
zvcFFp+G4ocfdRDEpeWH0u46Ql2R0JmGsi0k54AKcVptffQsj4dL9Lk4XxZHLu4Y
7mkwcKxqGq2jIE6fYlhWeott2+D+0nGhMxiwwiVu3UaHOq/rkSN3XCOMiHy73crb
6HiwgJrnR+g3/ju89RalulMCAwEAAQ==
-----END PUBLIC KEY-----`

func TestNewPublicKey(t *testing.T) {
	type args struct {
		key io.Reader
	}
	cases := map[string]struct {
		args    args
		wantErr bool
	}{
		"PGP encryption key": {
			args: args{
				key: bytes.NewBuffer([]byte(encryptionPGPKey)),
			},
			wantErr: false,
		},
		"RSA encryption key": {
			args: args{
				key: bytes.NewBuffer([]byte(encryptionRSAKey)),
			},
			wantErr: true,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := encrypta.NewPublicKey(c.args.key)
			if (err != nil) != c.wantErr {
				t.Errorf("NewPublicKey() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestNewPublicKeyFromBase64Encoded(t *testing.T) {
	type args struct {
		base64EncodedKey string
	}
	cases := map[string]struct {
		args    args
		wantErr bool
	}{
		"base64 encoded encryption key": {
			args: args{
				base64EncodedKey: base64.StdEncoding.EncodeToString([]byte(encryptionPGPKey)),
			},
			wantErr: false,
		},
		"base64 encoded dummy text": {
			args: args{
				base64EncodedKey: base64.StdEncoding.EncodeToString([]byte("foobar")),
			},
			wantErr: true,
		},
		"plain text": {
			args: args{
				base64EncodedKey: "foobar",
			},
			wantErr: true,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := encrypta.NewPublicKeyFromBase64Encoded(c.args.base64EncodedKey)
			if (err != nil) != c.wantErr {
				t.Errorf("NewPublicKeyFromBase64Encoded() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// newTestClient returns *http.Client with Transport replaced to avoid making real calls
func newTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

// client for testing normal response
// *http.Response: only give value when you want customize response
func client(t *testing.T, respBody string) *http.Client {
	t.Helper()

	return newTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer([]byte(respBody))),
			Header:     make(http.Header),
		}
	})
}

func TestNewPublicKeyFromURL(t *testing.T) {
	type args struct {
		publicKeyURL string
		opts         []encrypta.Option
	}
	cases := map[string]struct {
		args    args
		wantErr bool
	}{
		"PGP encryption key": {
			args: args{
				publicKeyURL: "https://example.com/pgp.key",
				opts:         []encrypta.Option{encrypta.HTTPClientOption(client(t, encryptionPGPKey))},
			},
			wantErr: false,
		},
		"RSA encryption key": {
			args: args{
				publicKeyURL: "https://example.com/rsa.key",
				opts:         []encrypta.Option{encrypta.HTTPClientOption(client(t, encryptionRSAKey))},
			},
			wantErr: true,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := encrypta.NewPublicKeyFromURL(c.args.publicKeyURL, c.args.opts...)
			if (err != nil) != c.wantErr {
				t.Errorf("NewPublicKeyFromURL() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestNewPublicKeyFromKeybase(t *testing.T) {
	type args struct {
		username string
		opts     []encrypta.Option
	}
	cases := map[string]struct {
		args    args
		wantErr bool
	}{
		"valid username": {
			args: args{
				username: "sawadashota",
				opts:     []encrypta.Option{encrypta.HTTPClientOption(client(t, encryptionPGPKey))},
			},
			wantErr: false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := encrypta.NewPublicKeyFromKeybase(c.args.username, c.args.opts...)
			if (err != nil) != c.wantErr {
				t.Errorf("NewPublicKeyFromKeybase() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func Test_pgpEncryptionKey_Encrypt(t *testing.T) {
	pk, err := encrypta.NewPublicKey(bytes.NewBuffer([]byte(encryptionPGPKey)))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		value []byte
	}
	cases := map[string]struct {
		args    args
		wantErr bool
	}{
		"input 'foo'": {
			args: args{
				value: []byte("foo"),
			},
			wantErr: false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := pk.Encrypt(c.args.value)
			if (err != nil) != c.wantErr {
				t.Errorf("pgpEncryptionKey.Encrypt() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
