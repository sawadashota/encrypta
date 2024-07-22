package encrypta_test

import (
	"testing"

	"github.com/sawadashota/encrypta"
)

func TestEncrypted_Base64Encode(t *testing.T) {
	cases := map[string]struct {
		e    encrypta.Encrypted
		want string
	}{
		"encrypted value is 'bar'": {
			e:    encrypta.Encrypted([]byte("bar")),
			want: "YmFy",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.e.Base64Encode(); got != c.want {
				t.Errorf("Encrypted.Base64Encode() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEncrypted_String(t *testing.T) {
	cases := map[string]struct {
		e    encrypta.Encrypted
		want string
	}{
		"encrypted value is 'bar'": {
			e:    encrypta.Encrypted([]byte("bar")),
			want: "bar",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.e.String(); got != c.want {
				t.Errorf("Encrypted.Base64Encode() = %v, want %v", got, c.want)
			}
		})
	}
}
