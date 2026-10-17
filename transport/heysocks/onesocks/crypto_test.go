package onesocks

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKDFVectors(t *testing.T) {
	tests := []struct {
		keyLen int
		want   string
	}{
		{
			16,
			"5f4dcc3b5aa765d61d8327deb882cf99",
		},
		{
			24,
			"5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374a",
		},
		{
			32,
			"5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08",
		},
	}

	for _, tt := range tests {
		got, err := KDF("password", tt.keyLen)
		if err != nil {
			t.Fatalf("KDF(%d): %v", tt.keyLen, err)
		}

		if hex.EncodeToString(got) != tt.want {
			t.Fatalf(
				"KDF(%d) = %x, want %s",
				tt.keyLen,
				got,
				tt.want,
			)
		}
	}
}

func TestVerify16Vector(t *testing.T) {
	got := Verify16("password")

	const want = "03586e9133f5f4b39d2f615d95a493c4"

	if hex.EncodeToString(got[:]) != want {
		t.Fatalf(
			"Verify16 = %x, want %s",
			got,
			want,
		)
	}
}

func TestSupportedAESCTRCiphers(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"aes-128-ctr", 16},
		{"AES-192-CTR", 24},
		{"aes-256-ctr", 32},
	}

	iv := make([]byte, 16)
	plaintext := []byte("onesocks-stage-b")

	for _, tt := range tests {
		c, err := NewStreamCipher(tt.name, "password")
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}

		if len(c.key) != tt.keySize {
			t.Fatalf(
				"%s key size = %d, want %d",
				tt.name,
				len(c.key),
				tt.keySize,
			)
		}

		encrypted := make([]byte, len(plaintext))

		enc, err := c.Encrypter(iv)
		if err != nil {
			t.Fatalf("%s encrypter: %v", tt.name, err)
		}

		enc.XORKeyStream(encrypted, plaintext)

		decrypted := make([]byte, len(encrypted))

		dec, err := c.Decrypter(iv)
		if err != nil {
			t.Fatalf("%s decrypter: %v", tt.name, err)
		}

		dec.XORKeyStream(decrypted, encrypted)

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf(
				"%s round trip failed: %q",
				tt.name,
				decrypted,
			)
		}
	}
}

func TestRejectInvalidCipherAndIV(t *testing.T) {
	if _, err := NewStreamCipher(
		"chacha20",
		"password",
	); err == nil {
		t.Fatal("expected unsupported cipher error")
	}

	c, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Encrypter(
		make([]byte, 15),
	); err == nil {
		t.Fatal("expected invalid IV error")
	}
}
