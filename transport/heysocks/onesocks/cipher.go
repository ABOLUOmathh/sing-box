package onesocks

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
)

const (
	CipherAES128CTR = "AES-128-CTR"
	CipherAES192CTR = "AES-192-CTR"
	CipherAES256CTR = "AES-256-CTR"
)

type StreamCipher struct {
	key    []byte
	verify [16]byte
}

func NewStreamCipher(
	cipherName string,
	password string,
) (*StreamCipher, error) {
	var keyLen int

	switch strings.ToUpper(cipherName) {
	case CipherAES128CTR:
		keyLen = 16
	case CipherAES192CTR:
		keyLen = 24
	case CipherAES256CTR:
		keyLen = 32
	default:
		return nil, fmt.Errorf(
			"onesocks: unsupported cipher %q",
			cipherName,
		)
	}

	key, err := KDF(password, keyLen)
	if err != nil {
		return nil, err
	}

	return &StreamCipher{
		key:    key,
		verify: Verify16(password),
	}, nil
}

func (c *StreamCipher) Verify() [16]byte {
	return c.verify
}

func (c *StreamCipher) IVSize() int {
	return aes.BlockSize
}

func (c *StreamCipher) Encrypter(iv []byte) (cipher.Stream, error) {
	return c.newCTR(iv)
}

func (c *StreamCipher) Decrypter(iv []byte) (cipher.Stream, error) {
	return c.newCTR(iv)
}

func (c *StreamCipher) newCTR(iv []byte) (cipher.Stream, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf(
			"onesocks: invalid AES-CTR IV length %d, want %d",
			len(iv),
			aes.BlockSize,
		)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf(
			"onesocks: create AES cipher: %w",
			err,
		)
	}

	return cipher.NewCTR(block, iv), nil
}
