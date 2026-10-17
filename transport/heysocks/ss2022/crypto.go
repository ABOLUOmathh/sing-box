package heysocks2022

import (
	"crypto/aes"
	"crypto/cipher"

	"lukechampine.com/blake3"
)

const (
	subkeyCtxSession  = "shadowsocks 2022 session subkey"
	subkeyCtxIdentity = "shadowsocks 2022 identity subkey"
)

func deriveSubkey(psk, salt []byte, context string) []byte {
	keyMaterial := make([]byte, len(psk)+len(salt))
	copy(keyMaterial, psk)
	copy(keyMaterial[len(psk):], salt)

	key := make([]byte, len(psk))
	blake3.DeriveKey(key, context, keyMaterial)
	return key
}

func newAES(psk, salt []byte, context string) (cipher.Block, error) {
	return aes.NewCipher(deriveSubkey(psk, salt, context))
}

func newSessionCipher(psk, salt []byte) (*streamCipher, error) {
	block, err := newAES(psk, salt, subkeyCtxSession)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return newStreamCipher(aead), nil
}

func clientPSKHashes(identityPSKs [][]byte, masterPSK []byte) [][identityHeaderLength]byte {
	if len(identityPSKs) == 0 {
		return nil
	}

	hashes := make([][identityHeaderLength]byte, len(identityPSKs))

	for i := 1; i < len(identityPSKs); i++ {
		hash := blake3.Sum512(identityPSKs[i])
		copy(hashes[i-1][:], hash[:identityHeaderLength])
	}

	hash := blake3.Sum512(masterPSK)
	copy(hashes[len(hashes)-1][:], hash[:identityHeaderLength])

	return hashes
}

type streamCipher struct {
	aead  cipher.AEAD
	nonce []byte
}

func newStreamCipher(aead cipher.AEAD) *streamCipher {
	return &streamCipher{
		aead:  aead,
		nonce: make([]byte, aead.NonceSize()),
	}
}

func (c *streamCipher) overhead() int {
	return c.aead.Overhead()
}

func (c *streamCipher) seal(plaintext []byte) []byte {
	out := c.aead.Seal(nil, c.nonce, plaintext, nil)
	incrementNonce(c.nonce)
	return out
}

func (c *streamCipher) open(ciphertext []byte) ([]byte, error) {
	out, err := c.aead.Open(nil, c.nonce, ciphertext, nil)
	if err == nil {
		incrementNonce(c.nonce)
	}
	return out, err
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
