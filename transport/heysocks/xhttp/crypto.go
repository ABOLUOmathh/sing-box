package xhttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec G501 -- required for HeySocks protocol compatibility
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

const (
	CipherAES128CTR = "AES-128-CTR"

	identityFormat = "%sdo not hack this protocol please"
)

// StreamCipher contains the state recovered from the HeySocks native
// xhttp StreamCipher implementation.
//
// MD5 and AES-CTR are used here strictly for wire compatibility with
// the existing protocol, not as a new cryptographic design.
type StreamCipher struct {
	key      []byte
	identity [md5.Size]byte

	mu          sync.RWMutex
	sessionBlob []byte

	fakeNet map[string][]byte
}

// KDF implements the native HeySocks XHTTP key derivation:
//
// D1 = MD5(password)
// D2 = MD5(D1 || password)
// D3 = MD5(D2 || password)
// ...
//
// Digests are concatenated until keyLen bytes are available.
func KDF(password string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("xhttp: invalid key length %d", keyLen)
	}

	out := make([]byte, 0, keyLen)
	var previous []byte

	for len(out) < keyLen {
		h := md5.New() // #nosec G401 -- protocol compatibility

		if len(previous) != 0 {
			_, _ = h.Write(previous)
		}

		_, _ = h.Write([]byte(password))

		previous = h.Sum(nil)
		out = append(out, previous...)
	}

	key := make([]byte, keyLen)
	copy(key, out[:keyLen])

	return key, nil
}

func NewStreamCipher(
	cipherName string,
	password string,
	fakeNet map[string]string,
) (*StreamCipher, error) {
	switch strings.ToUpper(cipherName) {
	case CipherAES128CTR:
	default:
		return nil, fmt.Errorf(
			"xhttp: unsupported cipher %q",
			cipherName,
		)
	}

	parts := strings.Split(password, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf(
			"xhttp: password must contain key:session",
		)
	}

	keyText := parts[0]
	sessionText := parts[1]

	if keyText == "" {
		return nil, fmt.Errorf("xhttp: empty password key part")
	}
	if sessionText == "" {
		return nil, fmt.Errorf("xhttp: empty password session part")
	}

	key, err := KDF(keyText, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	sessionBlob, err := hex.DecodeString(sessionText)
	if err != nil {
		return nil, fmt.Errorf(
			"xhttp: decode session blob: %w",
			err,
		)
	}

	if err := validateSessionBlob(sessionBlob); err != nil {
		return nil, err
	}

	identity := md5.Sum( // #nosec G401 -- protocol compatibility
		[]byte(fmt.Sprintf(identityFormat, keyText)),
	)

	decodedFakeNet := make(map[string][]byte, len(fakeNet))
	for network, encoded := range fakeNet {
		if encoded == "" {
			continue
		}

		value, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf(
				"xhttp: decode fake-net[%q]: %w",
				network,
				err,
			)
		}

		if len(value) > fakePrefixSize {
			return nil, fmt.Errorf(
				"xhttp: fake-net[%q] is %d bytes, max %d",
				network,
				len(value),
				fakePrefixSize,
			)
		}

		decodedFakeNet[network] = value
	}

	return &StreamCipher{
		key:         key,
		identity:    identity,
		sessionBlob: append([]byte(nil), sessionBlob...),
		fakeNet:     decodedFakeNet,
	}, nil
}

func (c *StreamCipher) IVSize() int {
	return aes.BlockSize
}

func (c *StreamCipher) Identity() [md5.Size]byte {
	return c.identity
}

func (c *StreamCipher) SessionBlob() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return append([]byte(nil), c.sessionBlob...)
}

func (c *StreamCipher) SetSessionBlob(blob []byte) error {
	if err := validateSessionBlob(blob); err != nil {
		return err
	}

	c.mu.Lock()
	c.sessionBlob = append(c.sessionBlob[:0], blob...)
	c.mu.Unlock()

	return nil
}

func (c *StreamCipher) FakeNet(network string) []byte {
	value := c.fakeNet[network]
	return append([]byte(nil), value...)
}

func (c *StreamCipher) Encrypter(iv []byte) (cipher.Stream, error) {
	return c.newCTR(iv)
}

func (c *StreamCipher) Decrypter(iv []byte) (cipher.Stream, error) {
	// CTR encryption and decryption are the same XOR operation.
	return c.newCTR(iv)
}

func (c *StreamCipher) newCTR(iv []byte) (cipher.Stream, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf(
			"xhttp: invalid AES-CTR IV length %d, want %d",
			len(iv),
			aes.BlockSize,
		)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("xhttp: create AES cipher: %w", err)
	}

	return cipher.NewCTR(block, iv), nil
}

func validateSessionBlob(blob []byte) error {
	if len(blob) < 1 {
		return fmt.Errorf("xhttp: empty session blob")
	}

	declared := int(blob[0])
	actual := len(blob) - 1

	if declared != actual {
		return fmt.Errorf(
			"xhttp: malformed session blob: declared=%d actual=%d",
			declared,
			actual,
		)
	}

	return nil
}
