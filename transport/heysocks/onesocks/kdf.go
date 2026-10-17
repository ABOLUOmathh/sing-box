package onesocks

import (
	"crypto/md5" // #nosec G501 -- required for OneSocks wire compatibility
	"fmt"
)

const verifySuffix = "_onesocks"

// KDF implements the native OneSocks MD5 key derivation:
//
// D1 = MD5(password)
// D2 = MD5(D1 || password)
// D3 = MD5(D2 || password)
// ...
//
// Digests are concatenated until keyLen bytes are available.
func KDF(password string, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("onesocks: invalid key length %d", keyLen)
	}

	out := make([]byte, 0, keyLen)
	var previous []byte
	passwordBytes := []byte(password)

	for len(out) < keyLen {
		h := md5.New() // #nosec G401 -- protocol compatibility

		if len(previous) != 0 {
			_, _ = h.Write(previous)
		}

		_, _ = h.Write(passwordBytes)

		previous = h.Sum(nil)
		out = append(out, previous...)
	}

	key := make([]byte, keyLen)
	copy(key, out[:keyLen])

	return key, nil
}

// Verify16 returns the raw 16-byte native OneSocks verification digest:
//
// MD5(password + "_onesocks")
func Verify16(password string) [md5.Size]byte {
	return md5.Sum( // #nosec G401 -- protocol compatibility
		[]byte(password + verifySuffix),
	)
}
