package heysocks2022

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	MethodAES128GCM  = "2022-blake3-aes-128-gcm"
	BlackstoneSuffix = "#BLACKSTONE"
)

func NormalizePassword(methodName, password string) (normalized string, blackstone bool, err error) {
	if !strings.HasSuffix(password, BlackstoneSuffix) {
		return password, false, nil
	}

	if methodName != MethodAES128GCM {
		return "", false, fmt.Errorf(
			"heysocks ss2022: %s marker is only supported with %s",
			BlackstoneSuffix,
			MethodAES128GCM,
		)
	}

	normalized = strings.TrimSuffix(password, BlackstoneSuffix)
	if normalized == "" {
		return "", false, fmt.Errorf("heysocks ss2022: empty password before %s marker", BlackstoneSuffix)
	}

	return normalized, true, nil
}

type Method struct {
	psk          []byte
	identityPSKs [][]byte
	eihPSKHashes [][identityHeaderLength]byte

	randReader io.Reader
	timeFunc   func() time.Time
}

func New(methodName, password string) (*Method, error) {
	if methodName != MethodAES128GCM {
		return nil, fmt.Errorf("heysocks ss2022: unsupported cipher %q in stage1", methodName)
	}

	parts := strings.Split(password, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("heysocks ss2022: password must contain at least identityPSK:masterPSK")
	}

	keys := make([][]byte, 0, len(parts))
	for i, part := range parts {
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("heysocks ss2022: password component %d is not strict Base64: %w", i, err)
		}
		if len(key) != 16 {
			return nil, fmt.Errorf("heysocks ss2022: password component %d decoded to %d bytes, want 16", i, len(key))
		}
		keys = append(keys, key)
	}

	master := append([]byte(nil), keys[len(keys)-1]...)
	identities := make([][]byte, len(keys)-1)
	for i := range identities {
		identities[i] = append([]byte(nil), keys[i]...)
	}

	return &Method{
		psk:          master,
		identityPSKs: identities,
		eihPSKHashes: clientPSKHashes(identities, master),
		randReader:   rand.Reader,
		timeFunc:     time.Now,
	}, nil
}

func (m *Method) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	c := newClientConn(conn, destination, m)
	if _, err := c.ensureHandshake(nil); err != nil {
		return nil, err
	}
	return c, nil
}

func (m *Method) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return newClientConn(conn, destination, m)
}
