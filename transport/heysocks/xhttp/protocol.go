package xhttp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	fakePrefixSize = 128
	identitySize   = 16
)

func buildBootstrap(
	c *StreamCipher,
	network string,
	randReader io.Reader,
) (header []byte, iv []byte, err error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	fake := c.FakeNet(network)
	if len(fake) > fakePrefixSize {
		return nil, nil, fmt.Errorf(
			"xhttp: fake prefix too long: %d",
			len(fake),
		)
	}

	session := c.SessionBlob()
	if err := validateSessionBlob(session); err != nil {
		return nil, nil, err
	}

	ivSize := c.IVSize()

	headerLen :=
		fakePrefixSize +
			identitySize +
			len(session) +
			1 +
			ivSize

	header = make([]byte, headerLen)

	// Native order:
	//
	//   1. fake-net bytes
	//   2. random padding through byte 127
	//   3. identity
	//   4. session blob
	//   5. IV size
	//   6. random IV
	copy(header[:fakePrefixSize], fake)

	if _, err := io.ReadFull(
		randReader,
		header[len(fake):fakePrefixSize],
	); err != nil {
		return nil, nil, fmt.Errorf(
			"xhttp: generate fake prefix padding: %w",
			err,
		)
	}

	offset := fakePrefixSize

	identity := c.Identity()
	copy(header[offset:], identity[:])
	offset += identitySize

	copy(header[offset:], session)
	offset += len(session)

	header[offset] = byte(ivSize)
	offset++

	iv = make([]byte, ivSize)
	if _, err := io.ReadFull(randReader, iv); err != nil {
		return nil, nil, fmt.Errorf(
			"xhttp: generate IV: %w",
			err,
		)
	}

	copy(header[offset:], iv)

	return header, iv, nil
}

func parseBootstrap(
	r io.Reader,
	c *StreamCipher,
) ([]byte, error) {
	prefix := make([]byte, fakePrefixSize)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf(
			"xhttp: read fake prefix: %w",
			err,
		)
	}

	peerIdentity := make([]byte, identitySize)
	if _, err := io.ReadFull(r, peerIdentity); err != nil {
		return nil, fmt.Errorf(
			"xhttp: read identity: %w",
			err,
		)
	}

	localIdentity := c.Identity()
	if !bytes.Equal(peerIdentity, localIdentity[:]) {
		return nil, fmt.Errorf("xhttp: identity mismatch")
	}

	var nBuf [1]byte
	if _, err := io.ReadFull(r, nBuf[:]); err != nil {
		return nil, fmt.Errorf(
			"xhttp: read session length: %w",
			err,
		)
	}

	n := int(nBuf[0])

	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf(
			"xhttp: read session body: %w",
			err,
		)
	}

	session := make([]byte, n+1)
	session[0] = nBuf[0]
	copy(session[1:], body)

	if err := c.SetSessionBlob(session); err != nil {
		return nil, err
	}

	var ivSizeBuf [1]byte
	if _, err := io.ReadFull(r, ivSizeBuf[:]); err != nil {
		return nil, fmt.Errorf(
			"xhttp: read IV size: %w",
			err,
		)
	}

	// Native HeySocks trusts the advertised wire IV size at this
	// parsing step. Cipher creation below will reject an incompatible
	// IV length when appropriate.
	ivSize := int(ivSizeBuf[0])

	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, fmt.Errorf(
			"xhttp: read IV: %w",
			err,
		)
	}

	return iv, nil
}

// PackPacket implements the recovered native UDP framing:
//
// [128 fake/random]
// [16 identity MD5]
// [1 N]
// [N session bytes]
// [1 IV size]
// [IV]
// [encrypted payload]
func PackPacket(
	c *StreamCipher,
	payload []byte,
	randReader io.Reader,
) ([]byte, error) {
	header, iv, err := buildBootstrap(c, "udp", randReader)
	if err != nil {
		return nil, err
	}

	stream, err := c.Encrypter(iv)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(payload))
	stream.XORKeyStream(ciphertext, payload)

	packet := make([]byte, 0, len(header)+len(ciphertext))
	packet = append(packet, header...)
	packet = append(packet, ciphertext...)

	return packet, nil
}

// UnpackPacket verifies the identity field, synchronizes the peer
// session blob, and decrypts one native HeySocks XHTTP UDP datagram.
func UnpackPacket(
	c *StreamCipher,
	packet []byte,
) ([]byte, error) {
	if len(packet) < fakePrefixSize+identitySize+1+1 {
		return nil, fmt.Errorf(
			"xhttp: packet too short: %d",
			len(packet),
		)
	}

	offset := fakePrefixSize

	localIdentity := c.Identity()
	if !bytes.Equal(
		packet[offset:offset+identitySize],
		localIdentity[:],
	) {
		return nil, fmt.Errorf("xhttp: identity mismatch")
	}
	offset += identitySize

	n := int(packet[offset])
	offset++

	if len(packet) < offset+n+1 {
		return nil, fmt.Errorf(
			"xhttp: truncated session body",
		)
	}

	session := make([]byte, n+1)
	session[0] = byte(n)
	copy(session[1:], packet[offset:offset+n])
	offset += n

	if err := c.SetSessionBlob(session); err != nil {
		return nil, err
	}

	ivSize := int(packet[offset])
	offset++

	if len(packet) < offset+ivSize {
		return nil, fmt.Errorf("xhttp: truncated IV")
	}

	iv := packet[offset : offset+ivSize]
	offset += ivSize

	stream, err := c.Decrypter(iv)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(packet)-offset)
	stream.XORKeyStream(plaintext, packet[offset:])

	return plaintext, nil
}
