package onesocks

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

// PacketConn implements the recovered native OneSocks UDP encryption layer.
//
// Each UDP datagram is independently framed as:
//
// [1 protocol version]
// [1 padding length]
// [P random padding]
// [16 verify]
// [1 IV size]
// [IV]
// [AES-CTR ciphertext]
//
// The plaintext encrypted by this layer is supplied unchanged by the caller.
// In the native OneSocks adapter that plaintext is:
//
// SOCKS_ADDR(destination) || UDP payload
//
// Destination-address encoding itself intentionally does not belong here.
type PacketConn struct {
	net.PacketConn

	cipher     *StreamCipher
	paddingLen int
	randReader io.Reader

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewPacketConn wraps a UDP PacketConn with native OneSocks datagram
// encryption.
func NewPacketConn(
	conn net.PacketConn,
	streamCipher *StreamCipher,
	paddingLen int,
) (*PacketConn, error) {
	return newPacketConnWithRand(
		conn,
		streamCipher,
		paddingLen,
		rand.Reader,
	)
}

func newPacketConnWithRand(
	conn net.PacketConn,
	streamCipher *StreamCipher,
	paddingLen int,
	randReader io.Reader,
) (*PacketConn, error) {
	if conn == nil {
		return nil, fmt.Errorf(
			"onesocks: nil packet connection",
		)
	}

	if streamCipher == nil {
		return nil, fmt.Errorf(
			"onesocks: nil stream cipher",
		)
	}

	if paddingLen < 0 || paddingLen > 255 {
		return nil, fmt.Errorf(
			"onesocks: invalid UDP padding length %d",
			paddingLen,
		)
	}

	if randReader == nil {
		randReader = rand.Reader
	}

	return &PacketConn{
		PacketConn: conn,
		cipher:     streamCipher,
		paddingLen: paddingLen,
		randReader: randReader,
	}, nil
}

// PackPacket builds one native OneSocks UDP datagram.
//
// A fresh IV is generated for every packet. CTR state is therefore not shared
// between UDP datagrams.
func PackPacket(
	streamCipher *StreamCipher,
	plaintext []byte,
	paddingLen int,
	randReader io.Reader,
) ([]byte, error) {
	if streamCipher == nil {
		return nil, fmt.Errorf(
			"onesocks: nil stream cipher",
		)
	}

	if paddingLen < 0 || paddingLen > 255 {
		return nil, fmt.Errorf(
			"onesocks: invalid UDP padding length %d",
			paddingLen,
		)
	}

	if randReader == nil {
		randReader = rand.Reader
	}

	padding := make([]byte, paddingLen)

	if _, err := io.ReadFull(
		randReader,
		padding,
	); err != nil {
		return nil, fmt.Errorf(
			"onesocks: generate UDP padding: %w",
			err,
		)
	}

	ivSize := streamCipher.IVSize()
	if ivSize <= 0 || ivSize > 255 {
		return nil, fmt.Errorf(
			"onesocks: invalid UDP IV size %d",
			ivSize,
		)
	}

	iv := make([]byte, ivSize)

	if _, err := io.ReadFull(
		randReader,
		iv,
	); err != nil {
		return nil, fmt.Errorf(
			"onesocks: generate UDP IV: %w",
			err,
		)
	}

	encrypter, err :=
		streamCipher.Encrypter(iv)
	if err != nil {
		return nil, fmt.Errorf(
			"onesocks: create UDP encrypter: %w",
			err,
		)
	}

	verify := streamCipher.Verify()

	headerLen :=
		2 +
			paddingLen +
			len(verify) +
			1 +
			ivSize

	packet := make(
		[]byte,
		headerLen+len(plaintext),
	)

	packet[0] = protocolVersion
	packet[1] = byte(paddingLen)

	offset := 2

	copy(
		packet[offset:],
		padding,
	)
	offset += paddingLen

	copy(
		packet[offset:],
		verify[:],
	)
	offset += len(verify)

	packet[offset] = byte(ivSize)
	offset++

	copy(
		packet[offset:],
		iv,
	)
	offset += ivSize

	encrypter.XORKeyStream(
		packet[offset:],
		plaintext,
	)

	return packet, nil
}

// UnpackPacket removes one native OneSocks UDP frame.
//
// Native OneSocks does not visibly validate packet[0] in the recovered
// Unpack path. The second byte supplies the padding length.
//
// The returned plaintext aliases packet and begins after the OneSocks UDP
// header.
func UnpackPacket(
	streamCipher *StreamCipher,
	packet []byte,
) ([]byte, error) {
	if streamCipher == nil {
		return nil, fmt.Errorf(
			"onesocks: nil stream cipher",
		)
	}

	if len(packet) < 2 {
		return nil, fmt.Errorf(
			"onesocks: UDP packet too short",
		)
	}

	paddingLen := int(packet[1])

	verifyStart := 2 + paddingLen
	verifyEnd := verifyStart + 16

	if verifyEnd >= len(packet) {
		return nil, fmt.Errorf(
			"onesocks: truncated UDP verification header",
		)
	}

	verify := streamCipher.Verify()

	if !bytes.Equal(
		packet[verifyStart:verifyEnd],
		verify[:],
	) {
		return nil, fmt.Errorf(
			"onesocks: UDP verification mismatch",
		)
	}

	ivSizeOffset := verifyEnd
	ivSize := int(packet[ivSizeOffset])

	ivStart := ivSizeOffset + 1
	ivEnd := ivStart + ivSize

	if ivEnd > len(packet) {
		return nil, fmt.Errorf(
			"onesocks: truncated UDP IV",
		)
	}

	decrypter, err :=
		streamCipher.Decrypter(
			packet[ivStart:ivEnd],
		)
	if err != nil {
		return nil, fmt.Errorf(
			"onesocks: create UDP decrypter: %w",
			err,
		)
	}

	plaintext := packet[ivEnd:]

	decrypter.XORKeyStream(
		plaintext,
		plaintext,
	)

	return plaintext, nil
}

// WriteTo encrypts one complete native OneSocks UDP datagram.
//
// The underlying PacketConn receives the framed/encrypted packet, while the
// caller receives the original plaintext length.
func (c *PacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	packet, err := PackPacket(
		c.cipher,
		p,
		c.paddingLen,
		c.randReader,
	)
	if err != nil {
		return 0, err
	}

	n, err := c.PacketConn.WriteTo(
		packet,
		addr,
	)
	if err != nil {
		return 0, err
	}

	if n != len(packet) {
		return 0, fmt.Errorf(
			"onesocks: short UDP write: wrote=%d want=%d",
			n,
			len(packet),
		)
	}

	return len(p), nil
}

// ReadFrom decrypts one complete native OneSocks UDP datagram.
//
// On an unpack failure this mirrors the recovered native behavior by
// preserving the packed length and underlying address in the return values.
func (c *PacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	n, addr, err :=
		c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	plaintext, err := UnpackPacket(
		c.cipher,
		p[:n],
	)
	if err != nil {
		return n, addr, err
	}

	copy(
		p,
		plaintext,
	)

	return len(plaintext), addr, nil
}
