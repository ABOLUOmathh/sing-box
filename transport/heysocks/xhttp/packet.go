package xhttp

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

// PacketConn implements the native HeySocks XHTTP UDP data path.
//
// Each datagram is independently framed as:
//
// [128 fake/random]
// [16 identity]
// [1 session length]
// [N session body]
// [1 IV size]
// [IV]
// [ciphertext]
//
// The destination net.Addr itself is not encoded by this layer.
// It is passed unchanged to the underlying net.PacketConn.
type PacketConn struct {
	net.PacketConn

	cipher     *StreamCipher
	randReader io.Reader

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewPacketConn(
	conn net.PacketConn,
	c *StreamCipher,
) *PacketConn {
	return newPacketConnWithRand(
		conn,
		c,
		rand.Reader,
	)
}

func newPacketConnWithRand(
	conn net.PacketConn,
	c *StreamCipher,
	randReader io.Reader,
) *PacketConn {
	if randReader == nil {
		randReader = rand.Reader
	}

	return &PacketConn{
		PacketConn: conn,
		cipher:     c,
		randReader: randReader,
	}
}

// WriteTo mirrors the recovered native PacketConn.WriteTo behavior.
//
// The underlying connection receives the packed datagram, while the
// caller sees the length of the original plaintext payload.
func (c *PacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	packet, err := PackPacket(
		c.cipher,
		p,
		c.randReader,
	)
	if err != nil {
		return 0, err
	}

	n, err := c.PacketConn.WriteTo(packet, addr)
	if err != nil {
		return 0, err
	}

	if n != len(packet) {
		return 0, fmt.Errorf(
			"xhttp: short UDP write: wrote=%d want=%d",
			n,
			len(packet),
		)
	}

	// Native returns original plaintext length rather than packed size.
	return len(p), nil
}

// ReadFrom mirrors the recovered native PacketConn.ReadFrom path:
//
// underlying ReadFrom(p)
//
//	↓
//
// Unpack(p[:n])
//
//	↓
//
// copy plaintext to the beginning of p
//
// On an unpack failure, the native implementation returns the
// original packed length/address together with the unpack error.
func (c *PacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	n, addr, err := c.PacketConn.ReadFrom(p)
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

	copy(p, plaintext)

	return len(plaintext), addr, nil
}
