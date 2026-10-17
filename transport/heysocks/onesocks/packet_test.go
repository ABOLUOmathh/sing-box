package onesocks

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type packetTestConn struct {
	readPacket []byte
	readAddr   net.Addr

	wrote     []byte
	writeAddr net.Addr
}

func (c *packetTestConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	n := copy(
		p,
		c.readPacket,
	)

	return n, c.readAddr, nil
}

func (c *packetTestConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	c.wrote = append(
		c.wrote[:0],
		p...,
	)
	c.writeAddr = addr

	return len(p), nil
}

func (c *packetTestConn) Close() error {
	return nil
}

func (c *packetTestConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *packetTestConn) SetDeadline(
	time.Time,
) error {
	return nil
}

func (c *packetTestConn) SetReadDeadline(
	time.Time,
) error {
	return nil
}

func (c *packetTestConn) SetWriteDeadline(
	time.Time,
) error {
	return nil
}

func TestPackPacketNativeLayout(
	t *testing.T,
) {
	streamCipher, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	padding := []byte{
		0xa1,
		0xa2,
		0xa3,
	}

	iv := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}

	randomMaterial := append(
		append(
			[]byte(nil),
			padding...,
		),
		iv...,
	)

	plaintext := []byte(
		"onesocks native udp",
	)

	packet, err := PackPacket(
		streamCipher,
		plaintext,
		len(padding),
		bytes.NewReader(
			randomMaterial,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	if packet[0] != protocolVersion {
		t.Fatalf(
			"version = %#x, want %#x",
			packet[0],
			protocolVersion,
		)
	}

	if packet[1] != byte(len(padding)) {
		t.Fatalf(
			"padding length = %d, want %d",
			packet[1],
			len(padding),
		)
	}

	if !bytes.Equal(
		packet[2:2+len(padding)],
		padding,
	) {
		t.Fatalf(
			"padding mismatch: %x",
			packet[2:2+len(padding)],
		)
	}

	verify := streamCipher.Verify()

	verifyStart :=
		2 + len(padding)
	verifyEnd :=
		verifyStart + len(verify)

	if !bytes.Equal(
		packet[verifyStart:verifyEnd],
		verify[:],
	) {
		t.Fatalf(
			"verify mismatch: %x",
			packet[verifyStart:verifyEnd],
		)
	}

	if packet[verifyEnd] !=
		byte(streamCipher.IVSize()) {
		t.Fatalf(
			"IV size = %d, want %d",
			packet[verifyEnd],
			streamCipher.IVSize(),
		)
	}

	ivStart := verifyEnd + 1
	ivEnd :=
		ivStart +
			streamCipher.IVSize()

	if !bytes.Equal(
		packet[ivStart:ivEnd],
		iv,
	) {
		t.Fatalf(
			"IV mismatch: %x",
			packet[ivStart:ivEnd],
		)
	}

	gotPacket := append(
		[]byte(nil),
		packet...,
	)

	got, err := UnpackPacket(
		streamCipher,
		gotPacket,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		got,
		plaintext,
	) {
		t.Fatalf(
			"plaintext = %x, want %x",
			got,
			plaintext,
		)
	}
}

func TestUnpackPacketRejectsBadVerify(
	t *testing.T,
) {
	streamCipher, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	packet, err := PackPacket(
		streamCipher,
		[]byte("payload"),
		0,
		bytes.NewReader(
			bytes.Repeat(
				[]byte{0x11},
				streamCipher.IVSize(),
			),
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	packet[2] ^= 0xff

	if _, err := UnpackPacket(
		streamCipher,
		packet,
	); err == nil {
		t.Fatal(
			"expected verification error",
		)
	}
}

func TestPacketConnNativeRoundTrip(
	t *testing.T,
) {
	streamCipher, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 443,
	}

	base := &packetTestConn{}

	randomMaterial := bytes.Repeat(
		[]byte{0x42},
		64,
	)

	conn, err := newPacketConnWithRand(
		base,
		streamCipher,
		2,
		bytes.NewReader(
			randomMaterial,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte{
		0x01,
		1, 1, 1, 1,
		0x00, 0x35,
		0xde, 0xad, 0xbe, 0xef,
	}

	n, err := conn.WriteTo(
		plaintext,
		proxyAddr,
	)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(plaintext) {
		t.Fatalf(
			"WriteTo n = %d, want %d",
			n,
			len(plaintext),
		)
	}

	if base.writeAddr != proxyAddr {
		t.Fatalf(
			"WriteTo addr = %v, want %v",
			base.writeAddr,
			proxyAddr,
		)
	}

	packed := append(
		[]byte(nil),
		base.wrote...,
	)

	unpacked, err := UnpackPacket(
		streamCipher,
		packed,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		unpacked,
		plaintext,
	) {
		t.Fatalf(
			"WriteTo plaintext = %x, want %x",
			unpacked,
			plaintext,
		)
	}

	readPacked, err := PackPacket(
		streamCipher,
		plaintext,
		2,
		bytes.NewReader(
			bytes.Repeat(
				[]byte{0x24},
				64,
			),
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	base.readPacket = readPacked
	base.readAddr = proxyAddr

	buf := make(
		[]byte,
		len(readPacked)+32,
	)

	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(plaintext) {
		t.Fatalf(
			"ReadFrom n = %d, want %d",
			n,
			len(plaintext),
		)
	}

	if addr != proxyAddr {
		t.Fatalf(
			"ReadFrom addr = %v, want %v",
			addr,
			proxyAddr,
		)
	}

	if !bytes.Equal(
		buf[:n],
		plaintext,
	) {
		t.Fatalf(
			"ReadFrom plaintext = %x, want %x",
			buf[:n],
			plaintext,
		)
	}
}

func TestNewPacketConnValidation(
	t *testing.T,
) {
	streamCipher, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	base := &packetTestConn{}

	if _, err := NewPacketConn(
		nil,
		streamCipher,
		0,
	); err == nil {
		t.Fatal(
			"expected nil connection error",
		)
	}

	if _, err := NewPacketConn(
		base,
		nil,
		0,
	); err == nil {
		t.Fatal(
			"expected nil cipher error",
		)
	}

	if _, err := NewPacketConn(
		base,
		streamCipher,
		256,
	); err == nil {
		t.Fatal(
			"expected padding length error",
		)
	}
}
