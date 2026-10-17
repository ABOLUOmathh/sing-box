package xhttp

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

type testPacketDatagram struct {
	data []byte
	from net.Addr
}

type testPacketConn struct {
	local net.Addr

	in  <-chan testPacketDatagram
	out chan<- testPacketDatagram

	mu           sync.Mutex
	lastWriteTo  net.Addr
	lastWriteLen int
}

func newTestPacketPipe() (
	*testPacketConn,
	*testPacketConn,
) {
	aToB := make(chan testPacketDatagram, 8)
	bToA := make(chan testPacketDatagram, 8)

	a := &testPacketConn{
		local: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 10001,
		},
		in:  bToA,
		out: aToB,
	}

	b := &testPacketConn{
		local: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 10002,
		},
		in:  aToB,
		out: bToA,
	}

	return a, b
}

func (c *testPacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	d := <-c.in

	n := copy(p, d.data)

	return n, d.from, nil
}

func (c *testPacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	cp := append([]byte(nil), p...)

	c.mu.Lock()
	c.lastWriteTo = addr
	c.lastWriteLen = len(cp)
	c.mu.Unlock()

	c.out <- testPacketDatagram{
		data: cp,
		from: c.local,
	}

	return len(cp), nil
}

func (c *testPacketConn) Close() error {
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr {
	return c.local
}

func (c *testPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *testPacketConn) writeInfo() (net.Addr, int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.lastWriteTo, c.lastWriteLen
}

func newPacketTestCipher(
	t *testing.T,
	password string,
) *StreamCipher {
	t.Helper()

	c, err := NewStreamCipher(
		"aes-128-ctr",
		password,
		map[string]string{
			"udp": "aabbcc",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func TestNativeUDPPacketConnRoundTrip(t *testing.T) {
	rawA, rawB := newTestPacketPipe()

	cipherA := newPacketTestCipher(
		t,
		"abc:03010203",
	)

	// Deliberately start B with a different session blob.
	// Receiving A's packet must synchronize B to A's blob.
	cipherB := newPacketTestCipher(
		t,
		"abc:0109",
	)

	a := newPacketConnWithRand(
		rawA,
		cipherA,
		bytes.NewReader(
			bytes.Repeat([]byte{0x11}, 4096),
		),
	)

	b := newPacketConnWithRand(
		rawB,
		cipherB,
		bytes.NewReader(
			bytes.Repeat([]byte{0x22}, 4096),
		),
	)

	payload := []byte(
		"heysocks-xhttp-native-udp",
	)

	serverAddr := &net.UDPAddr{
		IP:   net.IPv4(203, 0, 113, 10),
		Port: 443,
	}

	n, err := a.WriteTo(payload, serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	// Native wrapper reports plaintext length.
	if n != len(payload) {
		t.Fatalf(
			"WriteTo length=%d want=%d",
			n,
			len(payload),
		)
	}

	wireAddr, wireLen := rawA.writeInfo()

	if wireAddr.String() != serverAddr.String() {
		t.Fatalf(
			"underlying destination=%v want=%v",
			wireAddr,
			serverAddr,
		)
	}

	if wireLen <= len(payload) {
		t.Fatalf(
			"wire datagram not framed: wire=%d plaintext=%d",
			wireLen,
			len(payload),
		)
	}

	buf := make([]byte, 2048)

	gotN, from, err := b.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf[:gotN], payload) {
		t.Fatalf(
			"payload mismatch:\n got=%q\nwant=%q",
			buf[:gotN],
			payload,
		)
	}

	if from.String() != rawA.LocalAddr().String() {
		t.Fatalf(
			"source addr=%v want=%v",
			from,
			rawA.LocalAddr(),
		)
	}

	// Peer-provided session state must now be synchronized.
	if got := cipherB.SessionBlob(); !bytes.Equal(
		got,
		[]byte{3, 1, 2, 3},
	) {
		t.Fatalf(
			"session synchronization mismatch: %x",
			got,
		)
	}
}

func TestNativeUDPPacketConnBidirectional(t *testing.T) {
	rawA, rawB := newTestPacketPipe()

	a := newPacketConnWithRand(
		rawA,
		newPacketTestCipher(
			t,
			"abc:020102",
		),
		bytes.NewReader(
			bytes.Repeat([]byte{0x33}, 4096),
		),
	)

	b := newPacketConnWithRand(
		rawB,
		newPacketTestCipher(
			t,
			"abc:020304",
		),
		bytes.NewReader(
			bytes.Repeat([]byte{0x44}, 4096),
		),
	)

	aToB := []byte("a-to-b")
	bToA := []byte("b-to-a")

	if _, err := a.WriteTo(
		aToB,
		rawB.LocalAddr(),
	); err != nil {
		t.Fatal(err)
	}

	bufB := make([]byte, 2048)

	nB, _, err := b.ReadFrom(bufB)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bufB[:nB], aToB) {
		t.Fatalf(
			"A->B mismatch: got=%q want=%q",
			bufB[:nB],
			aToB,
		)
	}

	if _, err := b.WriteTo(
		bToA,
		rawA.LocalAddr(),
	); err != nil {
		t.Fatal(err)
	}

	bufA := make([]byte, 2048)

	nA, _, err := a.ReadFrom(bufA)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bufA[:nA], bToA) {
		t.Fatalf(
			"B->A mismatch: got=%q want=%q",
			bufA[:nA],
			bToA,
		)
	}
}

func TestNativeUDPPacketConnRejectsWrongIdentity(t *testing.T) {
	rawA, rawB := newTestPacketPipe()

	a := newPacketConnWithRand(
		rawA,
		newPacketTestCipher(
			t,
			"abc:0101",
		),
		bytes.NewReader(
			bytes.Repeat([]byte{0x55}, 4096),
		),
	)

	// Different key part => different identity MD5.
	b := newPacketConnWithRand(
		rawB,
		newPacketTestCipher(
			t,
			"different-key:0101",
		),
		bytes.NewReader(
			bytes.Repeat([]byte{0x66}, 4096),
		),
	)

	payload := []byte("identity-check")

	if _, err := a.WriteTo(
		payload,
		rawB.LocalAddr(),
	); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)

	n, _, err := b.ReadFrom(buf)

	if err == nil {
		t.Fatal("expected identity mismatch")
	}

	// Native ReadFrom exposes the packed datagram length on
	// Unpack failure.
	if n <= len(payload) {
		t.Fatalf(
			"error path length=%d, expected packed length > %d",
			n,
			len(payload),
		)
	}
}
