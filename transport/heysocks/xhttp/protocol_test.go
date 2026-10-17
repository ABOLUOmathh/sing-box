package xhttp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKDF(t *testing.T) {
	got, err := KDF("abc", 32)
	if err != nil {
		t.Fatal(err)
	}

	const wantHex = "900150983cd24fb0d6963f7d28e17f72" +
		"ea0b31e1087a22bc5394a6636e6ed34b"

	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"KDF mismatch:\n got=%x\nwant=%x",
			got,
			want,
		)
	}
}

func TestPasswordMaterial(t *testing.T) {
	c, err := NewStreamCipher(
		"aes-128-ctr",
		"abc:03010203",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	const wantIdentity = "3ce5f672516f9a2617c72634beffefb4"

	gotIdentity := c.Identity()

	if hex.EncodeToString(gotIdentity[:]) != wantIdentity {
		t.Fatalf(
			"identity mismatch: got=%x want=%s",
			gotIdentity,
			wantIdentity,
		)
	}

	wantSession := []byte{3, 1, 2, 3}

	if got := c.SessionBlob(); !bytes.Equal(got, wantSession) {
		t.Fatalf(
			"session mismatch: got=%x want=%x",
			got,
			wantSession,
		)
	}
}

func TestUDPPacketRoundTrip(t *testing.T) {
	c, err := NewStreamCipher(
		"aes-128-ctr",
		"abc:03010203",
		map[string]string{
			"udp": "aabbcc",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("heysocks-xhttp-stage15")

	randomBytes := bytes.Repeat([]byte{0x42}, 512)

	packet, err := PackPacket(
		c,
		payload,
		bytes.NewReader(randomBytes),
	)
	if err != nil {
		t.Fatal(err)
	}

	// fake-net prefix
	if !bytes.Equal(packet[:3], []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf(
			"fake-net prefix mismatch: %x",
			packet[:3],
		)
	}

	// 128 fake + 16 identity = session length byte
	if got := packet[144]; got != 3 {
		t.Fatalf(
			"session length byte = %d, want 3",
			got,
		)
	}

	if !bytes.Equal(
		packet[145:148],
		[]byte{1, 2, 3},
	) {
		t.Fatalf(
			"session body mismatch: %x",
			packet[145:148],
		)
	}

	// offset:
	// 128 + 16 + (1+3) = 148
	if got := packet[148]; got != 16 {
		t.Fatalf(
			"IV size = %d, want 16",
			got,
		)
	}

	plaintext, err := UnpackPacket(c, packet)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, payload) {
		t.Fatalf(
			"round trip mismatch:\n got=%q\nwant=%q",
			plaintext,
			payload,
		)
	}
}

func TestRejectMalformedSessionBlob(t *testing.T) {
	_, err := NewStreamCipher(
		"aes-128-ctr",
		"abc:05010203",
		nil,
	)

	if err == nil {
		t.Fatal("expected malformed session blob error")
	}
}
