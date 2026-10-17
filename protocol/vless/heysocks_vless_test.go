package vless

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type heySocksWriteResult struct {
	n   int
	err error
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}

func TestHeySocksVLESSWireFormat(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"
	const hHex = "03aabbcc"

	outboundInstance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test-vless", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		UUID: uuidStr,
		E:    true,
		H:    hHex,
	})
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	out := outboundInstance.(*Outbound)

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	deadline := time.Now().Add(5 * time.Second)
	clientSide.SetDeadline(deadline)
	serverSide.SetDeadline(deadline)

	dst := M.ParseSocksaddr("1.2.3.4:443")
	heysocksConn := NewHeySocksConn(clientSide, out.heysocksClient, out.rawUUID)
	conn, err := out.client.DialEarlyConn(heysocksConn, dst)
	if err != nil {
		t.Fatalf("DialEarlyConn failed: %v", err)
	}

	rawUUID := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	sum := md5.Sum(rawUUID)

	want := mustDecodeHex(t,
		"00"+ // version
			"00112233445566778899aabbccddeeff"+ // uuid
			"00"+ // addon len
			"01"+ // tcp
			"01bb"+ // port 443
			"01"+ // ipv4
			"01020304", // 1.2.3.4
	)
	want = append(want, sum[:]...)
	want = append(want, mustDecodeHex(t, hHex)...)
	want = append(want, []byte("hello")...)

	writeCh := make(chan heySocksWriteResult, 1)
	go func() {
		n, err := conn.Write([]byte("hello"))
		writeCh <- heySocksWriteResult{n: n, err: err}
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverSide, got); err != nil {
		t.Fatalf("ReadFull request failed: %v", err)
	}

	wr := <-writeCh
	if wr.err != nil {
		t.Fatalf("Write failed: %v", wr.err)
	}
	if wr.n != len("hello") {
		t.Fatalf("Write returned n=%d, want %d", wr.n, len("hello"))
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("HeySocks VLESS wire mismatch:\n got  %x\n want %x", got, want)
	}

	// Now test response handling with dynamic H update
	respBytes := []byte{
		0x00,       // response version
		0x00,       // addon length
		0x03,       // hLen = 3
		0xdd, 0xee, 0xff, // new token bytes
		'w', 'o', 'r', 'l', 'd', // response payload
	}

	go func() {
		serverSide.Write(respBytes)
	}()

	readBuf := make([]byte, 5)
	n, err := io.ReadFull(conn, readBuf)
	if err != nil {
		t.Fatalf("conn Read failed: %v", err)
	}
	if n != 5 || string(readBuf) != "world" {
		t.Fatalf("unexpected payload read: %q", string(readBuf[:n]))
	}

	// Verify that H token was dynamically updated thread-safely
	_, newH := out.heysocksClient.snapshot()
	expectedH := []byte{0x03, 0xdd, 0xee, 0xff}
	if !bytes.Equal(newH, expectedH) {
		t.Fatalf("H token not updated correctly: got %x, want %x", newH, expectedH)
	}
}

func TestHeySocksVLESSInvalidH(t *testing.T) {
	_, err := NewHeySocksClient(false, "zz")
	if err == nil {
		t.Fatal("expected error for invalid hex H, got nil")
	}
}
