package heysocks_xhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	xhttp "github.com/sagernet/sing-box/transport/heysocks/xhttp"
	M "github.com/sagernet/sing/common/metadata"
)

func TestHeySocksXHTTPOutboundTCP(t *testing.T) {
	const password = "testkey:03010203"
	const cipherName = "AES-128-CTR"

	outboundInstance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test-xhttp", option.HeySocksXHTTPOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 8888,
		},
		Password: password,
		Cipher:   cipherName,
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

	dst := M.ParseSocksaddr("93.184.216.34:80")
	var destBuf bytes.Buffer
	destBuf.Grow(M.SocksaddrSerializer.AddrPortLen(dst))
	if err := M.SocksaddrSerializer.WriteAddrPort(&destBuf, dst); err != nil {
		t.Fatalf("serialize destination: %v", err)
	}

	// Create client stream
	clientStream := xhttp.NewConn(clientSide, out.cipher, destBuf.Bytes())

	writeDone := make(chan error, 1)
	go func() {
		// First flight writes destination via Write(nil)
		if _, err := clientStream.Write(nil); err != nil {
			writeDone <- err
			return
		}
		_, err := clientStream.Write([]byte("ping"))
		writeDone <- err
	}()

	// Server side reads bootstrap header:
	// 128 fake/padding + 16 identity + sessionLen(1) + sessionBody + 1 IV size + IV(16)
	session := out.cipher.SessionBlob()
	headerLen := 128 + 16 + len(session) + 1 + 16
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(serverSide, hdr); err != nil {
		t.Fatalf("server read bootstrap header: %v", err)
	}

	iv := hdr[headerLen-16:]
	decrypter, err := out.cipher.Decrypter(iv)
	if err != nil {
		t.Fatalf("server decrypter: %v", err)
	}

	// Read encrypted destination + "ping"
	encryptedPayload := make([]byte, destBuf.Len()+4)
	if _, err := io.ReadFull(serverSide, encryptedPayload); err != nil {
		t.Fatalf("server read encrypted payload: %v", err)
	}

	decryptedPayload := make([]byte, len(encryptedPayload))
	decrypter.XORKeyStream(decryptedPayload, encryptedPayload)

	if !bytes.Equal(decryptedPayload[:destBuf.Len()], destBuf.Bytes()) {
		t.Fatalf("destination mismatch: got %x, want %x", decryptedPayload[:destBuf.Len()], destBuf.Bytes())
	}
	if string(decryptedPayload[destBuf.Len():]) != "ping" {
		t.Fatalf("payload mismatch: got %s, want ping", string(decryptedPayload[destBuf.Len():]))
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("client write failed: %v", err)
	}
}

func TestHeySocksXHTTPOutboundValidation(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.HeySocksXHTTPOptions{
		Password: "",
	})
	if err == nil {
		t.Fatal("expected error for empty password, got nil")
	}

	_, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.HeySocksXHTTPOptions{
		Password: "secret",
		Cipher:   "invalid-cipher",
	})
	if err == nil {
		t.Fatal("expected error for invalid cipher, got nil")
	}
}
