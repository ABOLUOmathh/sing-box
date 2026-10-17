package onesocks

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/heysocks/onesocks"
	M "github.com/sagernet/sing/common/metadata"
)

func TestOneSocksOutboundTCP(t *testing.T) {
	const password = "test-onesocks-password"
	const cipherName = "AES-128-CTR"

	outboundInstance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test-onesocks", option.OneSocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 8888,
		},
		Password:   password,
		Cipher:     cipherName,
		PaddingLen: "0-0",
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
	clientStream, err := onesocks.NewConn(clientSide, out.cipher, destBuf.Bytes(), 0)
	if err != nil {
		t.Fatalf("NewConn failed: %v", err)
	}

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

	// Server side reads stream header:
	// prefix(2) + verify(16) + ivSize(1) + iv(16)
	hdr := make([]byte, 2+16+1+16)
	if _, err := io.ReadFull(serverSide, hdr); err != nil {
		t.Fatalf("server read stream header: %v", err)
	}
	if hdr[0] != 0x01 || hdr[1] != 0x00 {
		t.Fatalf("unexpected version/padding: %x", hdr[:2])
	}

	iv := hdr[2+16+1:]
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

func TestOneSocksOutboundValidation(t *testing.T) {
	_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.OneSocksOutboundOptions{
		Password: "",
	})
	if err == nil {
		t.Fatal("expected error for empty password, got nil")
	}

	_, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", option.OneSocksOutboundOptions{
		Password: "secret",
		Cipher:   "invalid-cipher",
	})
	if err == nil {
		t.Fatal("expected error for invalid cipher, got nil")
	}
}
