package onesocks

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestWriteDestinationFirstFlight(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	destination := []byte{
		0x03,
		0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e',
		'.', 'c', 'o', 'm',
		0x01, 0xbb,
	}

	stream, err := NewConn(
		client,
		c,
		destination,
		8,
	)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello-onesocks")

	errCh := make(chan error, 1)

	go func() {
		if _, err := stream.Write(nil); err != nil {
			errCh <- err
			return
		}

		if _, err := stream.Write(payload); err != nil {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	prefix := make([]byte, 2)
	if _, err := io.ReadFull(server, prefix); err != nil {
		t.Fatal(err)
	}

	if prefix[0] != 0x01 {
		t.Fatalf(
			"version = %#02x, want 0x01",
			prefix[0],
		)
	}

	if prefix[1] != 8 {
		t.Fatalf(
			"padding length = %d, want 8",
			prefix[1],
		)
	}

	padding := make([]byte, int(prefix[1]))
	if _, err := io.ReadFull(server, padding); err != nil {
		t.Fatal(err)
	}

	proof := make([]byte, 17)
	if _, err := io.ReadFull(server, proof); err != nil {
		t.Fatal(err)
	}

	verify := c.Verify()

	if !bytes.Equal(proof[:16], verify[:]) {
		t.Fatalf(
			"verify = %x, want %x",
			proof[:16],
			verify,
		)
	}

	if proof[16] != 0x10 {
		t.Fatalf(
			"IV marker = %#02x, want 0x10",
			proof[16],
		)
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(server, iv); err != nil {
		t.Fatal(err)
	}

	decryptor, err := c.Decrypter(iv)
	if err != nil {
		t.Fatal(err)
	}

	encryptedTarget := make(
		[]byte,
		len(destination),
	)

	if _, err := io.ReadFull(
		server,
		encryptedTarget,
	); err != nil {
		t.Fatal(err)
	}

	target := make([]byte, len(destination))
	decryptor.XORKeyStream(
		target,
		encryptedTarget,
	)

	if !bytes.Equal(target, destination) {
		t.Fatalf(
			"destination = %x, want %x",
			target,
			destination,
		)
	}

	encryptedPayload := make(
		[]byte,
		len(payload),
	)

	if _, err := io.ReadFull(
		server,
		encryptedPayload,
	); err != nil {
		t.Fatal(err)
	}

	gotPayload := make([]byte, len(payload))
	decryptor.XORKeyStream(
		gotPayload,
		encryptedPayload,
	)

	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf(
			"payload = %q, want %q",
			gotPayload,
			payload,
		)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestReadEncryptedStream(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewConn(
		client,
		c,
		nil,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	sender, err := NewConn(
		server,
		c,
		nil,
		3,
	)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("server-response")

	errCh := make(chan error, 1)

	go func() {
		_, err := sender.Write(payload)
		errCh <- err
	}()

	got := make([]byte, len(payload))

	if _, err := io.ReadFull(
		receiver,
		got,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf(
			"response = %q, want %q",
			got,
			payload,
		)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestRejectBadVerify(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewConn(
		client,
		c,
		nil,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		header := make([]byte, 0, 35)

		header = append(header, 0x01, 0x00)
		header = append(header, make([]byte, 16)...)
		header = append(header, 0x10)
		header = append(header, make([]byte, 16)...)

		_, _ = server.Write(header)
	}()

	buf := make([]byte, 1)

	if _, err := receiver.Read(buf); err == nil {
		t.Fatal("expected verification mismatch")
	}
}

func TestRejectInvalidPaddingLength(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c, err := NewStreamCipher(
		CipherAES128CTR,
		"password",
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewConn(
		client,
		c,
		nil,
		256,
	); err == nil {
		t.Fatal("expected invalid padding error")
	}
}
