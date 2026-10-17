package xhttp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
)

func newTestCipher(t *testing.T) *StreamCipher {
	t.Helper()

	c, err := NewStreamCipher(
		"aes-128-ctr",
		"abc:03010203",
		map[string]string{
			"tcp": "aabbcc",
			"udp": "ddeeff",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func TestTCPStreamClientToServer(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	client := newConnWithRand(
		rawClient,
		newTestCipher(t),
		nil,
		bytes.NewReader(bytes.Repeat([]byte{0x11}, 1024)),
	)

	server := newConnWithRand(
		rawServer,
		newTestCipher(t),
		nil,
		bytes.NewReader(bytes.Repeat([]byte{0x22}, 1024)),
	)

	want := []byte(
		"heysocks-xhttp-tcp-client-to-server",
	)

	errCh := make(chan error, 1)

	go func() {
		_, err := client.Write(want)
		errCh <- err
	}()

	got := make([]byte, len(want))

	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"plaintext mismatch:\n got=%q\nwant=%q",
			got,
			want,
		)
	}
}

func TestTCPStreamBidirectional(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	client := newConnWithRand(
		rawClient,
		newTestCipher(t),
		nil,
		bytes.NewReader(bytes.Repeat([]byte{0x33}, 2048)),
	)

	server := newConnWithRand(
		rawServer,
		newTestCipher(t),
		nil,
		bytes.NewReader(bytes.Repeat([]byte{0x44}, 2048)),
	)

	c2s := []byte("client-message")
	s2c := []byte("server-message")

	writeClient := make(chan error, 1)
	go func() {
		_, err := client.Write(c2s)
		writeClient <- err
	}()

	gotC2S := make([]byte, len(c2s))
	if _, err := io.ReadFull(server, gotC2S); err != nil {
		t.Fatal(err)
	}

	if err := <-writeClient; err != nil {
		t.Fatal(err)
	}

	writeServer := make(chan error, 1)
	go func() {
		_, err := server.Write(s2c)
		writeServer <- err
	}()

	gotS2C := make([]byte, len(s2c))
	if _, err := io.ReadFull(client, gotS2C); err != nil {
		t.Fatal(err)
	}

	if err := <-writeServer; err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(gotC2S, c2s) {
		t.Fatalf(
			"client->server mismatch: got=%q want=%q",
			gotC2S,
			c2s,
		)
	}

	if !bytes.Equal(gotS2C, s2c) {
		t.Fatalf(
			"server->client mismatch: got=%q want=%q",
			gotS2C,
			s2c,
		)
	}
}

func TestTCPStreamContinuousWrites(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	client := newConnWithRand(
		rawClient,
		newTestCipher(t),
		nil,
		bytes.NewReader(bytes.Repeat([]byte{0x55}, 2048)),
	)

	server := newConnWithRand(
		rawServer,
		newTestCipher(t),
		nil,
		bytes.NewReader(bytes.Repeat([]byte{0x66}, 2048)),
	)

	parts := [][]byte{
		[]byte("one-"),
		[]byte("two-"),
		[]byte("three"),
	}

	want := bytes.Join(parts, nil)

	errCh := make(chan error, 1)

	go func() {
		for _, p := range parts {
			if _, err := client.Write(p); err != nil {
				errCh <- err
				return
			}
		}

		errCh <- nil
	}()

	got := make([]byte, len(want))

	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"continuous stream mismatch: got=%q want=%q",
			got,
			want,
		)
	}
}

func TestTCPNilWriteSendsDestination(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	destination := []byte{
		0x03,
		0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xbb,
	}

	client := newConnWithRand(
		rawClient,
		newTestCipher(t),
		destination,
		bytes.NewReader(
			bytes.Repeat([]byte{0x77}, 2048),
		),
	)

	errCh := make(chan error, 1)

	go func() {
		n, err := client.Write(nil)
		if err == nil && n != len(destination) {
			err = fmt.Errorf(
				"Write(nil) returned n=%d, want %d",
				n,
				len(destination),
			)
		}
		errCh <- err
	}()

	// Test cipher uses session:
	//
	// [3][1][2][3]
	//
	// Native bootstrap:
	//
	// 128 fake/random
	// 16 identity
	// 4 session bytes
	// 1 IV-size
	// 16 IV
	//
	// total = 165.
	header := make([]byte, 165)

	if _, err := io.ReadFull(rawServer, header); err != nil {
		t.Fatal(err)
	}

	if got := header[144]; got != 3 {
		t.Fatalf(
			"session length byte=%d want=3",
			got,
		)
	}

	if got := header[148]; got != 16 {
		t.Fatalf(
			"IV size=%d want=16",
			got,
		)
	}

	iv := append(
		[]byte(nil),
		header[149:165]...,
	)

	stream, err := newTestCipher(t).Decrypter(iv)
	if err != nil {
		t.Fatal(err)
	}

	encryptedDestination := make(
		[]byte,
		len(destination),
	)

	if _, err := io.ReadFull(
		rawServer,
		encryptedDestination,
	); err != nil {
		t.Fatal(err)
	}

	gotDestination := make(
		[]byte,
		len(destination),
	)

	stream.XORKeyStream(
		gotDestination,
		encryptedDestination,
	)

	if !bytes.Equal(
		gotDestination,
		destination,
	) {
		t.Fatalf(
			"destination mismatch:\n got=%x\nwant=%x",
			gotDestination,
			destination,
		)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestTCPDestinationThenPayloadContinuousStream(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	destination := []byte{
		0x01,
		192, 0, 2, 10,
		0x01, 0xbb,
	}

	client := newConnWithRand(
		rawClient,
		newTestCipher(t),
		destination,
		bytes.NewReader(
			bytes.Repeat([]byte{0x31}, 4096),
		),
	)

	server := newConnWithRand(
		rawServer,
		newTestCipher(t),
		nil,
		bytes.NewReader(
			bytes.Repeat([]byte{0x41}, 4096),
		),
	)

	payload := []byte(
		"payload-after-destination",
	)

	errCh := make(chan error, 1)

	go func() {
		n, err := client.Write(nil)
		if err != nil {
			errCh <- err
			return
		}

		if n != len(destination) {
			errCh <- fmt.Errorf(
				"Write(nil) returned n=%d, want %d",
				n,
				len(destination),
			)
			return
		}

		n, err = client.Write(payload)
		if err != nil {
			errCh <- err
			return
		}

		if n != len(payload) {
			errCh <- fmt.Errorf(
				"payload Write returned n=%d, want %d",
				n,
				len(payload),
			)
			return
		}

		errCh <- nil
	}()

	gotDestination := make(
		[]byte,
		len(destination),
	)

	if _, err := io.ReadFull(
		server,
		gotDestination,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		gotDestination,
		destination,
	) {
		t.Fatalf(
			"destination mismatch:\n got=%x\nwant=%x",
			gotDestination,
			destination,
		)
	}

	gotPayload := make(
		[]byte,
		len(payload),
	)

	if _, err := io.ReadFull(
		server,
		gotPayload,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		gotPayload,
		payload,
	) {
		t.Fatalf(
			"payload mismatch:\n got=%q\nwant=%q",
			gotPayload,
			payload,
		)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
