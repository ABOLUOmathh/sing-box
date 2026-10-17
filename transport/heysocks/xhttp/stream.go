package xhttp

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

// Conn implements the recovered HeySocks XHTTP TCP xstream.
//
// Wire layout:
//
// bootstrap:
//
//	[128 fake/random]
//	[16 identity]
//	[session blob]
//	[1 IV size]
//	[IV]
//
// continuous AES-CTR stream:
//
//	Write(nil)  -> encrypted Destination
//	Write(data) -> encrypted data
//
// Read and write directions use independent CTR streams and IVs.
type Conn struct {
	net.Conn

	cipher      *StreamCipher
	destination []byte
	randReader  io.Reader

	readMu  sync.Mutex
	writeMu sync.Mutex

	reader cipher.Stream
	writer cipher.Stream
}

func NewConn(
	conn net.Conn,
	c *StreamCipher,
	destination []byte,
) *Conn {
	return newConnWithRand(
		conn,
		c,
		destination,
		rand.Reader,
	)
}

func newConnWithRand(
	conn net.Conn,
	c *StreamCipher,
	destination []byte,
	randReader io.Reader,
) *Conn {
	if randReader == nil {
		randReader = rand.Reader
	}

	return &Conn{
		Conn:        conn,
		cipher:      c,
		destination: append([]byte(nil), destination...),
		randReader:  randReader,
	}
}

func (c *Conn) initWriterLocked() error {
	if c.writer != nil {
		return nil
	}

	header, iv, err := buildBootstrap(
		c.cipher,
		"tcp",
		c.randReader,
	)
	if err != nil {
		return err
	}

	if err := writeAll(c.Conn, header); err != nil {
		return fmt.Errorf(
			"xhttp: write TCP bootstrap: %w",
			err,
		)
	}

	writer, err := c.cipher.Encrypter(iv)
	if err != nil {
		return fmt.Errorf(
			"xhttp: initialize TCP encrypter: %w",
			err,
		)
	}

	c.writer = writer

	return nil
}

func (c *Conn) initReaderLocked() error {
	if c.reader != nil {
		return nil
	}

	iv, err := parseBootstrap(c.Conn, c.cipher)
	if err != nil {
		return err
	}

	reader, err := c.cipher.Decrypter(iv)
	if err != nil {
		return fmt.Errorf(
			"xhttp: initialize TCP decrypter: %w",
			err,
		)
	}

	c.reader = reader

	return nil
}

func (c *Conn) writeEncryptedLocked(
	p []byte,
) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	encrypted := make([]byte, len(p))
	c.writer.XORKeyStream(encrypted, p)

	if err := writeAll(
		c.Conn,
		encrypted,
	); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Write mirrors the native xstream.Conn.Write semantics.
//
// A nil slice is a protocol control operation:
//
// Write(nil)
//
//	-> initialize bootstrap if necessary
//	-> encrypt and send Destination
//
// A non-nil slice is ordinary application data.
//
// This intentionally distinguishes nil from a non-nil zero-length slice.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.initWriterLocked(); err != nil {
		return 0, err
	}

	if p == nil {
		return c.writeEncryptedLocked(c.destination)
	}

	return c.writeEncryptedLocked(p)
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := c.initReaderLocked(); err != nil {
		return 0, err
	}

	n, err := c.Conn.Read(p)

	if n > 0 {
		c.reader.XORKeyStream(
			p[:n],
			p[:n],
		)
	}

	return n, err
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)

		if n > 0 {
			p = p[n:]
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}

	return nil
}
