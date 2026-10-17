package onesocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
)

const protocolVersion byte = 0x01

type Conn struct {
	net.Conn

	cipher      *StreamCipher
	destination []byte
	paddingLen  int

	readMu  sync.Mutex
	writeMu sync.Mutex

	reader cipher.Stream
	writer cipher.Stream
}

func NewConn(
	conn net.Conn,
	streamCipher *StreamCipher,
	destination []byte,
	paddingLen int,
) (*Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("onesocks: nil connection")
	}

	if streamCipher == nil {
		return nil, fmt.Errorf("onesocks: nil stream cipher")
	}

	if paddingLen < 0 || paddingLen > 255 {
		return nil, fmt.Errorf(
			"onesocks: invalid padding length %d",
			paddingLen,
		)
	}

	return &Conn{
		Conn:        conn,
		cipher:      streamCipher,
		destination: append([]byte(nil), destination...),
		paddingLen:  paddingLen,
	}, nil
}

func writeFull(w io.Writer, data []byte) (int, error) {
	total := 0

	for len(data) != 0 {
		n, err := w.Write(data)

		if n > 0 {
			total += n
			data = data[n:]
		}

		if err != nil {
			return total, err
		}

		if n == 0 {
			return total, io.ErrShortWrite
		}
	}

	return total, nil
}

func (c *Conn) initWriterLocked() error {
	if c.writer != nil {
		return nil
	}

	padding := make([]byte, c.paddingLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return fmt.Errorf(
			"onesocks: generate padding: %w",
			err,
		)
	}

	iv := make([]byte, c.cipher.IVSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf(
			"onesocks: generate IV: %w",
			err,
		)
	}

	verify := c.cipher.Verify()

	header := make(
		[]byte,
		0,
		2+len(padding)+len(verify)+1+len(iv),
	)

	header = append(
		header,
		protocolVersion,
		byte(c.paddingLen),
	)
	header = append(header, padding...)
	header = append(header, verify[:]...)
	header = append(
		header,
		byte(c.cipher.IVSize()),
	)
	header = append(header, iv...)

	if _, err := writeFull(c.Conn, header); err != nil {
		return fmt.Errorf(
			"onesocks: write stream header: %w",
			err,
		)
	}

	stream, err := c.cipher.Encrypter(iv)
	if err != nil {
		return err
	}

	c.writer = stream
	return nil
}

func (c *Conn) initReaderLocked() error {
	if c.reader != nil {
		return nil
	}

	prefix := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, prefix); err != nil {
		return fmt.Errorf(
			"onesocks: read stream prefix: %w",
			err,
		)
	}

	paddingLen := int(prefix[1])

	if paddingLen != 0 {
		if _, err := io.CopyN(
			io.Discard,
			c.Conn,
			int64(paddingLen),
		); err != nil {
			return fmt.Errorf(
				"onesocks: read padding: %w",
				err,
			)
		}
	}

	verifyAndIVSize := make([]byte, 17)
	if _, err := io.ReadFull(
		c.Conn,
		verifyAndIVSize,
	); err != nil {
		return fmt.Errorf(
			"onesocks: read verify block: %w",
			err,
		)
	}

	verify := c.cipher.Verify()

	if !bytes.Equal(
		verifyAndIVSize[:16],
		verify[:],
	) {
		return fmt.Errorf(
			"onesocks: verification mismatch",
		)
	}

	// Native OneSocks reads the final byte of this block but does not
	// visibly reject a non-0x10 value. Preserve that behavior here.

	iv := make([]byte, c.cipher.IVSize())
	if _, err := io.ReadFull(c.Conn, iv); err != nil {
		return fmt.Errorf(
			"onesocks: read IV: %w",
			err,
		)
	}

	stream, err := c.cipher.Decrypter(iv)
	if err != nil {
		return err
	}

	c.reader = stream
	return nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.initWriterLocked(); err != nil {
		return 0, err
	}

	plaintext := p

	if p == nil {
		plaintext = c.destination
	}

	encrypted := make([]byte, len(plaintext))
	c.writer.XORKeyStream(
		encrypted,
		plaintext,
	)

	return writeFull(c.Conn, encrypted)
}

func (c *Conn) Read(p []byte) (int, error) {
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
