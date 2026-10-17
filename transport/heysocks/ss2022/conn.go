package heysocks2022

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
)

type clientConn struct {
	net.Conn

	method      *Method
	destination M.Socksaddr

	handshakeMu   sync.Mutex
	handshakeDone bool
	handshakeErr  error
	requestSalt   []byte
	writeCipher   *streamCipher

	writeMu sync.Mutex

	readMu          sync.Mutex
	responseStarted bool
	readCipher      *streamCipher
	readBuf         []byte
}

func newClientConn(conn net.Conn, destination M.Socksaddr, method *Method) *clientConn {
	return &clientConn{
		Conn:        conn,
		method:      method,
		destination: destination,
	}
}

func (c *clientConn) ensureHandshake(initialPayload []byte) (int, error) {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()

	if c.handshakeDone {
		return 0, c.handshakeErr
	}

	packet, requestSalt, excessPayload, writerCipher, err := c.method.buildFirstFlight(c.destination, initialPayload)
	if err != nil {
		c.handshakeDone = true
		c.handshakeErr = err
		return 0, err
	}

	if err = writeFull(c.Conn, packet); err != nil {
		c.handshakeDone = true
		c.handshakeErr = err
		return 0, err
	}

	if len(excessPayload) > 0 {
		if _, err = writeStreamPayload(c.Conn, writerCipher, excessPayload); err != nil {
			c.handshakeDone = true
			c.handshakeErr = err
			return 0, err
		}
	}

	c.requestSalt = append([]byte(nil), requestSalt...)
	c.writeCipher = writerCipher
	c.handshakeDone = true
	return len(initialPayload), nil
}

func (c *clientConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	consumed, err := c.ensureHandshake(p)
	if err != nil {
		return consumed, err
	}
	if consumed == len(p) {
		return len(p), nil
	}

	n, err := writeStreamPayload(c.Conn, c.writeCipher, p[consumed:])
	return consumed + n, err
}

func (c *clientConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if _, err := c.ensureHandshake(nil); err != nil {
		return 0, err
	}

	for {
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}

		var (
			payload []byte
			err     error
		)

		if !c.responseStarted {
			payload, err = c.readFirstResponsePayload()
			if err != nil {
				return 0, err
			}
			c.responseStarted = true
		} else {
			payload, err = c.readStreamPayload()
			if err != nil {
				return 0, err
			}
		}

		if len(payload) == 0 {
			continue
		}

		c.readBuf = payload
	}
}

func (c *clientConn) readFirstResponsePayload() ([]byte, error) {
	salt := make([]byte, len(c.method.psk))
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return nil, err
	}

	readerCipher, err := newSessionCipher(c.method.psk, salt)
	if err != nil {
		return nil, err
	}

	responseHeaderPlainLength := 1 + 8 + len(c.requestSalt) + 2
	sealedHeader := make([]byte, responseHeaderPlainLength+readerCipher.overhead())
	if _, err := io.ReadFull(c.Conn, sealedHeader); err != nil {
		return nil, err
	}

	plaintextHeader, err := readerCipher.open(sealedHeader)
	if err != nil {
		return nil, fmt.Errorf("heysocks ss2022: decrypt response header: %w", err)
	}

	payloadLength, err := parseResponseHeader(plaintextHeader, c.requestSalt)
	if err != nil {
		return nil, err
	}

	sealedPayload := make([]byte, payloadLength+readerCipher.overhead())
	if _, err := io.ReadFull(c.Conn, sealedPayload); err != nil {
		return nil, err
	}

	payload, err := readerCipher.open(sealedPayload)
	if err != nil {
		return nil, fmt.Errorf("heysocks ss2022: decrypt first response payload: %w", err)
	}

	c.readCipher = readerCipher
	return payload, nil
}

func (c *clientConn) readStreamPayload() ([]byte, error) {
	if c.readCipher == nil {
		return nil, fmt.Errorf("heysocks ss2022: response cipher is not initialized")
	}

	sealedLength := make([]byte, 2+c.readCipher.overhead())
	if _, err := io.ReadFull(c.Conn, sealedLength); err != nil {
		return nil, err
	}

	lengthPlain, err := c.readCipher.open(sealedLength)
	if err != nil {
		return nil, fmt.Errorf("heysocks ss2022: decrypt stream length: %w", err)
	}
	if len(lengthPlain) != 2 {
		return nil, fmt.Errorf("heysocks ss2022: invalid decrypted stream length size %d", len(lengthPlain))
	}

	payloadLength := int(binary.BigEndian.Uint16(lengthPlain))
	if payloadLength == 0 {
		return nil, fmt.Errorf("heysocks ss2022: zero-length stream chunk")
	}

	sealedPayload := make([]byte, payloadLength+c.readCipher.overhead())
	if _, err := io.ReadFull(c.Conn, sealedPayload); err != nil {
		return nil, err
	}

	payload, err := c.readCipher.open(sealedPayload)
	if err != nil {
		return nil, fmt.Errorf("heysocks ss2022: decrypt stream payload: %w", err)
	}
	return payload, nil
}

func writeStreamPayload(conn net.Conn, cipher *streamCipher, payload []byte) (int, error) {
	if cipher == nil {
		return 0, fmt.Errorf("heysocks ss2022: stream cipher is not initialized")
	}

	written := 0
	for len(payload) > 0 {
		chunkLength := len(payload)
		if chunkLength > maxPayloadSize {
			chunkLength = maxPayloadSize
		}

		chunk := payload[:chunkLength]
		lengthPlain := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPlain, uint16(chunkLength))

		sealedLength := cipher.seal(lengthPlain)
		sealedPayload := cipher.seal(chunk)

		frame := make([]byte, 0, len(sealedLength)+len(sealedPayload))
		frame = append(frame, sealedLength...)
		frame = append(frame, sealedPayload...)

		if err := writeFull(conn, frame); err != nil {
			return written, err
		}

		written += chunkLength
		payload = payload[chunkLength:]
	}

	return written, nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
