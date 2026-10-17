package vless

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type HeySocksClient struct {
	e  bool
	mu sync.RWMutex
	h  []byte
}

func parseUUID(userId string) ([16]byte, error) {
	u, err := uuid.FromString(userId)
	if err != nil {
		u = uuid.NewV5(uuid.Nil, userId)
	}
	return u, nil
}

func NewHeySocksClient(e bool, hHex string) (*HeySocksClient, error) {
	var h []byte
	if hHex != "" {
		decoded, err := hex.DecodeString(hHex)
		if err != nil {
			return nil, E.Cause(err, "invalid heysocks vless h hex string")
		}
		if len(decoded) < 1 {
			return nil, errors.New("empty heysocks vless h")
		}
		if len(decoded) >= 2 && int(decoded[0]) == len(decoded)-1 {
			h = decoded
		} else {
			h = append([]byte{byte(len(decoded))}, decoded...)
		}
	}
	return &HeySocksClient{
		e: e,
		h: h,
	}, nil
}

func (c *HeySocksClient) snapshot() (bool, []byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.h == nil {
		return c.e, nil
	}
	h := make([]byte, len(c.h))
	copy(h, c.h)
	return c.e, h
}

func (c *HeySocksClient) setH(h []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copyH := make([]byte, len(h))
	copy(copyH, h)
	c.h = copyH
}

func (c *HeySocksClient) hasH() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.h) > 0
}

const (
	stateRespVersion     = 0
	stateRespProtobufLen = 1
	stateRespProtobuf    = 2
	stateRespHLen        = 3
	stateRespHData       = 4
	stateStreamReady     = 5
)

var (
	_ net.Conn       = (*HeySocksConn)(nil)
	_ N.ExtendedConn = (*HeySocksConn)(nil)
	_ N.EarlyReader  = (*HeySocksConn)(nil)
	_ N.EarlyWriter  = (*HeySocksConn)(nil)
)

type HeySocksConn struct {
	net.Conn
	client         *HeySocksClient
	rawUUID        [16]byte
	requestWritten bool
	writeMu        sync.Mutex

	readMu         sync.Mutex
	state          int
	protobufRemain int
	hRemain        int
	newH           []byte
	unreadBuf      bytes.Buffer
}

func NewHeySocksConn(conn net.Conn, client *HeySocksClient, rawUUID [16]byte) *HeySocksConn {
	return &HeySocksConn{
		Conn:    conn,
		client:  client,
		rawUUID: rawUUID,
		state:   stateRespVersion,
	}
}

func (c *HeySocksConn) Upstream() any {
	return c.Conn
}

func (c *HeySocksConn) ReaderReplaceable() bool {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.state == stateStreamReady && c.unreadBuf.Len() == 0
}

func (c *HeySocksConn) WriterReplaceable() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.requestWritten
}

func (c *HeySocksConn) NeedHandshakeForRead() bool {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.state < stateStreamReady
}

func (c *HeySocksConn) NeedHandshakeForWrite() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return !c.requestWritten
}

func parseVLESSHeaderLen(b []byte) (int, error) {
	if len(b) < 1+16+1+1+1 {
		return 0, io.ErrShortBuffer
	}
	if b[0] != 0 {
		return 0, errors.New("unsupported vless version")
	}
	addonLen := int(b[17])
	offset := 18 + addonLen
	if len(b) < offset+1+1 {
		return 0, io.ErrShortBuffer
	}
	// command byte at offset
	offset++
	addrType := b[offset]
	offset++
	switch addrType {
	case 1: // IPv4
		offset += 4 + 2
	case 2: // Domain
		if len(b) < offset+1 {
			return 0, io.ErrShortBuffer
		}
		domainLen := int(b[offset])
		offset += 1 + domainLen + 2
	case 3: // IPv6
		offset += 16 + 2
	default:
		return 0, fmt.Errorf("unknown address type %d", addrType)
	}
	if len(b) < offset {
		return 0, io.ErrShortBuffer
	}
	return offset, nil
}

func (c *HeySocksConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.requestWritten {
		return c.Conn.Write(b)
	}

	headerLen, err := parseVLESSHeaderLen(b)
	if err != nil {
		c.requestWritten = true
		return c.Conn.Write(b)
	}

	e, h := c.client.snapshot()
	var out bytes.Buffer
	out.Grow(len(b) + 16 + len(h))
	out.Write(b[:headerLen])

	if e {
		sum := md5.Sum(c.rawUUID[:])
		out.Write(sum[:])
	}
	if len(h) > 0 {
		out.Write(h)
	}
	out.Write(b[headerLen:])

	c.requestWritten = true
	_, err = c.Conn.Write(out.Bytes())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *HeySocksConn) WriteBuffer(buffer *buf.Buffer) error {
	_, err := c.Write(buffer.Bytes())
	if err == nil {
		buffer.Reset()
	}
	return err
}

func (c *HeySocksConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.state == stateStreamReady {
		if c.unreadBuf.Len() > 0 {
			return c.unreadBuf.Read(b)
		}
		return c.Conn.Read(b)
	}

	var raw [512]byte
	for c.state < stateStreamReady && c.unreadBuf.Len() == 0 {
		n, err := c.Conn.Read(raw[:])
		if err != nil {
			return 0, err
		}
		i := 0
		for i < n && c.state < stateStreamReady {
			switch c.state {
			case stateRespVersion:
				c.unreadBuf.WriteByte(raw[i])
				i++
				c.state = stateRespProtobufLen
			case stateRespProtobufLen:
				pLen := int(raw[i])
				c.unreadBuf.WriteByte(raw[i])
				i++
				if pLen > 0 {
					c.protobufRemain = pLen
					c.state = stateRespProtobuf
				} else {
					if c.client.hasH() {
						c.state = stateRespHLen
					} else {
						c.state = stateStreamReady
					}
				}
			case stateRespProtobuf:
				avail := n - i
				toRead := c.protobufRemain
				if avail < toRead {
					toRead = avail
				}
				c.unreadBuf.Write(raw[i : i+toRead])
				i += toRead
				c.protobufRemain -= toRead
				if c.protobufRemain == 0 {
					if c.client.hasH() {
						c.state = stateRespHLen
					} else {
						c.state = stateStreamReady
					}
				}
			case stateRespHLen:
				hLen := int(raw[i])
				i++
				if hLen == 0 {
					c.state = stateStreamReady
				} else {
					c.hRemain = hLen
					c.newH = make([]byte, hLen+1)
					c.newH[0] = byte(hLen)
					c.state = stateRespHData
				}
			case stateRespHData:
				avail := n - i
				toRead := c.hRemain
				if avail < toRead {
					toRead = avail
				}
				dstOffset := len(c.newH) - c.hRemain
				copy(c.newH[dstOffset:dstOffset+toRead], raw[i:i+toRead])
				i += toRead
				c.hRemain -= toRead
				if c.hRemain == 0 {
					c.client.setH(c.newH)
					c.state = stateStreamReady
				}
			}
		}
		if i < n {
			c.unreadBuf.Write(raw[i:n])
		}
	}

	return c.unreadBuf.Read(b)
}

func (c *HeySocksConn) ReadBuffer(buffer *buf.Buffer) error {
	n, err := c.Read(buffer.FreeBytes())
	if n > 0 {
		buffer.Truncate(n)
	}
	return err
}

func (c *HeySocksConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *HeySocksConn) FrontHeadroom() int {
	return 0
}
