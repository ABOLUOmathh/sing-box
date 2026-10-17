package heysocks2022

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	headerTypeClientStream = 0
	headerTypeServerStream = 1

	identityHeaderLength = 16
	maxPaddingLength     = 900
	maxPayloadSize       = 0xFFFF

	tcpRequestFixedHeaderLength = 1 + 8 + 2
	heysocksEExtensionLength    = md5.Size
	tcpRequestFixedPlainLength  = tcpRequestFixedHeaderLength + heysocksEExtensionLength
)

func encodeDestination(destination M.Socksaddr) ([]byte, error) {
	var b bytes.Buffer
	b.Grow(M.SocksaddrSerializer.AddrPortLen(destination))
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, destination); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (m *Method) buildFirstFlight(destination M.Socksaddr, payload []byte) (
	packet []byte,
	requestSalt []byte,
	excessPayload []byte,
	writerCipher *streamCipher,
	err error,
) {
	destinationBytes, err := encodeDestination(destination)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	payloadPart := payload
	roomForPayload := maxPayloadSize - len(destinationBytes) - 2
	var paddingPayloadLen int

	switch {
	case len(payloadPart) > roomForPayload:
		paddingPayloadLen = roomForPayload
		excessPayload = payloadPart[roomForPayload:]
		payloadPart = payloadPart[:roomForPayload]
	case len(payloadPart) >= maxPaddingLength:
		paddingPayloadLen = len(payloadPart)
	case len(payloadPart) > 0:
		paddingPayloadLen = len(payloadPart) + mrand.Intn(maxPaddingLength-len(payloadPart)+1)
	default:
		paddingPayloadLen = 1 + mrand.Intn(maxPaddingLength)
	}

	requestSalt = make([]byte, len(m.psk))
	if _, err = io.ReadFull(m.randReader, requestSalt); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("heysocks ss2022: generate salt: %w", err)
	}

	identityHeaders := make([]byte, identityHeaderLength*len(m.eihPSKHashes))
	for i := range m.eihPSKHashes {
		block, blockErr := newAES(m.identityPSKs[i], requestSalt, subkeyCtxIdentity)
		if blockErr != nil {
			return nil, nil, nil, nil, blockErr
		}

		dst := identityHeaders[i*identityHeaderLength : (i+1)*identityHeaderLength]
		block.Encrypt(dst, m.eihPSKHashes[i][:])
	}

	variablePlainLength := len(destinationBytes) + 2 + paddingPayloadLen
	variablePlain := make([]byte, variablePlainLength)
	copy(variablePlain, destinationBytes)

	paddingLength := variablePlainLength - len(destinationBytes) - 2 - len(payloadPart)
	binary.BigEndian.PutUint16(variablePlain[len(destinationBytes):], uint16(paddingLength))
	copy(variablePlain[len(destinationBytes)+2+paddingLength:], payloadPart)

	fixedPlain := make([]byte, tcpRequestFixedPlainLength)
	fixedPlain[0] = headerTypeClientStream
	binary.BigEndian.PutUint64(fixedPlain[1:], uint64(m.timeFunc().Unix()))
	binary.BigEndian.PutUint16(fixedPlain[1+8:], uint16(variablePlainLength))

	encodedMasterPSK := base64.StdEncoding.EncodeToString(m.psk)
	digest := md5.Sum([]byte(encodedMasterPSK))
	copy(fixedPlain[tcpRequestFixedHeaderLength:], digest[:])

	writerCipher, err = newSessionCipher(m.psk, requestSalt)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	fixedCiphertext := writerCipher.seal(fixedPlain)
	variableCiphertext := writerCipher.seal(variablePlain)

	packet = make(
		[]byte,
		0,
		len(requestSalt)+len(identityHeaders)+len(fixedCiphertext)+len(variableCiphertext),
	)
	packet = append(packet, requestSalt...)
	packet = append(packet, identityHeaders...)
	packet = append(packet, fixedCiphertext...)
	packet = append(packet, variableCiphertext...)

	return packet, requestSalt, excessPayload, writerCipher, nil
}

func parseResponseHeader(plaintext, requestSalt []byte) (int, error) {
	expectedLength := 1 + 8 + len(requestSalt) + 2
	if len(plaintext) != expectedLength {
		return 0, fmt.Errorf(
			"heysocks ss2022: response header length %d, want %d",
			len(plaintext),
			expectedLength,
		)
	}

	if plaintext[0] != headerTypeServerStream {
		return 0, fmt.Errorf(
			"heysocks ss2022: response header type %d, want %d",
			plaintext[0],
			headerTypeServerStream,
		)
	}

	// Intentionally do not enforce the historical +/-30 second response
	// timestamp validation. This matches the HeySocks native response
	// behavior verified against the target server.

	responseRequestSalt := plaintext[1+8 : 1+8+len(requestSalt)]
	if !bytes.Equal(requestSalt, responseRequestSalt) {
		return 0, fmt.Errorf("heysocks ss2022: response request salt mismatch")
	}

	payloadLength := int(binary.BigEndian.Uint16(plaintext[1+8+len(requestSalt):]))
	return payloadLength, nil
}
