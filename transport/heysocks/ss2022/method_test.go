package heysocks2022

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func testPassword() string {
	identity := bytes.Repeat([]byte{0x11}, 16)
	master := bytes.Repeat([]byte{0x22}, 16)
	return base64.StdEncoding.EncodeToString(identity) + ":" + base64.StdEncoding.EncodeToString(master)
}

func TestNewParsesIdentityAndMasterPSK(t *testing.T) {
	m, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}

	if len(m.identityPSKs) != 1 {
		t.Fatalf("identity PSK count = %d, want 1", len(m.identityPSKs))
	}
	if len(m.identityPSKs[0]) != 16 || len(m.psk) != 16 {
		t.Fatalf("unexpected key lengths identity=%d master=%d", len(m.identityPSKs[0]), len(m.psk))
	}
}

func TestBuildFirstFlightContainsHeySocksEExtension(t *testing.T) {
	m, err := New(MethodAES128GCM, testPassword())
	if err != nil {
		t.Fatal(err)
	}

	fixedSalt := bytes.Repeat([]byte{0x33}, 16)
	m.randReader = bytes.NewReader(fixedSalt)
	m.timeFunc = func() time.Time { return time.Unix(1700000000, 0) }

	destination := M.ParseSocksaddrHostPort("1.1.1.1", 80)
	packet, requestSalt, _, _, err := m.buildFirstFlight(destination, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(requestSalt, fixedSalt) {
		t.Fatalf("request salt mismatch")
	}

	offset := len(requestSalt)

	identityBlock, err := newAES(m.identityPSKs[0], requestSalt, subkeyCtxIdentity)
	if err != nil {
		t.Fatal(err)
	}
	identityPlain := make([]byte, identityHeaderLength)
	identityBlock.Decrypt(identityPlain, packet[offset:offset+identityHeaderLength])
	if !bytes.Equal(identityPlain, m.eihPSKHashes[0][:]) {
		t.Fatalf("identity header plaintext mismatch")
	}
	offset += identityHeaderLength

	readerCipher, err := newSessionCipher(m.psk, requestSalt)
	if err != nil {
		t.Fatal(err)
	}

	fixedSealedLength := tcpRequestFixedPlainLength + readerCipher.overhead()
	fixedPlain, err := readerCipher.open(packet[offset : offset+fixedSealedLength])
	if err != nil {
		t.Fatal(err)
	}
	offset += fixedSealedLength

	if fixedPlain[0] != headerTypeClientStream {
		t.Fatalf("request type = %d, want %d", fixedPlain[0], headerTypeClientStream)
	}
	if got := int64(binary.BigEndian.Uint64(fixedPlain[1:9])); got != 1700000000 {
		t.Fatalf("timestamp = %d", got)
	}

	expectedDigest := md5.Sum([]byte(base64.StdEncoding.EncodeToString(m.psk)))
	if !bytes.Equal(fixedPlain[tcpRequestFixedHeaderLength:], expectedDigest[:]) {
		t.Fatalf("HeySocks E digest mismatch")
	}

	variablePlain, err := readerCipher.open(packet[offset:])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(variablePlain), int(binary.BigEndian.Uint16(fixedPlain[9:11])); got != want {
		t.Fatalf("variable length = %d, fixed header says %d", got, want)
	}

	destinationBytes, err := encodeDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(variablePlain, destinationBytes) {
		t.Fatalf("variable header does not begin with destination")
	}
	if !bytes.HasSuffix(variablePlain, []byte("abc")) {
		t.Fatalf("variable header does not end with initial payload")
	}
}

func TestParseResponseHeaderIgnoresTimestampSkew(t *testing.T) {
	requestSalt := bytes.Repeat([]byte{0x44}, 16)
	header := make([]byte, 1+8+len(requestSalt)+2)
	header[0] = headerTypeServerStream

	binary.BigEndian.PutUint64(header[1:9], 1)
	copy(header[9:], requestSalt)
	binary.BigEndian.PutUint16(header[9+len(requestSalt):], 394)

	n, err := parseResponseHeader(header, requestSalt)
	if err != nil {
		t.Fatal(err)
	}
	if n != 394 {
		t.Fatalf("payload length = %d, want 394", n)
	}
}

func TestNormalizePasswordBlackstoneExact(t *testing.T) {
	base := testPassword()

	tests := []struct {
		name           string
		password       string
		wantPassword   string
		wantBlackstone bool
	}{
		{"exact marker", base + BlackstoneSuffix, base, true},
		{"lowercase marker", base + "#blackstone", base + "#blackstone", false},
		{"other marker", base + "#TESTSTONE", base + "#TESTSTONE", false},
		{"extended marker", base + "#BLACKSTONEX", base + "#BLACKSTONEX", false},
		{"no marker", base, base, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPassword, gotBlackstone, err := NormalizePassword(MethodAES128GCM, tt.password)
			if err != nil {
				t.Fatal(err)
			}
			if gotPassword != tt.wantPassword {
				t.Fatalf("password = %q, want %q", gotPassword, tt.wantPassword)
			}
			if gotBlackstone != tt.wantBlackstone {
				t.Fatalf("blackstone = %v, want %v", gotBlackstone, tt.wantBlackstone)
			}
		})
	}
}

func TestNormalizePasswordBlackstoneRejectsUnsupportedCipher(t *testing.T) {
	_, _, err := NormalizePassword("aes-128-gcm", testPassword()+BlackstoneSuffix)
	if err == nil {
		t.Fatal("expected unsupported cipher error")
	}
}
