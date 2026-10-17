package shadowsocks

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	ss2022 "github.com/sagernet/sing-box/transport/heysocks/ss2022"
	M "github.com/sagernet/sing/common/metadata"
)

func testBlackstonePassword() string {
	idKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	masterKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	return idKey + ":" + masterKey + ss2022.BlackstoneSuffix
}

func TestBlackstoneOutboundInit(t *testing.T) {
	outboundInstance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test-blackstone", option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 8388,
		},
		Method:   ss2022.MethodAES128GCM,
		Password: testBlackstonePassword(),
	})
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	out := outboundInstance.(*Outbound)
	if out.blackstoneMethod == nil {
		t.Fatal("expected blackstoneMethod to be initialized, got nil")
	}
	if out.uotClient == nil {
		t.Fatal("expected uotClient to be initialized by default for Blackstone, got nil")
	}
}

func TestBlackstoneOutboundTCP(t *testing.T) {
	outboundInstance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test-blackstone", option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 8388,
		},
		Method:   ss2022.MethodAES128GCM,
		Password: testBlackstonePassword(),
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
	clientConn := out.blackstoneMethod.DialEarlyConn(clientSide, dst)

	writeDone := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("ping"))
		writeDone <- err
	}()

	// Read packet on server side
	buf := make([]byte, 1024)
	n, err := serverSide.Read(buf)
	if err != nil {
		t.Fatalf("server Read failed: %v", err)
	}
	if n < 16+16 { // at least salt + identity header
		t.Fatalf("packet too short: %d bytes", n)
	}

	if err := <-writeDone; err != nil {
		t.Fatalf("client write failed: %v", err)
	}
}

func TestBlackstoneNativeUDPRejection(t *testing.T) {
	outboundInstance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test-blackstone", option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 8388,
		},
		Method:   ss2022.MethodAES128GCM,
		Password: testBlackstonePassword(),
	})
	if err != nil {
		t.Fatalf("NewOutbound failed: %v", err)
	}

	out := outboundInstance.(*Outbound)
	dialer := (*shadowsocksDialer)(out)

	_, err = dialer.ListenPacket(context.Background(), M.ParseSocksaddr("8.8.8.8:53"))
	if err == nil {
		t.Fatal("expected error for native UDP on Blackstone, got nil")
	}
}
