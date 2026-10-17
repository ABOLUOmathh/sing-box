package heysocks_xhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	xhttp "github.com/sagernet/sing-box/transport/heysocks/xhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HeySocksXHTTPOptions](registry, C.TypeHeySocksXHTTP, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	serverAddr      M.Socksaddr
	cipher          *xhttp.StreamCipher
	uotClient       *uot.Client
	multiplexDialer *mux.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HeySocksXHTTPOptions) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, E.New("missing password")
	}
	cipherName := options.Cipher
	if cipherName == "" {
		cipherName = "aes-128-ctr"
	}
	streamCipher, err := xhttp.NewStreamCipher(strings.ToUpper(cipherName), options.Password, options.FakeNet)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeHeySocksXHTTP, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		cipher:     streamCipher,
	}
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if !uotOptions.Enabled {
		outbound.multiplexDialer, err = mux.NewClientWithOptions((*xhttpDialer)(outbound), logger, common.PtrValueOrDefault(options.Multiplex))
		if err != nil {
			return nil, err
		}
	} else {
		outbound.uotClient = &uot.Client{
			Dialer:  (*xhttpDialer)(outbound),
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			if h.uotClient != nil {
				h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
				return h.uotClient.DialContext(ctx, network, destination)
			}
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*xhttpDialer)(h).DialContext(ctx, network, destination)
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
	}
	return h.multiplexDialer.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.multiplexDialer == nil {
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
			return h.uotClient.ListenPacket(ctx, destination)
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*xhttpDialer)(h).ListenPacket(ctx, destination)
	}
	h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
	return h.multiplexDialer.ListenPacket(ctx, destination)
}

func (h *Outbound) MultiplexEnabled() bool {
	return h.multiplexDialer != nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if h.multiplexDialer != nil {
		h.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	if h.multiplexDialer != nil {
		h.multiplexDialer.CloseIdleConnections()
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.multiplexDialer != nil {
		scope.Add(h.multiplexDialer.Close)
	}
	return nil
}

var _ N.Dialer = (*xhttpDialer)(nil)

type xhttpDialer Outbound

func (h *xhttpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		var destBuf bytes.Buffer
		destBuf.Grow(M.SocksaddrSerializer.AddrPortLen(destination))
		if err := M.SocksaddrSerializer.WriteAddrPort(&destBuf, destination); err != nil {
			outConn.Close()
			return nil, err
		}
		stream := xhttp.NewConn(outConn, h.cipher, destBuf.Bytes())
		if _, err := stream.Write(nil); err != nil {
			outConn.Close()
			return nil, err
		}
		return stream, nil
	case N.NetworkUDP:
		packetConn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *xhttpDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	rawPacketConn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	encryptedPacketConn := xhttp.NewPacketConn(rawPacketConn, h.cipher)
	serverUDPAddr := h.serverAddr.UDPAddr()
	return bufio.NewPacketConn(&xhttpPacketConn{
		PacketConn: encryptedPacketConn,
		serverAddr: serverUDPAddr,
	}), nil
}

type xhttpPacketConn struct {
	net.PacketConn
	serverAddr net.Addr
}

func (c *xhttpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	n, _, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	r := bytes.NewReader(buf[:n])
	dest, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return 0, nil, err
	}
	payloadLen := r.Len()
	if len(p) < payloadLen {
		return 0, nil, io.ErrShortBuffer
	}
	nRead, _ := r.Read(p[:payloadLen])
	return nRead, dest.UDPAddr(), nil
}

func (c *xhttpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dest := M.SocksaddrFromNet(addr)
	var b bytes.Buffer
	b.Grow(M.SocksaddrSerializer.AddrPortLen(dest) + len(p))
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, dest); err != nil {
		return 0, err
	}
	b.Write(p)
	_, err := c.PacketConn.WriteTo(b.Bytes(), c.serverAddr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *xhttpPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := c.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr), nil
}

func (c *xhttpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}
