package option

type HeySocksXHTTPOptions struct {
	DialerOptions
	ServerOptions
	Password   string                    `json:"password"`
	Cipher     string                    `json:"cipher,omitempty" enum:"aes-128-ctr,aes-192-ctr,aes-256-ctr"`
	Network    NetworkList               `json:"network,omitempty"`
	PaddingLen string                    `json:"padding_len,omitempty"`
	FakeNet    map[string]string         `json:"fake_net,omitempty"`
	UDPOverTCP *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
	Multiplex  *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	E          bool                      `json:"e,omitempty"`
	H          string                    `json:"h,omitempty"`
}
