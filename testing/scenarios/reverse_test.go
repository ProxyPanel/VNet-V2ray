package scenarios

import (
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/app/log"
	"github.com/v2fly/v2ray-core/v4/app/policy"
	"github.com/v2fly/v2ray-core/v4/app/proxyman"
	"github.com/v2fly/v2ray-core/v4/app/reverse"
	"github.com/v2fly/v2ray-core/v4/app/router"
	"github.com/v2fly/v2ray-core/v4/common"
	clog "github.com/v2fly/v2ray-core/v4/common/log"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/serial"
	"github.com/v2fly/v2ray-core/v4/common/uuid"
	"github.com/v2fly/v2ray-core/v4/proxy/blackhole"
	"github.com/v2fly/v2ray-core/v4/proxy/dokodemo"
	"github.com/v2fly/v2ray-core/v4/proxy/freedom"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess/inbound"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess/outbound"
	"github.com/v2fly/v2ray-core/v4/testing/servers/tcp"
)

func TestReverseProxy(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)

	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	externalPort := tcp.PickPort()
	reversePort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&reverse.Config{
				PortalConfig: []*reverse.PortalConfig{
					{
						Tag:    "portal",
						Domain: "test.v2fly.org",
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						Domain: []*router.Domain{
							{Type: router.Domain_Full, Value: "test.v2fly.org"},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "portal",
						},
					},
					{
						InboundTag: []string{"external"},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "portal",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "external",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(externalPort),
					Listen:    net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address: net.NewIPOrDomain(dest.Address),
					Port:    uint32(dest.Port),
					NetworkList: &net.NetworkList{
						Network: []net.Network{net.Network_TCP},
					},
				}),
			},
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(reversePort),
					Listen:    net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id:      userID.String(),
								AlterId: 64,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&reverse.Config{
				BridgeConfig: []*reverse.BridgeConfig{
					{
						Tag:    "bridge",
						Domain: "test.v2fly.org",
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						Domain: []*router.Domain{
							{Type: router.Domain_Full, Value: "test.v2fly.org"},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "reverse",
						},
					},
					{
						InboundTag: []string{"bridge"},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "freedom",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(clientPort),
					Listen:    net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address: net.NewIPOrDomain(dest.Address),
					Port:    uint32(dest.Port),
					NetworkList: &net.NetworkList{
						Network: []net.Network{net.Network_TCP},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag:           "freedom",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
			{
				Tag: "reverse",
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Receiver: []*protocol.ServerEndpoint{
						{
							Address: net.NewIPOrDomain(net.LocalHostIP),
							Port:    uint32(reversePort),
							User: []*protocol.User{
								{
									Account: serial.ToTypedMessage(&vmess.Account{
										Id:      userID.String(),
										AlterId: 64,
										SecuritySettings: &protocol.SecurityConfig{
											Type: protocol.SecurityType_AES128_GCM,
										},
									}),
								},
							},
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)

	defer CloseAllServers(servers)

	var errg errgroup.Group
	for i := 0; i < 32; i++ {
		errg.Go(testTCPConn(externalPort, 10240*1024, time.Second*40))
	}

	if err := errg.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestReverseProxyLongRunning(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)

	defer tcpServer.Close()

	userID := protocol.NewID(uuid.New())
	externalPort := tcp.PickPort()
	reversePort := tcp.PickPort()

	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&policy.Config{
				Level: map[uint32]*policy.Policy{
					0: {
						Timeout: &policy.Policy_Timeout{
							UplinkOnly:   &policy.Second{Value: 0},
							DownlinkOnly: &policy.Second{Value: 0},
						},
					},
				},
			}),
			serial.ToTypedMessage(&reverse.Config{
				PortalConfig: []*reverse.PortalConfig{
					{
						Tag:    "portal",
						Domain: "test.v2fly.org",
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						Domain: []*router.Domain{
							{Type: router.Domain_Full, Value: "test.v2fly.org"},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "portal",
						},
					},
					{
						InboundTag: []string{"external"},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "portal",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "external",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(externalPort),
					Listen:    net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address: net.NewIPOrDomain(dest.Address),
					Port:    uint32(dest.Port),
					NetworkList: &net.NetworkList{
						Network: []net.Network{net.Network_TCP},
					},
				}),
			},
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(reversePort),
					Listen:    net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id:      userID.String(),
								AlterId: 64,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  log.LogType_Console,
			}),
			serial.ToTypedMessage(&policy.Config{
				Level: map[uint32]*policy.Policy{
					0: {
						Timeout: &policy.Policy_Timeout{
							UplinkOnly:   &policy.Second{Value: 0},
							DownlinkOnly: &policy.Second{Value: 0},
						},
					},
				},
			}),
			serial.ToTypedMessage(&reverse.Config{
				BridgeConfig: []*reverse.BridgeConfig{
					{
						Tag:    "bridge",
						Domain: "test.v2fly.org",
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						Domain: []*router.Domain{
							{Type: router.Domain_Full, Value: "test.v2fly.org"},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "reverse",
						},
					},
					{
						InboundTag: []string{"bridge"},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "freedom",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(clientPort),
					Listen:    net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address: net.NewIPOrDomain(dest.Address),
					Port:    uint32(dest.Port),
					NetworkList: &net.NetworkList{
						Network: []net.Network{net.Network_TCP},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag:           "freedom",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			},
			{
				Tag: "reverse",
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Receiver: []*protocol.ServerEndpoint{
						{
							Address: net.NewIPOrDomain(net.LocalHostIP),
							Port:    uint32(reversePort),
							User: []*protocol.User{
								{
									Account: serial.ToTypedMessage(&vmess.Account{
										Id:      userID.String(),
										AlterId: 64,
										SecuritySettings: &protocol.SecurityConfig{
											Type: protocol.SecurityType_AES128_GCM,
										},
									}),
								},
							},
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)

	defer CloseAllServers(servers)

	for i := 0; i < 4096; i++ {
		if err := testTCPConn(externalPort, 1024, time.Second*20)(); err != nil {
			t.Error(err)
		}
	}
}
