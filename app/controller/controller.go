package controller

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/r3labs/diff"
	"v2ray.com/core"
	"v2ray.com/core/app/proxyman"
	"v2ray.com/core/common"
	"v2ray.com/core/common/acme"
	"v2ray.com/core/common/api"
	"v2ray.com/core/common/errors"
	"v2ray.com/core/common/log"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/retry"
	"v2ray.com/core/common/serial"
	"v2ray.com/core/common/task"
	"v2ray.com/core/common/uuid"
	controllerInterface "v2ray.com/core/features/controller"
	"v2ray.com/core/features/inbound"
	"v2ray.com/core/infra/conf"
	"v2ray.com/core/proxy"
	"v2ray.com/core/proxy/freedom"
	"v2ray.com/core/proxy/vmess"
	vmess_inbound "v2ray.com/core/proxy/vmess/inbound"
	"v2ray.com/core/transport/internet"
	"v2ray.com/core/transport/internet/tls"
	"v2ray.com/core/transport/internet/websocket"
)

//go:generate errorgen

type Controller struct {
	*api.ApiClient
	nodeInfo *api.NodeInfo
	context.Context
	userUpdatePeriodic      *task.Periodic
	nodeInfoMonitorPeriodic *task.Periodic
}

func NewController(ctx context.Context, config *Config) (*Controller, error) {
	controller := new(Controller)
	controller.Context = ctx
	controller.ApiClient = api.NewClient(config.GetApiServer(), int(config.GetNodeId()), config.GetKey())
	return controller, nil
}

func (c *Controller) Type() interface{} {
	return controllerInterface.Type()
}

func (c *Controller) Start() error {
	var err error
	c.nodeInfo, err = c.fetchNodeInfo()
	if err != nil {
		err.(*errors.Error).AtError().WriteToLog()
		os.Exit(23)
	}
	inboundConfig, outboundConfig, err := c.getConfigFromRemote()
	if err != nil {
		panic(newError("controller start failed").Base(err))
	}

	server := core.MustFromContext(c.Context)
	err = core.AddInboundHandler(server, inboundConfig)
	if err != nil {
		panic(newError("add inboundConfig failed").Base(err))
	}

	err = core.AddOutboundHandler(server, outboundConfig)
	if err != nil {
		panic(newError("add outboundConfig failed").Base(err))
	}

	err = c.getUserFromRemote()
	if err != nil {
		panic(newError("add outboundConfig failed").Base(err))
	}

	err = c.startNodeInfoMonitor()
	if err != nil {
		panic(newError("start node info monitor task failed").Base(err))
	}

	return nil
}

func (c *Controller) Close() error {
	if c.userUpdatePeriodic != nil {
		err := c.userUpdatePeriodic.Close()
		if err != nil {
			newError("user update periodic close failed").Base(err).AtError().WriteToLog()
		}
	}

	if c.nodeInfoMonitorPeriodic != nil {
		err := c.nodeInfoMonitorPeriodic.Close()
		if err != nil {
			newError("user update periodic close failed").Base(err).AtError().WriteToLog()
		}
	}
	return nil
}

func (c *Controller) GetNodeInfo() *api.NodeInfo {
	return c.nodeInfo
}

func (c *Controller) fetchNodeInfo() (*api.NodeInfo, error) {
	var nodeInfo *api.NodeInfo
	var err error
	err = retry.ExponentialBackoff(3, 200).On(func() error {
		nodeInfo, err = c.ApiClient.GetNodeInfo()
		return err
	})
	if err != nil {
		return nil, newError("fetch node info failed").Base(err)
	}
	return nodeInfo, nil
}

func (c *Controller) getConfigFromRemote() (*core.InboundHandlerConfig, *core.OutboundHandlerConfig, error) {

	inboundConfig, err := c.buildInboundConfig(c.nodeInfo)
	if err != nil {
		return nil, nil, newError("build config error").Base(err)
	}

	outboundConfig, err := c.buildOutboundConfig(c.nodeInfo)
	if err != nil {
		return nil, nil, newError("build config error").Base(err)
	}

	return inboundConfig, outboundConfig, nil
}

func (c *Controller) buildInboundConfig(info *api.NodeInfo) (*core.InboundHandlerConfig, error) {
	receiverSettings := &proxyman.ReceiverConfig{}
	receiverSettings.PortRange = &net.PortRange{
		From: uint32(info.V2Port),
		To:   uint32(info.V2Port),
	}
	receiverSettings.SniffingSettings = &proxyman.SniffingConfig{
		Enabled:             true,
		DestinationOverride: []string{"http", "tls"},
	}

	networkType, err := conf.TransportProtocol(info.V2Net).Build()
	if err != nil {
		return nil, newError("convert v2net failed").Base(err)
	}

	receiverSettings.StreamSettings = &internet.StreamConfig{
		ProtocolName: networkType,
	}

	if info.V2TLS {
		tlsConfig := new(tls.Config)
		tlsConfig.AllowInsecure = true
		tlsConfig.AllowInsecureCiphers = true

		var certificate *tls.Certificate
		if info.Key != "" && info.Cert != "" {
			certificate = new(tls.Certificate)
			certificate.Key = []byte(info.Key)
			certificate.Certificate = []byte(info.Cert)
			certificate.Usage = tls.Certificate_ENCIPHERMENT
		} else {
			if info.V2TLSProvider == "" {
				return nil, newError("V2TLSProvider is empty")
			}
			acmeConfig, err := acme.ConfigFromString(info.V2TLSProvider)
			if err != nil {
				return nil, err
			}

			acmeConfig.Domain = info.V2Host
			certificate, err = acme.AutoCert(acmeConfig)
			if err != nil {
				fmt.Println(newError("auto cert failed").Base(err).String())
				os.Exit(23)
			}

			err = c.ApiClient.PushCertification(&api.Certificate{
				Key: string(certificate.Key),
				Pem: string(certificate.Certificate),
			})
			if err != nil {
				return nil, err
			}
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content:  "push certfication success",
			})
		}

		// add config
		tlsConfig.Certificate = append(tlsConfig.Certificate, certificate)
		tm := serial.ToTypedMessage(tlsConfig)
		receiverSettings.StreamSettings.SecurityType = tm.Type
		receiverSettings.StreamSettings.SecuritySettings = append(receiverSettings.StreamSettings.SecuritySettings, tm)
	}

	if networkType == "websocket" {
		wsconfig := &websocket.Config{
			Path: info.V2Path,
			Header: []*websocket.Header{
				&websocket.Header{
					Key:   "host",
					Value: info.V2Host,
				},
			},
		}

		receiverSettings.StreamSettings.TransportSettings = append(receiverSettings.StreamSettings.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(wsconfig),
		})
	}

	vmessConfig := &vmess_inbound.Config{}

	return &core.InboundHandlerConfig{
		Tag:              "vmess",
		ReceiverSettings: serial.ToTypedMessage(receiverSettings),
		ProxySettings:    serial.ToTypedMessage(vmessConfig),
	}, nil
}

func (c *Controller) buildOutboundConfig(info *api.NodeInfo) (*core.OutboundHandlerConfig, error) {

	sendConfig := &proxyman.SenderConfig{}

	freedomConfig := &freedom.Config{
		DomainStrategy: freedom.Config_USE_IP,
	}

	return &core.OutboundHandlerConfig{
		SenderSettings: serial.ToTypedMessage(sendConfig),
		ProxySettings:  serial.ToTypedMessage(freedomConfig),
	}, nil
}

func (c *Controller) getUserFromRemote() error {
	updateUserFunc := func() error {
		return core.RequireFeatures(c.Context, func(manager inbound.Manager) error {
			handler, err := manager.GetHandler(c.Context, "vmess")
			if err != nil {
				return newError("get vmess handler failed").Base(err)
			}

			inboundInstance, ok := handler.(proxy.GetInbound)
			if !ok {
				return newError("vmess handler is not implement proxy.GetInbound")
			}

			userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
			if !ok {
				return newError("vmess handler is not implement proxy.UserManager")
			}

			vmessUserList, err := c.ApiClient.GetUserList()
			memoryUserList := make([]*protocol.MemoryUser, 0, 128)
			if err != nil {
				return err
			}
			for _, item := range vmessUserList {
				user := new(protocol.MemoryUser)
				user.Email = strconv.Itoa(item.UID)
				account := new(vmess.MemoryAccount)

				if c.nodeInfo.SpeedLimit == 0 || c.nodeInfo.SpeedLimit > item.SpeedLimit {
					account.Limit = item.SpeedLimit
				} else {
					account.Limit = c.nodeInfo.SpeedLimit
				}

				id, err := uuid.ParseString(item.VmessUID)
				if err != nil {
					newError("add user failed").Base(err).AtError().WriteToLog()
					continue
				}
				account.ID = protocol.NewID(id)
				account.AlterIDs = protocol.NewAlterIDs(account.ID, uint16(c.nodeInfo.V2AlterID))
				user.Account = account
				memoryUserList = append(memoryUserList, user)
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Debug,
					Content:  fmt.Sprintf("reload uid: %s with limit: %d", user.Email, account.Limit),
				})
			}
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content:  fmt.Sprintf("updater reload %d user", len(memoryUserList)),
			})
			if err := userManager.ResetUser(c.Context, memoryUserList); err != nil {
				runtime.GC()
				return err
			}
			return nil
		})
	}

	c.userUpdatePeriodic = &task.Periodic{
		Interval: 60 * time.Second,
		Execute: func() error {
			err := updateUserFunc()
			if err != nil {
				newError("update user peridoic failed").Base(err).AtError().WriteToLog()
				return nil
			}
			return nil
		},
	}

	return c.userUpdatePeriodic.Start()
}

func (c *Controller) startNodeInfoMonitor() error {
	c.nodeInfoMonitorPeriodic = &task.Periodic{
		Interval: 60 * time.Second,
		Execute: func() error {
			nodeInfo, err := c.fetchNodeInfo()
			if err != nil {
				newError("get node info error").Base(err).AtError().WriteToLog()
				return nil
			}
			if diff.Changed(c.nodeInfo, nodeInfo) {
				fmt.Println(newError("node info changed!!!").String())
				os.Exit(23)
			}
			return nil
		},
	}
	return c.nodeInfoMonitorPeriodic.Start()
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewController(ctx, cfg.(*Config))
	}))
}
