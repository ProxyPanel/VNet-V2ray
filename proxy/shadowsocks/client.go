// +build !confonly

package shadowsocks

import (
	"context"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/retry"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/signal"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/features/policy"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

// Client is a inbound handler for Shadowsocks protocol
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
}

// NewClient create a new Shadowsocks client.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Server {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to parse server spec").Base(err)
		}
		serverList.AddServer(s)
	}
	if serverList.Size() == 0 {
		return nil, newError("0 server")
	}

	v := core.MustFromContext(ctx)
	client := &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	return client, nil
}

// Process implements OutboundHandler.Process().
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target
	network := destination.Network

	var server *protocol.ServerSpec
	var conn internet.Connection

	err := retry.ExponentialBackoff(5, 100).On(func() error {
		server = c.serverPicker.PickServer()
		dest := server.Destination()
		dest.Network = network
		rawConn, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		conn = rawConn

		return nil
	})
	if err != nil {
		return newError("failed to find an available destination").AtWarning().Base(err)
	}
	newError("tunneling request to ", destination, " via ", server.Destination()).WriteToLog(session.ExportIDToError(ctx))

	defer conn.Close()

	request := &protocol.RequestHeader{
		Version: Version,
		Address: destination.Address,
		Port:    destination.Port,
	}
	if destination.Network == net.Network_TCP {
		request.Command = protocol.RequestCommandTCP
	} else {
		request.Command = protocol.RequestCommandUDP
	}

	user := server.PickUser()
	_, ok := user.Account.(*MemoryAccount)
	if !ok {
		return newError("user account is not valid")
	}
	request.User = user

	sessionPolicy := c.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	if request.Command == protocol.RequestCommandTCP {
		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		bodyWriter, err := WriteTCPRequest(request, bufferedWriter)
		if err != nil {
			return newError("failed to write request").Base(err)
		}

		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, bodyWriter, buf.UpdateActivity(timer))
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			responseReader, err := ReadTCPResponse(user, conn)
			if err != nil {
				return err
			}

			return buf.Copy(responseReader, link.Writer, buf.UpdateActivity(timer))
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return newError("connection ends").Base(err)
		}

		return nil
	}

	if request.Command == protocol.RequestCommandUDP {
		writer := &buf.SequentialWriter{Writer: &UDPWriter{
			Writer:  conn,
			Request: request,
		}}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
				return newError("failed to transport all UDP request").Base(err)
			}
			return nil
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			reader := &UDPReader{
				Reader: conn,
				User:   user,
			}

			if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
				return newError("failed to transport all UDP response").Base(err)
			}
			return nil
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return newError("connection ends").Base(err)
		}

		return nil
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
