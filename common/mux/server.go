package mux

import (
	"context"
	"crypto/tls"
	"io"
	net2 "net"
	"strings"
	"time"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/httpx"
	"github.com/v2fly/v2ray-core/v4/common/log"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/tlsx"
	controllerInterface "github.com/v2fly/v2ray-core/v4/features/controller"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/pipe"
)

type Server struct {
	dispatcher routing.Dispatcher
	controller controllerInterface.Controller
}

// NewServer creates a new mux.Server.
func NewServer(ctx context.Context) *Server {
	s := &Server{}
	core.RequireFeatures(ctx, func(d routing.Dispatcher) {
		s.dispatcher = d
	})

	core.RequireFeatures(ctx, func(c controllerInterface.Controller) {
		s.controller = c
	})
	return s
}

// Type implements common.HasType.
func (s *Server) Type() interface{} {
	return s.dispatcher.Type()
}

// Dispatch implements routing.Dispatcher
func (s *Server) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if dest.Address != muxCoolAddress {
		return s.dispatcher.Dispatch(ctx, dest)
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	serverWorder, err := NewServerWorker(ctx, s.dispatcher, &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	})
	if err != nil {
		return nil, err
	}
	serverWorder.SetController(s.controller)

	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
}

// Start implements common.Runnable.
func (s *Server) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *Server) Close() error {
	return nil
}

type ServerWorker struct {
	dispatcher     routing.Dispatcher
	link           *transport.Link
	sessionManager *SessionManager
	controller     controllerInterface.Controller
}

func NewServerWorker(ctx context.Context, d routing.Dispatcher, link *transport.Link) (*ServerWorker, error) {
	worker := &ServerWorker{
		dispatcher:     d,
		link:           link,
		sessionManager: NewSessionManager(),
	}

	go worker.run(ctx)
	return worker, nil
}

func handle(ctx context.Context, s *Session, output buf.Writer) {
	writer := NewResponseWriter(s.ID, output, s.transferType)
	if err := buf.Copy(s.input, writer); err != nil {
		newError("session ", s.ID, " ends.").Base(err).WriteToLog(session.ExportIDToError(ctx))
		writer.hasError = true
	}

	writer.Close()
	s.Close()
}

func (w *ServerWorker) SetController(c controllerInterface.Controller) {
	w.controller = c
}

func (w *ServerWorker) ActiveConnections() uint32 {
	return uint32(w.sessionManager.Size())
}

func (w *ServerWorker) Closed() bool {
	return w.sessionManager.Closed()
}

func (w *ServerWorker) handleStatusKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleStatusNew(ctx context.Context, meta *FrameMetadata, reader *buf.BufferedReader) error {
	newError("received request for ", meta.Target).WriteToLog(session.ExportIDToError(ctx))
	{
		msg := &log.AccessMessage{
			To:     meta.Target,
			Status: log.AccessAccepted,
			Reason: "",
		}
		if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
			msg.From = inbound.Source
			msg.Email = inbound.User.Email
		}
		ctx = log.ContextWithAccessMessage(ctx, msg)
	}
	link, err := w.dispatcher.Dispatch(ctx, meta.Target)
	if err != nil {
		// reject return redirect
		if strings.Contains(err.Error(), "destination is reject by rule") {
			w.doRedirect(ctx, meta, reader)
			return nil
		}

		if meta.Option.Has(OptionData) {
			buf.Copy(NewStreamReader(reader), buf.Discard)
		}
		return newError("failed to dispatch request.").Base(err)
	}
	s := &Session{
		input:        link.Reader,
		output:       link.Writer,
		parent:       w.sessionManager,
		ID:           meta.SessionID,
		transferType: protocol.TransferTypeStream,
	}
	if meta.Target.Network == net.Network_UDP {
		s.transferType = protocol.TransferTypePacket
	}
	w.sessionManager.Add(s)
	go handle(ctx, s, w.link.Writer)
	if !meta.Option.Has(OptionData) {
		return nil
	}

	rr := s.NewReader(reader)
	if err := buf.Copy(rr, s.output); err != nil {
		buf.Copy(rr, buf.Discard)
		common.Interrupt(s.input)
		return s.Close()
	}
	return nil
}

func (w *ServerWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := w.sessionManager.Get(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader)
	err := buf.Copy(rr, s.output)

	if err != nil && buf.IsWriteError(err) {
		newError("failed to write to downstream writer. closing session ", s.ID).Base(err).WriteToLog()

		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, w.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		drainErr := buf.Copy(rr, buf.Discard)
		common.Interrupt(s.input)
		s.Close()
		return drainErr
	}

	return err
}

func (w *ServerWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := w.sessionManager.Get(meta.SessionID); found {
		if meta.Option.Has(OptionError) {
			common.Interrupt(s.input)
			common.Interrupt(s.output)
		}
		s.Close()
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (w *ServerWorker) handleFrame(ctx context.Context, reader *buf.BufferedReader) error {
	var meta FrameMetadata
	err := meta.Unmarshal(reader)
	if err != nil {
		return newError("failed to read metadata").Base(err)
	}

	switch meta.SessionStatus {
	case SessionStatusKeepAlive:
		err = w.handleStatusKeepAlive(&meta, reader)
	case SessionStatusEnd:
		err = w.handleStatusEnd(&meta, reader)
	case SessionStatusNew:
		err = w.handleStatusNew(ctx, &meta, reader)
	case SessionStatusKeep:
		err = w.handleStatusKeep(&meta, reader)
	default:
		status := meta.SessionStatus
		return newError("unknown status: ", status).AtError()
	}

	if err != nil {
		return newError("failed to process data").Base(err)
	}
	return nil
}

func (w *ServerWorker) run(ctx context.Context) {
	input := w.link.Reader
	reader := &buf.BufferedReader{Reader: input}

	defer w.sessionManager.Close() // nolint: errcheck

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := w.handleFrame(ctx, reader)
			if err != nil {
				if errors.Cause(err) != io.EOF {
					newError("unexpected EOF").Base(err).WriteToLog(session.ExportIDToError(ctx))
					common.Interrupt(input)
				}
				return
			}
		}
	}
}

func (w *ServerWorker) doRedirect(ctx context.Context, meta *FrameMetadata, rawReader *buf.BufferedReader) {
	if meta.Target.Network == net.Network_UDP {
		return
	}

	var nodeInfo *api.NodeInfo
	if w.controller != nil {
		nodeInfo = w.controller.GetNodeInfo()
	}

	opts := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	s := &Session{
		input:        inboundLink.Reader,
		output:       inboundLink.Writer,
		parent:       w.sessionManager,
		ID:           meta.SessionID,
		transferType: protocol.TransferTypeStream,
	}
	w.sessionManager.Add(s)

	go handle(ctx, s, w.link.Writer)
	reader := s.NewReader(rawReader)
	if err := buf.Copy(reader, s.output); err != nil {
		buf.Copy(reader, buf.Discard)
		common.Interrupt(s.input)
		return
	}

	go func() {
		bufferedReader := &buf.BufferedReader{Reader: outboundLink.Reader}
		bufferedWriter := buf.NewBufferedWriter(outboundLink.Writer)
		defer bufferedWriter.Flush()
		defer w.sessionManager.Remove(s.ID)
		defer common.Interrupt(bufferedReader)
		defer common.Interrupt(bufferedWriter)

		if meta.Target.Port == 80 {
			// if n	ode info contain redirect url then return http status with 302 otherwise return 403 with default content
			if nodeInfo.RedirectUrl == "" {
				bufferedWriter.Write([]byte(httpx.Http403("该网站被阻止访问，如需访问请联系管理员。\r\n")))
			} else {
				bufferedWriter.Write([]byte(httpx.Http302(nodeInfo.RedirectUrl)))
			}
			return
		}

		if meta.Target.Port == 443 {
			fakeConn := FakeConnection{
				Writer: bufferedWriter,
				Reader: bufferedReader,
			}
			cert := []byte("-----BEGIN CERTIFICATE-----\nMIIBpTCCAUugAwIBAgIBATAKBggqhkjOPQQDAjAvMQ8wDQYDVQQKEwZLaXRhbWkx\nHDAaBgNVBAMTE0tpdGFtaSBHZW5lcmF0ZWQgQ0EwHhcNMjAwNjIxMTUyMTM3WhcN\nMjUwNjIxMTUyMTM3WjAvMQ8wDQYDVQQKEwZLaXRhbWkxHDAaBgNVBAMTE0tpdGFt\naSBHZW5lcmF0ZWQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKxhL2sjdx\nFn8TOC7KvmePl7AnW4+epS2biDH3Y4Ren8hcxsCJFKBi+gsBOKvE8eea8jWdDuVI\ndFtkxYHFlCpeo1gwVjAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUH\nAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxo\nb3N0MAoGCCqGSM49BAMCA0gAMEUCIQCPR9LpVAXlHarNTcchaZHEmNpdljbGussu\nzVqa6IcqtQIgDGMoYFeIu2izpUA8cUi8ad1mvupzshQCq4G1XMtG/Rc=\n-----END CERTIFICATE-----")
			key := []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICNABHyNkPZgcOtSHcnzI/PjAolsq2kGq0c+rB1JEW03oAoGCCqGSM49\nAwEHoUQDQgAECsYS9rI3cRZ/Ezguyr5nj5ewJ1uPnqUtm4gx92OEXp/IXMbAiRSg\nYvoLATirxPHnmvI1nQ7lSHRbZMWBxZQqXg==\n-----END EC PRIVATE KEY-----")
			certGen, keyGen, err := tlsx.MakeCertForUrl(cert, key, meta.Target.String())
			if err != nil {
				newError("tlsx make cert failed").Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
				return
			}

			config := &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{certGen},
						PrivateKey:  keyGen,
					},
				},
			}
			tlsConn := tls.Server(fakeConn, config)

			// if node info contain redirect url then return http status with 302 otherwise return 403 with default content
			if nodeInfo.RedirectUrl == "" {
				_, err = tlsConn.Write([]byte(httpx.Http403("该网站被阻止访问，如需访问请联系管理员。\r\n")))

			} else {
				_, err = tlsConn.Write([]byte(httpx.Http302(nodeInfo.RedirectUrl)))
			}

			if err != nil {
				newError("tls write failed").Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
				return
			}
		}
	}()
}

type FakeConnection struct {
	io.Reader
	io.Writer
}

func (f FakeConnection) Close() error {
	return nil
}

func (f FakeConnection) LocalAddr() net2.Addr {
	panic("implement me")
}

func (f FakeConnection) RemoteAddr() net2.Addr {
	panic("implement me")
}

func (f FakeConnection) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (f FakeConnection) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (f FakeConnection) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func (f FakeConnection) Read(b []byte) (n int, err error) {
	return f.Reader.Read(b)
}

func (f FakeConnection) Write(b []byte) (n int, err error) {
	defer f.Writer.(*buf.BufferedWriter).Flush()
	return f.Writer.Write(b)
}
