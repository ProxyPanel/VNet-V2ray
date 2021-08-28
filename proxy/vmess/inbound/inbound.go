// +build !confonly

package inbound

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

import (
	"context"
	"crypto/tls"
	"github.com/v2fly/v2ray-core/v4/features/history"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/app/rule"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/httpx"
	"github.com/v2fly/v2ray-core/v4/common/log"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/platform"
	"github.com/v2fly/v2ray-core/v4/common/protocol"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/signal"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/common/tlsx"
	"github.com/v2fly/v2ray-core/v4/common/uuid"
	controllerInterface "github.com/v2fly/v2ray-core/v4/features/controller"
	feature_inbound "github.com/v2fly/v2ray-core/v4/features/inbound"
	"github.com/v2fly/v2ray-core/v4/features/policy"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess"
	"github.com/v2fly/v2ray-core/v4/proxy/vmess/encoding"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

type userByEmail struct {
	sync.Mutex
	cache           map[string]*protocol.MemoryUser
	limiter         map[string]*buf.ProxyLimiter
	defaultLevel    uint32
	defaultAlterIDs uint16
}

func newUserByEmail(config *DefaultConfig) *userByEmail {
	return &userByEmail{
		cache:           make(map[string]*protocol.MemoryUser),
		limiter:         make(map[string]*buf.ProxyLimiter),
		defaultLevel:    config.Level,
		defaultAlterIDs: uint16(config.AlterId),
	}
}

func (v *userByEmail) ResetUsers(users []*protocol.MemoryUser) error {
	newCache := make(map[string]*protocol.MemoryUser)
	newLimiter := make(map[string]*buf.ProxyLimiter)

	for _, item := range users {
		newCache[item.Email] = item
		account := item.Account.(*vmess.MemoryAccount)
		if account.Limit > 0 {
			newLimiter[item.Email] = buf.NewProxyLimiter(account.Limit)
		}
	}

	v.Lock()
	defer v.Unlock()
	v.cache = newCache
	v.limiter = newLimiter

	return nil
}

func (v *userByEmail) addNoLock(u *protocol.MemoryUser) bool {
	email := strings.ToLower(u.Email)
	_, found := v.cache[email]
	if found {
		return false
	}
	v.cache[email] = u
	account := u.Account.(*vmess.MemoryAccount)
	if account.Limit > 0 {
		v.limiter[email] = buf.NewProxyLimiter(account.Limit)
	}
	return true
}

func (v *userByEmail) Exist(email string) bool {
	_, found := v.cache[email]
	return found
}

func (v *userByEmail) Add(u *protocol.MemoryUser) bool {
	v.Lock()
	defer v.Unlock()

	return v.addNoLock(u)
}

func (v *userByEmail) Get(email string) (*protocol.MemoryUser, bool) {
	email = strings.ToLower(email)

	v.Lock()
	defer v.Unlock()

	user, found := v.cache[email]
	if !found {
		id := uuid.New()
		rawAccount := &vmess.Account{
			Id:      id.String(),
			AlterId: uint32(v.defaultAlterIDs),
		}
		account, err := rawAccount.AsAccount()
		common.Must(err)
		user = &protocol.MemoryUser{
			Level:   v.defaultLevel,
			Email:   email,
			Account: account,
		}
		v.cache[email] = user
	}
	return user, found
}

func (v *userByEmail) GetLimiter(email string) *buf.ProxyLimiter {
	email = strings.ToLower(email)

	v.Lock()
	defer v.Unlock()
	limter, found := v.limiter[email]
	if found {
		return limter
	}

	return nil
}

func (v *userByEmail) Remove(email string) bool {
	email = strings.ToLower(email)

	v.Lock()
	defer v.Unlock()

	if _, found := v.cache[email]; !found {
		return false
	}
	delete(v.cache, email)

	if _, found := v.limiter[email]; !found {
		return false
	}
	delete(v.limiter, email)

	return true
}

// Handler is an inbound connection handler that handles messages in VMess protocol.
type Handler struct {
	policyManager         policy.Manager
	inboundHandlerManager feature_inbound.Manager
	clients               *vmess.TimedUserValidator
	usersByEmail          *userByEmail
	detours               *DetourConfig
	sessionHistory        *encoding.SessionHistory
	secure                bool
	userLinksLock         sync.Locker
	userLinks             map[string][]*transport.Link
	ruleManager           *rule.RuleManager
	controller            controllerInterface.Controller
	history               history.History
}

// New creates a new VMess inbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		policyManager:         v.GetFeature(policy.ManagerType()).(policy.Manager),
		inboundHandlerManager: v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		clients:               vmess.NewTimedUserValidator(protocol.DefaultIDHash),
		detours:               config.Detour,
		usersByEmail:          newUserByEmail(config.GetDefaultValue()),
		sessionHistory:        encoding.NewSessionHistory(),
		secure:                config.SecureEncryptionOnly,
		userLinksLock:         new(sync.Mutex),
		userLinks:             make(map[string][]*transport.Link),
		ruleManager:           core.MustFromContext(ctx).GetFeature(rule.Type()).(*rule.RuleManager),
		controller:            core.MustFromContext(ctx).GetFeature(controllerInterface.Type()).(controllerInterface.Controller),
		history:               core.MustFromContext(ctx).GetFeature(history.Type()).(history.History),
	}

	for _, user := range config.User {
		mUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, newError("failed to get VMess user").Base(err)
		}

		if err := handler.AddUser(ctx, mUser); err != nil {
			return nil, newError("failed to initiate user").Base(err)
		}
	}

	return handler, nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	return errors.Combine(
		h.clients.Close(),
		h.sessionHistory.Close(),
		common.Close(h.usersByEmail))
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (h *Handler) GetUser(email string) *protocol.MemoryUser {
	user, existing := h.usersByEmail.Get(email)
	if !existing {
		h.clients.Add(user)
	}
	return user
}

func (h *Handler) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if len(user.Email) > 0 && !h.usersByEmail.Add(user) {
		return newError("User ", user.Email, " already exists.")
	}
	return h.clients.Add(user)
}

func (h *Handler) ResetUser(ctx context.Context, user []*protocol.MemoryUser) error {
	if err := h.usersByEmail.ResetUsers(user); err != nil {
		return err
	}

	if err := h.clients.ResetUsers(user); err != nil {
		return err
	}

	h.userLinksLock.Lock()
	for k, v := range h.userLinks {

		if !h.usersByEmail.Exist(k) {
			for _, link := range v {
				if err := common.Close(link.Writer); err != nil {
					newError("close not exists user link error").Base(err).AtError().WriteToLog()
				}
				if err := common.Interrupt(link.Reader); err != nil {
					newError("close not exists user link error").Base(err).AtError().WriteToLog()
				}
			}
		}
	}
	h.userLinksLock.Unlock()
	return nil
}

func (h *Handler) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return newError("Email must not be empty.")
	}
	if !h.usersByEmail.Remove(email) {
		return newError("User ", email, " not found.")
	}
	h.clients.Remove(email)
	return nil
}

func transferResponse(timer signal.ActivityUpdater, session *encoding.ServerSession, request *protocol.RequestHeader, response *protocol.ResponseHeader, input buf.Reader, output *buf.BufferedWriter) error {
	session.EncodeResponseHeader(response, output)

	bodyWriter := session.EncodeResponseBody(request, output)

	{
		// Optimize for small response packet
		data, err := input.ReadMultiBuffer()
		if err != nil {
			return err
		}

		if err := bodyWriter.WriteMultiBuffer(data); err != nil {
			return err
		}
	}

	if err := output.SetBuffered(false); err != nil {
		return err
	}

	if err := buf.Copy(input, bodyWriter, buf.UpdateActivity(timer)); err != nil {
		return err
	}

	if request.Option.Has(protocol.RequestOptionChunkStream) {
		if err := bodyWriter.WriteMultiBuffer(buf.MultiBuffer{}); err != nil {
			return err
		}
	}

	return nil
}

func isInsecureEncryption(s protocol.SecurityType) bool {
	return s == protocol.SecurityType_NONE || s == protocol.SecurityType_LEGACY || s == protocol.SecurityType_UNKNOWN
}

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := h.policyManager.ForLevel(0)
	if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("unable to set read deadline").Base(err).AtWarning()
	}

	reader := buf.NewReader(connection)

	limitReader := &buf.LimitReader{
		Context: ctx,
		Limiter: nil,
		Reader:  reader,
	}

	bufferedReader := &buf.BufferedReader{Reader: limitReader}

	svrSession := encoding.NewServerSession(h.clients, h.sessionHistory)
	svrSession.SetAEADForced(aeadForced)
	request, err := svrSession.DecodeRequestHeader(bufferedReader)
	if err != nil {
		if errors.Cause(err) != io.EOF {
			log.Record(&log.AccessMessage{
				From:   connection.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			err = newError("invalid request from ", connection.RemoteAddr()).Base(err).AtInfo()
		}
		return err
	}

	uid, err := strconv.Atoi(request.User.Email)
	if err == nil {
		if h.history != nil {
			h.history.Record(ctx, &api.History{
				UID: uid,
				URL: request.Address.String(),
			})
		}
	} else {
		newError("uid convert error").Base(err).AtError().WriteToLog()
	}

	limiter := h.usersByEmail.GetLimiter(request.User.Email)
	if limiter != nil {
		limitReader.SetLimiter(limiter.Source.DownLimter)
		ctx = session.ContextWithProxyLimiter(ctx, limiter)
	}

	if h.secure && isInsecureEncryption(request.Security) {
		log.Record(&log.AccessMessage{
			From:   connection.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: "Insecure encryption",
			Email:  request.User.Email,
		})
		return newError("client is using insecure encryption: ", request.Security)
	}

	if request.Command != protocol.RequestCommandMux {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   connection.RemoteAddr(),
			To:     request.Destination(),
			Status: log.AccessAccepted,
			Reason: "",
			Email:  request.User.Email,
		})
	}

	newError("received request for ", request.Destination()).WriteToLog(session.ExportIDToError(ctx))

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		newError("unable to set back read deadline").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = request.User

	sessionPolicy = h.policyManager.ForLevel(request.User.Level)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	link, err := dispatcher.Dispatch(ctx, request.Destination())
	if err != nil {
		if strings.Contains(err.Error(), "destination is reject by rule") {
			if h.ruleManager != nil {
				if !h.ruleManager.Do(ctx, request.Destination()) {
					h.doRedirect(ctx, request, bufferedReader, svrSession, connection)
					return nil
				}
			}
		} else {
			return newError("failed to dispatch request to ", request.Destination()).Base(err)
		}
	}

	h.addLink(request.User, link)
	defer h.removeLink(request.User, link)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bodyReader := svrSession.DecodeRequestBody(request, bufferedReader)
		if err := buf.Copy(bodyReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transfer request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		writer := buf.NewWriter(connection)
		limiterWriter := &buf.LimitWriter{
			Context: ctx,
			Limiter: nil,
			Writer:  writer,
		}
		if limiter != nil {
			limiterWriter.SetLimiter(limiter.Source.UpLimiter)
		}

		bufferedWriter := buf.NewBufferedWriter(limiterWriter)
		defer bufferedWriter.Flush()

		response := &protocol.ResponseHeader{
			Command: h.generateCommand(ctx, request),
		}
		return transferResponse(timer, svrSession, request, response, link.Reader, bufferedWriter)
	}

	var requestDonePost = task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

func (h *Handler) doRedirect(ctx context.Context, request *protocol.RequestHeader, bufferReader *buf.BufferedReader, svrSession *encoding.ServerSession, connecton internet.Connection) {
	defer func() {
		if err := recover(); err != nil {
			newError("redirect error").Base(err.(error)).AtError().WriteToLog(session.ExportIDToError(ctx))
			return
		}
	}()
	var nodeInfo *api.NodeInfo
	if h.controller != nil {
		nodeInfo = h.controller.GetNodeInfo()
	}

	response := &protocol.ResponseHeader{
		Command: h.generateCommand(ctx, request),
	}
	svrSession.EncodeResponseHeader(response, connecton)
	write := svrSession.EncodeResponseBody(request, connecton)
	bufferedWriter := buf.NewBufferedWriter(write)
	defer bufferedWriter.Flush()

	reader := svrSession.DecodeRequestBody(request, bufferReader)
	bufferedReader := &buf.BufferedReader{Reader: reader}

	if request.Port == 80 {
		var tmpMBuf buf.MultiBuffer
		// if node info contain redirect url then return http status with 302 otherwise return 403 with default content
		if nodeInfo.Redirect == "" {
			tmpMBuf = buf.MultiBufferFromBytes([]byte(httpx.Http403("该网站被阻止访问，如需访问请联系管理员。\r\n")))
		} else {
			tmpMBuf = buf.MultiBufferFromBytes([]byte(httpx.Http302(nodeInfo.Redirect)))
		}
		bufferedWriter.WriteMultiBuffer(tmpMBuf)
		return
	}

	if request.Port == 443 {
		fakeConn := FakeConnection{
			Writer: bufferedWriter,
			Reader: bufferedReader,
			Conn:   connecton,
		}
		cert := []byte("-----BEGIN CERTIFICATE-----\nMIIBpTCCAUugAwIBAgIBATAKBggqhkjOPQQDAjAvMQ8wDQYDVQQKEwZLaXRhbWkx\nHDAaBgNVBAMTE0tpdGFtaSBHZW5lcmF0ZWQgQ0EwHhcNMjAwNjIxMTUyMTM3WhcN\nMjUwNjIxMTUyMTM3WjAvMQ8wDQYDVQQKEwZLaXRhbWkxHDAaBgNVBAMTE0tpdGFt\naSBHZW5lcmF0ZWQgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKxhL2sjdx\nFn8TOC7KvmePl7AnW4+epS2biDH3Y4Ren8hcxsCJFKBi+gsBOKvE8eea8jWdDuVI\ndFtkxYHFlCpeo1gwVjAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUH\nAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxo\nb3N0MAoGCCqGSM49BAMCA0gAMEUCIQCPR9LpVAXlHarNTcchaZHEmNpdljbGussu\nzVqa6IcqtQIgDGMoYFeIu2izpUA8cUi8ad1mvupzshQCq4G1XMtG/Rc=\n-----END CERTIFICATE-----")
		key := []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICNABHyNkPZgcOtSHcnzI/PjAolsq2kGq0c+rB1JEW03oAoGCCqGSM49\nAwEHoUQDQgAECsYS9rI3cRZ/Ezguyr5nj5ewJ1uPnqUtm4gx92OEXp/IXMbAiRSg\nYvoLATirxPHnmvI1nQ7lSHRbZMWBxZQqXg==\n-----END EC PRIVATE KEY-----")
		certGen, keyGen, err := tlsx.MakeCertForUrl(cert, key, request.Address.String())
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
		if nodeInfo.Redirect == "" {
			_, err = tlsConn.Write([]byte(httpx.Http403("该网站被阻止访问，如需访问请联系管理员。\r\n")))

		} else {
			_, err = tlsConn.Write([]byte(httpx.Http302(nodeInfo.Redirect)))
		}

		if err != nil {
			newError("tls write failed").Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
			return
		}

	}

}

func (h *Handler) generateCommand(ctx context.Context, request *protocol.RequestHeader) protocol.ResponseCommand {
	if h.detours != nil {
		tag := h.detours.To
		if h.inboundHandlerManager != nil {
			handler, err := h.inboundHandlerManager.GetHandler(ctx, tag)
			if err != nil {
				newError("failed to get detour handler: ", tag).Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
				return nil
			}
			proxyHandler, port, availableMin := handler.GetRandomInboundProxy()
			inboundHandler, ok := proxyHandler.(*Handler)
			if ok && inboundHandler != nil {
				if availableMin > 255 {
					availableMin = 255
				}

				newError("pick detour handler for port ", port, " for ", availableMin, " minutes.").AtDebug().WriteToLog(session.ExportIDToError(ctx))
				user := inboundHandler.GetUser(request.User.Email)
				if user == nil {
					return nil
				}
				account := user.Account.(*vmess.MemoryAccount)
				return &protocol.CommandSwitchAccount{
					Port:     port,
					ID:       account.ID.UUID(),
					AlterIds: uint16(len(account.AlterIDs)),
					Level:    user.Level,
					ValidMin: byte(availableMin),
				}
			}
		}
	}

	return nil
}

func (h *Handler) addLink(user *protocol.MemoryUser, link *transport.Link) {
	h.userLinksLock.Lock()
	defer h.userLinksLock.Unlock()

	if h.userLinks[user.Email] != nil {
		h.userLinks[user.Email] = append(h.userLinks[user.Email], link)
	} else {
		h.userLinks[user.Email] = make([]*transport.Link, 0, 16)
		h.userLinks[user.Email] = append(h.userLinks[user.Email], link)
	}
}

func (h *Handler) removeLink(user *protocol.MemoryUser, link *transport.Link) {
	h.userLinksLock.Lock()
	defer h.userLinksLock.Unlock()
	links, found := h.userLinks[user.Email]

	if !found {
		return
	}

	for i, t := range links {
		if unsafe.Pointer(t) == unsafe.Pointer(link) {
			newLinks := links
			newLinks[i] = newLinks[len(newLinks)-1]
			h.userLinks[user.Email] = newLinks[:len(newLinks)-1]
			return
		}
	}

}

type FakeConnection struct {
	io.Reader
	io.Writer
	net.Conn
}

func (f FakeConnection) Read(b []byte) (n int, err error) {
	return f.Reader.Read(b)
}

func (f FakeConnection) Write(b []byte) (n int, err error) {
	defer f.Writer.(*buf.BufferedWriter).Flush()
	return f.Writer.Write(b)
}

var (
	aeadForced     = false
	aeadForced2022 = false
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))

	defaultFlagValue := "NOT_DEFINED_AT_ALL"

	if time.Now().Year() >= 2022 {
		defaultFlagValue = "true_by_default_2022"
	}

	isAeadForced := platform.NewEnvFlag("v2ray.vmess.aead.forced").GetValue(func() string { return defaultFlagValue })
	if isAeadForced == "true" {
		aeadForced = true
	}

	if isAeadForced == "true_by_default_2022" {
		aeadForced = true
		aeadForced2022 = true
	}
}
