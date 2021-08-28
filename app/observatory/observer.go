// +build !confonly

package observatory

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/common"
	v2net "github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/signal/done"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/features/extension"
	"github.com/v2fly/v2ray-core/v4/features/outbound"
	"github.com/v2fly/v2ray-core/v4/transport/internet/tagged"
)

type Observer struct {
	config *Config
	ctx    context.Context

	statusLock sync.Mutex
	status     []*OutboundStatus

	finished *done.Instance

	ohm outbound.Manager
}

func (o *Observer) GetObservation(ctx context.Context) (proto.Message, error) {
	return &ObservationResult{Status: o.status}, nil
}

func (o *Observer) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *Observer) Start() error {
	if o.config != nil && len(o.config.SubjectSelector) != 0 {
		o.finished = done.New()
		go o.background()
	}
	return nil
}

func (o *Observer) Close() error {
	if o.finished != nil {
		return o.finished.Close()
	}
	return nil
}

func (o *Observer) background() {
	for !o.finished.Done() {
		hs, ok := o.ohm.(outbound.HandlerSelector)
		if !ok {
			newError("outbound.Manager is not a HandlerSelector").WriteToLog()
			return
		}

		outbounds := hs.Select(o.config.SubjectSelector)

		o.updateStatus(outbounds)

		for _, v := range outbounds {
			result := o.probe(v)
			o.updateStatusForResult(v, &result)
			if o.finished.Done() {
				return
			}
			time.Sleep(time.Second * 10)
		}
	}
}

func (o *Observer) updateStatus(outbounds []string) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	// TODO should remove old inbound that is removed
	_ = outbounds
}

func (o *Observer) probe(outbound string) ProbeResult {
	errorCollectorForRequest := newErrorCollector()

	httpTransport := http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return nil, nil
		},
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			var connection net.Conn
			taskErr := task.Run(ctx, func() error {
				// MUST use V2Fly's built in context system
				dest, err := v2net.ParseDestination(network + ":" + addr)
				if err != nil {
					return newError("cannot understand address").Base(err)
				}
				trackedCtx := session.TrackedConnectionError(o.ctx, errorCollectorForRequest)
				conn, err := tagged.Dialer(trackedCtx, dest, outbound)
				if err != nil {
					return newError("cannot dial remote address", dest).Base(err)
				}
				connection = conn
				return nil
			})
			if taskErr != nil {
				return nil, newError("cannot finish connection").Base(taskErr)
			}
			return connection, nil
		},
		TLSHandshakeTimeout: time.Second * 5,
	}
	httpClient := &http.Client{
		Transport: &httpTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar:     nil,
		Timeout: time.Second * 5,
	}
	var GETTime time.Duration
	err := task.Run(o.ctx, func() error {
		startTime := time.Now()
		response, err := httpClient.Get("https://api.v2fly.org/checkConnection.svgz")
		if err != nil {
			return newError("outbound failed to relay connection").Base(err)
		}
		if response.Body != nil {
			response.Body.Close()
		}
		endTime := time.Now()
		GETTime = endTime.Sub(startTime)
		return nil
	})
	if err != nil {
		fullerr := newError("underlying connection failed").Base(errorCollectorForRequest.UnderlyingError())
		fullerr = newError("with outbound handler report").Base(fullerr)
		fullerr = newError("GET request failed:", err).Base(fullerr)
		fullerr = newError("the outbound ", outbound, "is dead:").Base(fullerr)
		fullerr = fullerr.AtInfo()
		fullerr.WriteToLog()
		return ProbeResult{Alive: false, LastErrorReason: fullerr.Error()}
	}
	newError("the outbound ", outbound, "is alive:", GETTime.Seconds()).AtInfo().WriteToLog()
	return ProbeResult{Alive: true, Delay: GETTime.Milliseconds()}
}

func (o *Observer) updateStatusForResult(outbound string, result *ProbeResult) {
	o.statusLock.Lock()
	defer o.statusLock.Unlock()
	var status *OutboundStatus
	if location := o.findStatusLocationLockHolderOnly(outbound); location != -1 {
		status = o.status[location]
	} else {
		status = &OutboundStatus{}
		o.status = append(o.status, status)
	}

	status.LastTryTime = time.Now().Unix()
	status.OutboundTag = outbound
	status.Alive = result.Alive
	if result.Alive {
		status.Delay = result.Delay
		status.LastSeenTime = status.LastTryTime
		status.LastErrorReason = ""
	} else {
		status.LastErrorReason = result.LastErrorReason
		status.Delay = 99999999
	}
}

func (o *Observer) findStatusLocationLockHolderOnly(outbound string) int {
	for i, v := range o.status {
		if v.OutboundTag == outbound {
			return i
		}
	}
	return -1
}

func New(ctx context.Context, config *Config) (*Observer, error) {
	var outboundManager outbound.Manager
	err := core.RequireFeatures(ctx, func(om outbound.Manager) {
		outboundManager = om
	})
	if err != nil {
		return nil, newError("Cannot get depended features").Base(err)
	}
	return &Observer{
		config: config,
		ctx:    ctx,
		ohm:    outboundManager,
	}, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
