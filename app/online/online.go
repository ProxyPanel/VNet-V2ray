package online

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"v2ray.com/core/common"
	"v2ray.com/core/common/api"
	"v2ray.com/core/common/log"
	"v2ray.com/core/common/retry"
	"v2ray.com/core/common/task"
)

type Online struct {
	UID    string
	IPLock sync.Locker
	IPs    map[string]bool
}

type OnlineRepoter struct {
	sync.Locker
	*api.ApiClient
	context.Context
	reportPeriodic *task.Periodic
	onlineCache    *sync.Map
}

func NewReport(ctx context.Context, config *Config) (*OnlineRepoter, error) {
	o := new(OnlineRepoter)
	o.Locker = new(sync.Mutex)
	o.ApiClient = api.NewClient(config.GetApiServer(), int(config.GetNodeId()), config.GetKey())
	o.Context = ctx
	o.onlineCache = new(sync.Map)
	return o, nil
}

func Type() interface{} {
	return (*OnlineRepoter)(nil)
}

func (r *OnlineRepoter) Online(uid string, ip string) {
	r.Locker.Lock()
	value, ok := r.onlineCache.Load(uid)
	r.Unlock()

	if !ok {
		o := new(Online)
		o.UID = uid
		o.IPLock = new(sync.Mutex)
		o.IPLock.Lock()
		defer o.IPLock.Unlock()
		o.IPs = make(map[string]bool)
		o.IPs[ip] = true
		r.onlineCache.Store(uid, o)
		return
	} else {
		o := value.(*Online)
		o.IPLock.Lock()
		defer o.IPLock.Unlock()
		o.IPs[ip] = true
	}
}

func (r *OnlineRepoter) Type() interface{} {
	return (*OnlineRepoter)(nil)
}

func (r *OnlineRepoter) Start() error {
	r.reportPeriodic = &task.Periodic{
		Interval: 60 * time.Second,
		Execute: func() error {
			r.Lock()
			oldOnlineCache := r.onlineCache
			r.onlineCache = new(sync.Map)
			r.Unlock()

			onlines := make([]*api.NodeOnline, 0)
			oldOnlineCache.Range(func(key, value interface{}) bool {
				item := value.(*Online)
				nodeOnline := new(api.NodeOnline)
				uid, err := strconv.Atoi(item.UID)
				if err != nil {
					newError("uid convert failed", item.UID).Base(err).AtError().WriteToLog()
					return true
				}

				nodeOnline.UID = uid
				ipsArray := make([]string, 0)
				item.IPLock.Lock()
				for key, _ := range item.IPs {
					ipsArray = append(ipsArray, key)
				}
				item.IPLock.Unlock()

				nodeOnline.IP = strings.Join(ipsArray, ",")

				onlines = append(onlines, nodeOnline)
				return true
			})

			if len(onlines) == 0 {
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Info,
					Content:  "no online need report",
				})
				return nil
			}

			err := retry.ExponentialBackoff(3, 200).On(func() error {
				return r.ApiClient.ReportNodeOnline(onlines)
			})

			if err != nil {
				newError("report online error").Base(err).AtError().WriteToLog()
				return nil
			}

			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content:  fmt.Sprintf("report online count: %d", len(onlines)),
			})

			return nil
		},
	}

	return r.reportPeriodic.Start()
}

func (r *OnlineRepoter) Close() error {
	return r.reportPeriodic.Close()
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewReport(ctx, cfg.(*Config))
	}))
}
