package traffic

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"v2ray.com/core/common"
	"v2ray.com/core/common/api"
	"v2ray.com/core/common/log"
	"v2ray.com/core/common/retry"
	"v2ray.com/core/common/task"
	tf_feature "v2ray.com/core/features/traffic"
)

type Traffic struct {
	Email    string
	Upload   uint64
	Download uint64
}

func (t *Traffic) Up(up uint64) uint64 {
	return atomic.AddUint64(&t.Upload, up)
}

func (t *Traffic) Down(down uint64) uint64 {
	return atomic.AddUint64(&t.Download, down)
}

type TrafficMessage struct {
	Key   string
	Type  string
	Count uint64
}

type Manager struct {
	ctx            context.Context
	trafficCache   *sync.Map
	reportPeriodic *task.Periodic
	trafficQueue   chan TrafficMessage
	queueCancel    context.CancelFunc
	*api.ApiClient
}

func NewManager(ctx context.Context, config *Config) (tf_feature.Manager, error) {
	m := new(Manager)
	m.ctx = ctx
	m.ApiClient = api.NewClient(config.ApiServer, int(config.NodeId), config.Key)
	m.trafficCache = new(sync.Map)
	m.trafficQueue = make(chan TrafficMessage, 2048)
	m.reportPeriodic = m.reportTask()
	return m, nil
}

func (m *Manager) GetTraffic(email string) tf_feature.Traffic {
	value, ok := m.trafficCache.Load(email)
	if ok {
		return value.(*Traffic)
	}

	t := new(Traffic)
	t.Email = email
	m.trafficCache.Store(email, t)
	return t
}

func (m *Manager) Up(key string, count uint64) {
	m.trafficQueue <- TrafficMessage{
		Key:   key,
		Type:  "up",
		Count: count,
	}
}

func (m *Manager) Down(key string, count uint64) {
	m.trafficQueue <- TrafficMessage{
		Key:   key,
		Type:  "down",
		Count: count,
	}
}

func (m *Manager) reportTask() *task.Periodic {
	return &task.Periodic{
		Interval: 60 * time.Second,
		Execute: func() error {
			m.report()
			return nil
		},
	}
}

func (m *Manager) report() {
	oldTrafficCache := m.trafficCache
	m.trafficCache = new(sync.Map)

	trafficList := make([]*api.UserTraffic, 0)
	oldTrafficCache.Range(func(k, v interface{}) bool {
		key := k.(string)
		item := v.(*Traffic)
		userTraffic := new(api.UserTraffic)
		uid, err := strconv.Atoi(key)
		if err != nil {
			newError("traffic report uid convert error", key).Base(err).AtError().WriteToLog()
			return true
		}
		userTraffic.UID = uid
		userTraffic.Download = int(item.Download)
		userTraffic.Upload = int(item.Upload)
		trafficList = append(trafficList, userTraffic)
		return true
	})

	if len(trafficList) == 0 {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "no traffic need report",
		})
		return
	}

	err := retry.ExponentialBackoff(3, 200).On(func() error {
		return m.ApiClient.ReportUserTraffic(trafficList)
	})
	if err != nil {
		newError("report user traffic error").Base(err).AtError().WriteToLog()
	}
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("report user traffic count: %d", len(trafficList)),
	})
}

func (m *Manager) queue() {
	ctx, queueCancel := context.WithCancel(m.ctx)
	m.queueCancel = queueCancel
	for {
		var trafficMessage TrafficMessage
		select {
		case <-ctx.Done():
			return
		case trafficMessage = <-m.trafficQueue:
		}
		traffic := m.GetTraffic(trafficMessage.Key)

		switch trafficMessage.Type {
		case "up":
			traffic.Up(trafficMessage.Count)
		case "down":
			traffic.Down(trafficMessage.Count)
		}
	}
}

func (m *Manager) Type() interface{} {
	return tf_feature.ManagerType()
}

func (m *Manager) Start() error {
	err := m.reportPeriodic.Start()
	if err != nil {
		return err
	}
	go m.queue()
	return nil
}

func (m *Manager) Close() error {
	err := m.reportPeriodic.Close()
	if err != nil {
		return err
	}
	m.queueCancel()
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewManager(ctx, config.(*Config))
	}))
}
