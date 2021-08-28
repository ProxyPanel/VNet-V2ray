// +build !confonly
package history

import (
	"context"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/features/history"
	"time"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

type History struct {
	context context.Context
	*api.ApiClient
	historyChan      chan *api.History
	historyArray     []*api.History
	workerCtx        context.Context
	workerCancelFunc context.CancelFunc
}

func NewHistory(context context.Context, config *Config) (*History, error) {
	h := new(History)
	h.context = context
	h.ApiClient = api.NewClient(config.GetApiServer(), int(config.GetNodeId()), config.GetKey())
	h.historyChan = make(chan *api.History, 128)
	h.historyArray = make([]*api.History, 0, 256)
	return h, nil
}

func (h *History) Type() interface{} {
	return history.Type()
}

func (h *History) Start() error {
	h.workerCtx, h.workerCancelFunc = context.WithCancel(h.context)
	go h.worker()
	return nil
}

func (h *History) Close() error {
	h.workerCancelFunc()
	return nil
}

func (h *History) Record(ctx context.Context, history *api.History) error {
	h.historyChan <- history
	return nil
}

func (h *History) worker() {
	for {
		select {
		case item := <-h.historyChan:
			h.historyArray = append(h.historyArray, item)
			if len(h.historyArray) == 256 {
				tmpHistoryArray := h.historyArray
				h.historyArray = make([]*api.History, 0, 256)
				go func() {
					h.ApiClient.History(tmpHistoryArray)
				}()
			}
		case <-time.After(3 * time.Second):
			if len(h.historyArray) > 0 {
				tmpHistoryArray := h.historyArray
				h.historyArray = make([]*api.History, 0, 256)
				go func() {
					h.ApiClient.History(tmpHistoryArray)
				}()
			}
		case <-h.workerCtx.Done():
			break
		}
	}
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewHistory(ctx, cfg.(*Config))
	}))
}
