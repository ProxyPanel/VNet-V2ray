package dispatcher

import (
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/features/traffic"
)

type TrafficWriter struct {
	TM     traffic.Manager
	Key    string
	Writer buf.Writer
	Up     bool
}

func (t TrafficWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if t.Up {
		t.TM.Up(t.Key, uint64(mb.Len()))
	} else {
		t.TM.Down(t.Key, uint64(mb.Len()))
	}
	return t.Writer.WriteMultiBuffer(mb)
}

func (w *TrafficWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *TrafficWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
