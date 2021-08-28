package status

import (
	"context"
	"fmt"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"

	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/common/log"
	"github.com/v2fly/v2ray-core/v4/common/retry"
	"github.com/v2fly/v2ray-core/v4/common/task"
)

type StatusRepoter struct {
	*api.ApiClient
	context.Context
	reportPeriodic *task.Periodic
}

func NewStatus(ctx context.Context, config *Config) (*StatusRepoter, error) {
	s := new(StatusRepoter)
	s.ApiClient = api.NewClient(config.GetApiServer(), int(config.GetNodeId()), config.GetKey())
	s.Context = ctx
	return s, nil
}

func (s *StatusRepoter) Type() interface{} {
	return (*StatusRepoter)(nil)
}

func (s *StatusRepoter) Start() error {
	var lastByteSend uint64
	var lastByteRecv uint64
	upTime := time.Now()
	firstCount := true

	periodic := time.Duration(60)

	s.reportPeriodic = &task.Periodic{
		Interval: periodic * time.Second,
		Execute: func() error {
			cpuUsage, err := cpu.Percent(0, false)
			if err != nil {
				newError("get cpu usage failed").Base(err).AtError().WriteToLog()
				return nil
			}

			memUsage, err := mem.VirtualMemory()
			if err != nil {
				newError("get mem usage failed").Base(err).AtError().WriteToLog()
				return nil
			}

			ioCounter, err := net.IOCounters(false)
			if err != nil {
				newError("get io counter failed").Base(err).AtError().WriteToLog()
				return nil
			}

			diskUsage, err := disk.Usage("/")
			if err != nil {
				newError("get disk usage failed").Base(err).AtError().WriteToLog()
				return nil
			}

			var up uint64
			var down uint64

			if !firstCount {
				up = ioCounter[0].BytesSent - lastByteSend
				down = ioCounter[0].BytesRecv - lastByteRecv
			}

			lastByteSend = ioCounter[0].BytesSent
			lastByteRecv = ioCounter[0].BytesRecv
			firstCount = false

			ns := &api.NodeStatus{
				CPU:    fmt.Sprintf("%.2f%%", cpuUsage[0]),
				Mem:    fmt.Sprintf("%.2f%%", memUsage.UsedPercent),
				Net:    fmt.Sprintf("%v↑ - %v↓", bytefmt.ByteSize(up/uint64(periodic)), bytefmt.ByteSize(down/uint64(periodic))),
				Disk:   fmt.Sprintf("%.2f%%", diskUsage.UsedPercent),
				Uptime: int(time.Since(upTime).Seconds()),
			}

			err = retry.ExponentialBackoff(3, 200).On(func() error {
				return s.ApiClient.ReportNodeStatus(ns)
			})

			if err != nil {
				newError("report node status failed").Base(err).AtError().WriteToLog()
			}

			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content:  "report node status success",
			})
			return nil
		},
	}

	return s.reportPeriodic.Start()
}

func (s *StatusRepoter) Close() error {
	return s.reportPeriodic.Close()
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewStatus(ctx, cfg.(*Config))
	}))
}
