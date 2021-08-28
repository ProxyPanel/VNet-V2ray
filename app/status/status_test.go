package status_test

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"

	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/common/task"
)

func ExampleGOUtils() {
	memoryStat := common.Must2(mem.VirtualMemory()).(*mem.VirtualMemoryStat)
	fmt.Println(memoryStat)
	var send uint64
	var recv uint64
	var flag bool = false
	periodic := &task.Periodic{
		Interval: 1 * time.Second,
		Execute: func() error {
			iocounter := common.Must2(net.IOCounters(false)).([]net.IOCountersStat)
			up := iocounter[0].BytesSent - send
			down := iocounter[0].BytesRecv - recv
			if !flag {
				send = iocounter[0].BytesSent
				recv = iocounter[0].BytesRecv
				flag = true
				return nil
			}
			fmt.Printf("上传: %4d - 下载: %4d\n", up, down)
			return nil
		},
	}
	err := periodic.Start()
	if err != nil {
		fmt.Println(err)
	}
	time.Sleep(10 * time.Second)
	// Output:

}

func ExampleStatus() {

	// Output:

}
