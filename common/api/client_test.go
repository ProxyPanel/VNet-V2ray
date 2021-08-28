package api_test

import (
	"testing"

	. "github.com/v2fly/v2ray-core/v4/common/api"
)

func CreateClient() *ApiClient {
	client := NewClient("https://v.rcauth.com", 1, "yxl5yqkh")

	return client
}

func TestApiClient_GetNodeInfo(t *testing.T) {
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestApiClient_ReportNodeStatus(t *testing.T) {
	client := CreateClient()
	err := client.ReportNodeStatus(&NodeStatus{
		CPU:    "1",
		Mem:    "1",
		Net:    "1",
		Disk:   "1",
		Uptime: 0,
	})
	if err != nil {
		t.Error(err)
	}
}

func TestApiClient_GetUserList(t *testing.T) {
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	t.Log(userList)
}

func TestApiClient_ReportUserTraffic(t *testing.T) {
	userTrafficList := make([]*UserTraffic, 0)
	userTrafficList = append(userTrafficList, &UserTraffic{
		UID:      1,
		Upload:   409600,
		Download: 409600,
	})
	client := CreateClient()
	err := client.ReportUserTraffic(userTrafficList)
	if err != nil {
		t.Error(err)
	}
}

func TestApiClient_PushCertification(t *testing.T) {
	client := CreateClient()
	certificate := &Certificate{
		Key: "123",
		Pem: "123",
	}
	err := client.PushCertification(certificate)
	if err != nil {
		t.Error(err)
	}
}

func TestApiClient_History(t *testing.T) {
	client := CreateClient()
	history := &History{
		UID: 9,
		URL: "baidu.com",
	}
	err := client.History([]*History{history})
	if err != nil {
		t.Error(err)
	}
}

func TestApiClient_ReportIllegal(t *testing.T) {
	client := CreateClient()
	illegalReport := &IllegalReport{
		UID:    1,
		RuleID: 0,
		Reason: "test",
	}
	err := client.ReportIllegal([]*IllegalReport{illegalReport})
	if err != nil {
		t.Error(err)
	}
}

func TestApiClient_ReportNodeOnline(t *testing.T) {
	client := CreateClient()
	nodeOnline := &NodeOnline{
		UID: 1,
		IP:  "192.168.0.1",
	}
	err := client.ReportNodeOnline([]*NodeOnline{nodeOnline})
	if err != nil {
		t.Error(err)
	}
}
