package api_test

import (
	"testing"
	. "v2ray.com/core/common/api"
)

func CreateClient() *ApiClient {
	client := NewClient("https://www.vnetpanel.com", 4, "nhwzntuetd2kkb5a")

	return client
}

func TestApiClient_GetNodeInfost(t *testing.T) {
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

func TestApiClient_GetNodeRule(t *testing.T) {
	client := CreateClient()
	nodeRule, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeRule)
}

func TestApiClient_ReportUserTraffic(t *testing.T) {
	userTrafficList := make([]*UserTraffic, 0)
	userTrafficList = append(userTrafficList,&UserTraffic{
		UID:      1,
		Upload:   409600,
		Download: 409600,
	})
	client:=CreateClient()
	err := client.ReportUserTraffic(userTrafficList)
	if err != nil{
		t.Error(err)
	}
}
