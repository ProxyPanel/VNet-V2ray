package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
)

type ApiClient struct {
	client  *resty.Client
	ApiHost string
	NodeID  int
	Key     string
}

func NewClient(apiHost string, nodeId int, key string) *ApiClient {
	apiClient := new(ApiClient)
	client := resty.New()
	client.SetTimeout(5 * time.Second)
	client.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: true,
	})
	apiClient.client = client
	apiClient.NodeID = nodeId
	apiClient.Key = key
	apiClient.ApiHost = apiHost
	return apiClient
}

// GetNodeInfo will pull NodeInfo Config from vnetpanel
func (c *ApiClient) GetNodeInfo() (data *NodeInfo, err error) {
	if c.NodeID == 0 {
		return nil, newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/node/%d", c.NodeID)
	res, err := c.
		createCommonRequest().
		SetResult(&Response{}).
		Get(c.AssembleUrl(path))
	if err != nil {
		return nil, newError(fmt.Sprintf("request %s failed", path)).Base(err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, newError(fmt.Sprintf("request %s failed: %s", path, string(body))).Base(err)
	}

	response := res.Result().(*Response)
	if response.Status != "success" {
		return nil, newError(fmt.Sprintf("report node status failed: %s", response.Message))
	}
	nodeInfo := new(NodeInfo)
	if err := json.Unmarshal(response.Data, &nodeInfo); err != nil {
		return nil, newError("json unmarshal failed").Base(err)
	}

	return nodeInfo, nil
}

// Report Node Status to vnet-panel
func (c *ApiClient) ReportNodeStatus(nodeStatus *NodeStatus) error {
	if c.NodeID == 0 {
		return newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/nodeStatus/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetBody(nodeStatus)

	res, err := request.
		SetResult(&Response{}).
		Post(c.AssembleUrl(path))
	if err != nil {
		return newError(fmt.Sprintf("report node status error: %s", res.Body()))
	}

	response := res.Result().(*Response)
	if response.Status != "success" {
		return newError(fmt.Sprintf("report node status failed: %s", response.Message))
	}

	return nil
}

// GetUserList pull user list from vnet-panel
func (c *ApiClient) GetUserList() (data []*User, err error) {
	if c.NodeID == 0 {
		return nil, newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/userList/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetResult(&Response{})

	res, err := request.Get(c.AssembleUrl(path))
	if err != nil {
		return nil, newError("get user list failed ", res.Body()).Base(err)
	}

	response := res.Result().(*Response)
	if response.Status != "success" {
		return nil, newError("get user list failed", response.Message)
	}

	userList := make([]*User, 0)
	if err := json.Unmarshal(response.Data, &userList); err != nil {
		return nil, newError("get user list failed").Base(err)
	}

	return userList, err
}

func (c *ApiClient) ReportNodeOnline(online []*NodeOnline) error {
	if c.NodeID == 0 {
		return newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/nodeOnline/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetResult(&Response{})
	request.SetBody(online)
	res, err := request.Post(c.AssembleUrl(path))
	if err != nil {
		return newError("report node online failed").Base(err)
	}
	response := res.Result().(*Response)
	if response.Status != "success" {
		return newError("report node online failed", response.Message)
	}
	return nil
}

func (c *ApiClient) ReportUserTraffic(traffics []*UserTraffic) error {
	if c.NodeID == 0 {
		return newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/userTraffic/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetResult(&Response{})
	request.SetBody(traffics)
	res, err := request.Post(c.AssembleUrl(path))
	if err != nil {
		return newError("report user traffic failed").Base(err)
	}
	response := res.Result().(*Response)
	if response.Status != "success" {
		return newError("report user traffic failed", response.Message)
	}
	return nil
}

func (c *ApiClient) GetNodeRule() (rule *NodeRule, err error) {
	if c.NodeID == 0 {
		return nil, newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/nodeRule/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetResult(&Response{})
	res, err := request.Get(c.AssembleUrl(path))
	if err != nil {
		return nil, newError("get node rule failed").Base(err)
	}
	response := res.Result().(*Response)
	if response.Status != "success" {
		return nil, newError("get node rule failed", response.Message)
	}

	nodeRule := new(NodeRule)
	if err := json.Unmarshal(response.Data, &nodeRule); err != nil {
		return nil, newError("get node rule failed").Base(err)
	}
	return nodeRule, nil
}

func (c *ApiClient) ReportIllegal(illegalReport *IllegalReport) error {
	if c.NodeID == 0 {
		return newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/trigger/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetBody(illegalReport)
	request.SetResult(&Response{})
	res, err := request.Post(c.AssembleUrl(path))
	if err != nil {
		return newError("illegal report failed").Base(err)
	}

	response := res.Result().(*Response)
	if response.Status != "success" {
		return newError("illegal report failed", response.Message)
	}

	return nil
}

func (c *ApiClient) PushCertification(certificate *Certificate) error {
	if c.NodeID == 0 {
		return newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/v2ray/v1/certificate/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetBody(certificate)
	request.SetResult(&Response{})
	res, err := request.Post(c.AssembleUrl(path))
	if err != nil {
		return newError("push certificate failed").Base(err)
	}

	response := res.Result().(*Response)
	if response.Status != "success" {
		return newError("push certificate failed", response.Message)
	}

	return nil
}

func (c *ApiClient) History(history []*History) error {
	if c.NodeID == 0 {
		return newError("NodeId is 0")
	}

	path := fmt.Sprintf("/api/vmess/v1/user/history/%d", c.NodeID)
	request := c.createCommonRequest()
	request.SetBody(history)
	request.SetResult(&Response{})
	res, err := request.Post(c.AssembleUrl(path))
	if err != nil {
		return newError("history report failed").Base(err)
	}

	response := res.Result().(*Response)
	if response.Status != "success" {
		return newError("history report failed", response.Message)
	}

	return nil
}

func (c *ApiClient) AssembleUrl(path string) string {
	return c.ApiHost + path
}

func (c *ApiClient) createCommonRequest() *resty.Request {
	request := c.client.R().EnableTrace()
	request.EnableTrace()
	request.SetHeader("key", c.Key)
	request.SetHeader("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	return request
}
