package api

import "encoding/json"

type Response struct {
	Status  string          `json:"status"`
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

type NodeInfo struct {
	ID            int    `json:"id"`
	IsUDP         bool   `json:"is_udp"`
	SpeedLimit    uint64 `json:"speed_limit"`
	ClientLimit   int    `json:"client_limit"`
	PushPort      int    `json:"push_port"`
	Secret        string `json:"secret"`
	Key           string `json:"key"`
	Cert          string `json:"pem"`
	V2License     string `json:"v2_license"`
	V2AlterID     int    `json:"v2_alter_id"`
	V2Port        int    `json:"v2_port"`
	V2Method      string `json:"v2_method"`
	V2Net         string `json:"v2_net"`
	V2Type        string `json:"v2_type"`
	V2Host        string `json:"v2_host"`
	V2Path        string `json:"v2_path"`
	V2TLS         bool   `json:"v2_tls"`
	V2Cdn         bool   `json:"v2_cdn"`
	V2TLSProvider string `json:"v2_tls_provider"`
	RedirectUrl   string `json:"redirect_url"`
}

// NodeStatus Node status report
type NodeStatus struct {
	CPU    string `json:"cpu"`
	Mem    string `json:"mem"`
	Net    string `json:"net"`
	Disk   string `json:"disk"`
	Uptime int    `json:"uptime"`
}

type NodeOnline struct {
	UID int    `json:"uid"`
	IP  string `json:"ip"`
}

type User struct {
	UID        int    `json:"uid"`
	VmessUID   string `json:"vmess_uid"`
	SpeedLimit uint64 `json:"speed_limit"`
}

type UserTraffic struct {
	UID      int `json:"uid"`
	Upload   int `json:"upload"`
	Download int `json:"download"`
}

type NodeRule struct {
	Mode  string         `json:"mode"`
	Rules []NodeRuleItem `json:"rules"`
}

type NodeRuleItem struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type IllegalReport struct {
	UID    int    `json:"uid"`
	RuleID int    `json:"rule_id"`
	Reason string `json:"reason"`
}

type Certificate struct {
	Key string `json:"key"`
	Pem string `json:"pem"`
}

type History struct {
	UID int    `json:"uid"`
	URL string `json:"url"`
}
