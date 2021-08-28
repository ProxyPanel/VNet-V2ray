package api

import "encoding/json"

type Response struct {
	Status  string          `json:"status"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

type NodeInfo struct {
	ID          int      `json:"id"`
	UDP         bool     `json:"udp"`
	Speed       uint64   `json:"speed"`
	Client      int      `json:"client"`
	PushPort    int      `json:"push_port"`
	Secret      string   `json:"secret"`
	Key         string   `json:"key"`
	Pem         string   `json:"pem"`
	Audit       NodeRule `json:"audit"`
	License     string   `json:"license"`
	AlterId     int      `json:"alter_id"`
	Port        int      `json:"port"`
	Method      string   `json:"method"`
	Protocol    string   `json:"protocol"`
	Type        string   `json:"type"`
	Host        string   `json:"host"`
	Path        string   `json:"path"`
	TLS         bool     `json:"tls"`
	TLSProvider string   `json:"tls_provider"`
	Redirect    string   `json:"redirect"`
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
	UID   int    `json:"uid"`
	UUID  string `json:"uuid"`
	Speed uint64 `json:"speed"`
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
