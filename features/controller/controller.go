package inbound

import (
	"v2ray.com/core/common/api"
	"v2ray.com/core/features"
)

// Controller control inbound
//
// v2ray:api:stable
type Controller interface {
	features.Feature
	GetNodeInfo() *api.NodeInfo
}

// ControllerType returns the type of controller interface. Can be used for implementing common.HasType.
//
// v2ray:api:stable
func Type() interface{} {
	return (*Controller)(nil)
}
