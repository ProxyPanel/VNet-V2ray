package inbound

import (
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/features"
)

// Controller control inbound
type Controller interface {
	features.Feature
	GetNodeInfo() *api.NodeInfo
}

// ControllerType returns the type of controller interface. Can be used for implementing common.HasType.
func Type() interface{} {
	return (*Controller)(nil)
}
