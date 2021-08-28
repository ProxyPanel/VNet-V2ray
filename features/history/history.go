package history

import (
	"context"
	"github.com/v2fly/v2ray-core/v4/common/api"
	"github.com/v2fly/v2ray-core/v4/features"
)

// History report history
type History interface {
	features.Feature
	Record(ctx context.Context, history *api.History) error
}

// ControllerType returns the type of controller interface. Can be used for implementing common.HasType.
func Type() interface{} {
	return (*History)(nil)
}
