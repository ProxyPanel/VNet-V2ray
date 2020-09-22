package traffic

import "v2ray.com/core/features"

type Traffic interface {
	Up(uint64) uint64
	Down(uint64) uint64
}

type Manager interface {
	features.Feature

	Up(key string,count uint64)

	Down(Key string,count uint64)

	GetTraffic(string) Traffic
}

// ManagerType returns the type of Manager interface. Can be used to implement common.HasType.
//
// v2ray:api:stable
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// NoopManager is an implementation of Manager, which doesn't has actual functionalities.
type NoopManager struct{}

// Type implements common.HasType.
func (NoopManager) Type() interface{} {
	return ManagerType()
}

// RegisterCounter implements Manager.
func (NoopManager) GetTraffic(string) (Traffic, error) {
	return nil, newError("not implemented")
}

// Start implements common.Runnable.
func (NoopManager) Start() error { return nil }

// Close implements common.Closable.
func (NoopManager) Close() error { return nil }
