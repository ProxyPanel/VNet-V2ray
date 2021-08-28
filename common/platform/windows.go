// +build windows

package platform

import "path/filepath"

func ExpandEnv(s string) string {
	// TODO
	return s
}

func LineSeparator() string {
	return "\r\n"
}

func GetToolLocation(file string) string {
	const name = "v2ray.location.tool"
	toolPath := EnvFlag{Name: name, AltName: NormalizeEnvName(name)}.GetValue(getExecutableDir)
	return filepath.Join(toolPath, file+".exe")
}

// GetAssetLocation search for `file` in the excutable dir
func GetAssetLocation(file string) string {
	const name = "v2ray.location.asset"
	assetPath := NewEnvFlag(name).GetValue(getExecutableDir)
	return filepath.Join(assetPath, file)
}
