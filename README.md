# VNet-V2ray

# 编译
1. [Go语言](https://golang.org/), [Bazel](https://docs.bazel.build/)
2. 依次运行
```sh
git clone https://github.com/ProxyPanel/VNet-V2ray.git vent-v2ray && cd vent-v2ray
go mod tidy
bazel build --action_env=PATH=$PATH --action_env=SPWD=$PWD --action_env=GOPATH=$(go env GOPATH) --action_env=GOCACHE=$(go env GOCACHE) --spawn_strategy local //release_vnet:v2ray_linux_amd64_package
```
3. 获得 `bazel-bin/release_vnet/v2ray-linux-64.zip`

# License
 GNU GENERAL PUBLIC LICENSE