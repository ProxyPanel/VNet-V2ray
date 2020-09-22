package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"v2ray.com/core"
	"v2ray.com/core/app/controller"
	"v2ray.com/core/app/dispatcher"
	"v2ray.com/core/app/log"
	"v2ray.com/core/app/online"
	"v2ray.com/core/app/policy"
	"v2ray.com/core/app/proxyman"
	"v2ray.com/core/app/rule"
	"v2ray.com/core/app/stats"
	"v2ray.com/core/app/status"
	"v2ray.com/core/app/traffic"
	"v2ray.com/core/common/buf"
	clog "v2ray.com/core/common/log"
	"v2ray.com/core/common/serial"
	_ "v2ray.com/core/main/distro/all"
)

var (
	configFile = flag.String("config", "", "Config file for V2Ray.")
	version    = flag.Bool("version", false, "show version")
)

type Config struct {
	ApiServer string `json:"api_server"`
	Key       string `json:"key"`
	NodeId    int32  `json:"node_id"`
}

func main() {
	flag.Parse()
	printVersion()
	if *version {
		return
	}

	configFile := getConfigFilePath()
	if configFile == "" {
		fmt.Println("config is not exist")
		os.Exit(23)
	}

	fmt.Println(fmt.Sprintf("using config file: %s", configFile))

	fixedFile := os.ExpandEnv(configFile)
	file, err := os.Open(fixedFile)
	if err != nil {
		fmt.Print(newError("config file not readable").Base(err).Error())
		os.Exit(23)
	}
	defer file.Close()

	from, err := buf.ReadFrom(file)
	if err != nil {
		fmt.Println(newError("config file read error").Base(err).Error())
		os.Exit(23)
	}

	config := &Config{}
	err = json.Unmarshal([]byte(from.String()), config)
	if err != nil {
		fmt.Println(newError("config unmarshal error").Base(err).Error())
		os.Exit(23)
	}

	startWithConfig(config)
}

func printVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		fmt.Println(s)
	}
}

func fileExists(file string) bool {
	info, err := os.Stat(file)
	return err == nil && !info.IsDir()
}

func getConfigFilePath() string {
	if len(*configFile) > 0 {
		return *configFile
	}

	if workingDir, err := os.Getwd(); err == nil {
		configFile := filepath.Join(workingDir, "config.json")
		if fileExists(configFile) {
			return configFile
		}
	}

	if configFile := "/etc/v2ray/config.json"; fileExists(configFile) {
		return configFile
	}

	return ""
}

func startWithConfig(c *Config) {
	config := new(core.Config)
	config.App = make([]*serial.TypedMessage, 0, 5)
	config.App = append(config.App, serial.ToTypedMessage(&dispatcher.Config{}))
	config.App = append(config.App, serial.ToTypedMessage(&proxyman.InboundConfig{}))
	config.App = append(config.App, serial.ToTypedMessage(&proxyman.OutboundConfig{}))
	config.App = append(config.App, serial.ToTypedMessage(&stats.Config{}))
	config.App = append(config.App, serial.ToTypedMessage(&controller.Config{
		ApiServer: c.ApiServer,
		Key:       c.Key,
		NodeId:    c.NodeId,
	}))

	config.App = append(config.App, serial.ToTypedMessage(&traffic.Config{
		ApiServer: c.ApiServer,
		Key:       c.Key,
		NodeId:    c.NodeId,
	}))

	config.App = append(config.App, serial.ToTypedMessage(&status.Config{
		ApiServer: c.ApiServer,
		Key:       c.Key,
		NodeId:    c.NodeId,
	}))

	config.App = append(config.App, serial.ToTypedMessage(&online.Config{
		ApiServer: c.ApiServer,
		Key:       c.Key,
		NodeId:    c.NodeId,
	}))

	config.App = append(config.App, serial.ToTypedMessage(&rule.Config{
		ApiServer: c.ApiServer,
		Key:       c.Key,
		NodeId:    c.NodeId,
	}))

	config.App = append(config.App, serial.ToTypedMessage(&policy.Config{
		Level: map[uint32]*policy.Policy{
			0: &policy.Policy{
				//Buffer: &policy.Policy_Buffer{
				//	Connection: 0,
				//},
				Traffic: true,
			},
		},
		System: nil,
	}))
	config.App = append(config.App, serial.ToTypedMessage(&log.Config{
		ErrorLogType:  log.LogType_Console,
		AccessLogType: log.LogType_Console,
		ErrorLogLevel: clog.Severity_Info,
	}))

	server, err := core.New(config)
	if err != nil {
		fmt.Println(err.Error())
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	if err := server.Start(); err != nil {
		fmt.Println("Failed to start", err)
		os.Exit(-1)
	}
	defer server.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}
