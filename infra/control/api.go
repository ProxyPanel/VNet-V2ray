package control

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"

	logService "github.com/v2fly/v2ray-core/v4/app/log/command"
	statsService "github.com/v2fly/v2ray-core/v4/app/stats/command"
	"github.com/v2fly/v2ray-core/v4/common"
)

type APICommand struct{}

func (c *APICommand) Name() string {
	return "api"
}

func (c *APICommand) Description() Description {
	return Description{
		Short: "Call V2Ray API",
		Usage: []string{
			"v2ctl api [--server=127.0.0.1:8080] Service.Method Request",
			"Call an API in an V2Ray process.",
			"The following methods are currently supported:",
			"\tLoggerService.RestartLogger",
			"\tStatsService.GetStats",
			"\tStatsService.QueryStats",
			"API calls in this command have a timeout to the server of 3 seconds.",
			"Examples:",
			"v2ctl api --server=127.0.0.1:8080 LoggerService.RestartLogger '' ",
			"v2ctl api --server=127.0.0.1:8080 StatsService.QueryStats 'pattern: \"\" reset: false'",
			"v2ctl api --server=127.0.0.1:8080 StatsService.GetStats 'name: \"inbound>>>statin>>>traffic>>>downlink\" reset: false'",
			"v2ctl api --server=127.0.0.1:8080 StatsService.GetSysStats ''",
		},
	}
}

func (c *APICommand) Execute(args []string) error {
	fs := flag.NewFlagSet(c.Name(), flag.ContinueOnError)

	serverAddrPtr := fs.String("server", "127.0.0.1:8080", "Server address")

	if err := fs.Parse(args); err != nil {
		return err
	}

	unnamedArgs := fs.Args()
	if len(unnamedArgs) < 2 {
		return newError("service name or request not specified.")
	}

	service, method := getServiceMethod(unnamedArgs[0])
	handler, found := serivceHandlerMap[strings.ToLower(service)]
	if !found {
		return newError("unknown service: ", service)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *serverAddrPtr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return newError("failed to dial ", *serverAddrPtr).Base(err)
	}
	defer conn.Close()

	response, err := handler(ctx, conn, method, unnamedArgs[1])
	if err != nil {
		return newError("failed to call service ", unnamedArgs[0]).Base(err)
	}

	fmt.Println(response)
	return nil
}

func getServiceMethod(s string) (string, string) {
	ss := strings.Split(s, ".")
	service := ss[0]
	var method string
	if len(ss) > 1 {
		method = ss[1]
	}
	return service, method
}

type serviceHandler func(ctx context.Context, conn *grpc.ClientConn, method string, request string) (string, error)

var serivceHandlerMap = map[string]serviceHandler{
	"statsservice":  callStatsService,
	"loggerservice": callLogService,
}

func callLogService(ctx context.Context, conn *grpc.ClientConn, method string, request string) (string, error) {
	client := logService.NewLoggerServiceClient(conn)

	switch strings.ToLower(method) {
	case "restartlogger":
		r := &logService.RestartLoggerRequest{}
		if err := proto.UnmarshalText(request, r); err != nil {
			return "", err
		}
		resp, err := client.RestartLogger(ctx, r)
		if err != nil {
			return "", err
		}
		return proto.MarshalTextString(resp), nil
	default:
		return "", errors.New("Unknown method: " + method)
	}
}

func callStatsService(ctx context.Context, conn *grpc.ClientConn, method string, request string) (string, error) {
	client := statsService.NewStatsServiceClient(conn)

	switch strings.ToLower(method) {
	case "getstats":
		r := &statsService.GetStatsRequest{}
		if err := proto.UnmarshalText(request, r); err != nil {
			return "", err
		}
		resp, err := client.GetStats(ctx, r)
		if err != nil {
			return "", err
		}
		return proto.MarshalTextString(resp), nil
	case "querystats":
		r := &statsService.QueryStatsRequest{}
		if err := proto.UnmarshalText(request, r); err != nil {
			return "", err
		}
		resp, err := client.QueryStats(ctx, r)
		if err != nil {
			return "", err
		}
		return proto.MarshalTextString(resp), nil
	case "getsysstats":
		// SysStatsRequest is an empty message
		r := &statsService.SysStatsRequest{}
		resp, err := client.GetSysStats(ctx, r)
		if err != nil {
			return "", err
		}
		return proto.MarshalTextString(resp), nil
	default:
		return "", errors.New("Unknown method: " + method)
	}
}

func init() {
	common.Must(RegisterCommand(&APICommand{}))
}
