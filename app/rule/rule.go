package rule

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"v2ray.com/core/common"
	"v2ray.com/core/common/api"
	"v2ray.com/core/common/log"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/retry"
	"v2ray.com/core/common/session"
)

func Type() interface{} {
	return (*RuleManager)(nil)
}

type RuleManager struct {
	context.Context
	*api.ApiClient
	*api.NodeRule
}

func NewRuleManager(ctx context.Context, config *Config) (*RuleManager, error) {
	r := new(RuleManager)
	r.Context = ctx
	r.ApiClient = api.NewClient(config.GetApiServer(), int(config.GetNodeId()), config.GetKey())
	return r, nil
}

func (r *RuleManager) Do(ctx context.Context, destination net.Destination) bool {
	result := true
	if r.NodeRule == nil {
		return true
	}

	if r.NodeRule.Mode == "all" {
		result = true
	}

	if r.NodeRule.Mode == "reject" {
		result = r.reject(ctx, destination)
	}

	if r.NodeRule.Mode == "allow" {
		result = r.allow(ctx, destination)
	}

	return result
}

func (r *RuleManager) Type() interface{} {
	return (*RuleManager)(nil)
}

func (r *RuleManager) Start() error {
	var err error
	var nodeRule *api.NodeRule
	err = retry.ExponentialBackoff(3, 200).On(func() error {
		nodeRule, err = r.ApiClient.GetNodeRule()
		return err
	})
	if err != nil {
		panic(newError("rule manager start failed").Base(err))
	}
	r.NodeRule = nodeRule
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("load rule count: %d", len(nodeRule.Rules)),
	})
	return nil
}

func (r *RuleManager) Close() error {
	return nil
}

func (r *RuleManager) reject(ctx context.Context, destination net.Destination) bool {
	result := true
	ruleId := 0

	for _, rule := range r.NodeRule.Rules {
		if rule.Type == "reg" {
			if regexp.MustCompile(rule.Pattern).Match([]byte(destination.String())) {
				ruleId = rule.ID
				result = false
				break
			}
		}

		if rule.Type == "domain" {
			if strings.Contains(destination.String(), rule.Pattern) {
				ruleId = rule.ID
				result = false
				break
			}
		}

		if rule.Type == "ip" {
			if strings.Contains(destination.String(), rule.Pattern) {
				ruleId = rule.ID
				result = false
				break
			}
		}
	}

	if !result {
		sessionInbound := session.InboundFromContext(ctx)
		var user *protocol.MemoryUser
		if sessionInbound != nil {
			user = sessionInbound.User
		}

		if user == nil {
			return result
		}

		uid, err := strconv.Atoi(user.Email)
		if err != nil {
			newError("uid convert failed").Base(err).AtError().WriteToLog()
			return result
		}

		illegalReport := &api.IllegalReport{
			UID:    uid,
			RuleID: ruleId,
			Reason: fmt.Sprintf("违反reject规则: %s", destination.String()),
		}

		err = retry.ExponentialBackoff(2, 200).On(func() error {
			return r.ApiClient.ReportIllegal(illegalReport)
		})
		if err != nil {
			newError("report illegal failed").Base(err).AtError().WriteToLog()
			return result
		}
	}

	return result
}

func (r *RuleManager) allow(ctx context.Context, destination net.Destination) bool {
	result := false

	for _, rule := range r.NodeRule.Rules {
		if rule.Type == "reg" {
			if regexp.MustCompile(rule.Pattern).Match([]byte(destination.String())) {
				result = true
				break
			}
		}

		if rule.Type == "domain" {
			if strings.Contains(destination.String(), rule.Pattern) {
				result = true
				break
			}
		}

		if rule.Type == "ip" {
			if strings.Contains(destination.String(), rule.Pattern) {
				result = true
				break
			}
		}
	}

	return result
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewRuleManager(ctx, cfg.(*Config))
	}))
}
