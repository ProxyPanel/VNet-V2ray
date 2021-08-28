// +build !confonly

// Package dns is an implementation of core.DNS feature.
package dns

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/v2fly/v2ray-core/v4/app/router"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/errors"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/strmatcher"
	"github.com/v2fly/v2ray-core/v4/features"
	"github.com/v2fly/v2ray-core/v4/features/dns"
)

// DNS is a DNS rely server.
type DNS struct {
	sync.Mutex
	tag             string
	disableCache    bool
	disableFallback bool
	ipOption        *dns.IPOption
	hosts           *StaticHosts
	clients         []*Client
	ctx             context.Context
	domainMatcher   strmatcher.IndexMatcher
	matcherInfos    []DomainMatcherInfo
}

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher
type DomainMatcherInfo struct {
	clientIdx     uint16
	domainRuleIdx uint16
}

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	var tag string
	if len(config.Tag) > 0 {
		tag = config.Tag
	} else {
		tag = generateRandomTag()
	}

	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, newError("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption *dns.IPOption
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = &dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP4:
		ipOption = &dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = &dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	}

	hosts, err := NewStaticHosts(config.StaticHosts, config.Hosts)
	if err != nil {
		return nil, newError("failed to create hosts").Base(err)
	}

	clients := []*Client{}
	domainRuleCount := 0
	for _, ns := range config.NameServer {
		domainRuleCount += len(ns.PrioritizedDomain)
	}

	// MatcherInfos is ensured to cover the maximum index domainMatcher could return, where matcher's index starts from 1
	matcherInfos := make([]DomainMatcherInfo, domainRuleCount+1)
	domainMatcher := &strmatcher.MatcherGroup{}
	geoipContainer := router.GeoIPMatcherContainer{}

	for _, endpoint := range config.NameServers {
		features.PrintDeprecatedFeatureWarning("simple DNS server")
		client, err := NewSimpleClient(ctx, endpoint, clientIP)
		if err != nil {
			return nil, newError("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	for _, ns := range config.NameServer {
		clientIdx := len(clients)
		updateDomain := func(domainRule strmatcher.Matcher, originalRuleIdx int, matcherInfos []DomainMatcherInfo) error {
			midx := domainMatcher.Add(domainRule)
			matcherInfos[midx] = DomainMatcherInfo{
				clientIdx:     uint16(clientIdx),
				domainRuleIdx: uint16(originalRuleIdx),
			}
			return nil
		}

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}
		client, err := NewClient(ctx, ns, myClientIP, geoipContainer, &matcherInfos, updateDomain)
		if err != nil {
			return nil, newError("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient())
	}

	return &DNS{
		tag:             tag,
		hosts:           hosts,
		ipOption:        ipOption,
		clients:         clients,
		ctx:             ctx,
		domainMatcher:   domainMatcher,
		matcherInfos:    matcherInfos,
		disableCache:    config.DisableCache,
		disableFallback: config.DisableFallback,
	}, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	return nil
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	return inbound != nil && inbound.Tag == s.tag
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string) ([]net.IP, error) {
	return s.lookupIPInternal(domain, dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: s.ipOption.FakeEnable,
	})
}

// LookupIPv4 implements dns.IPv4Lookup.
func (s *DNS) LookupIPv4(domain string) ([]net.IP, error) {
	return s.lookupIPInternal(domain, dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
		FakeEnable: s.ipOption.FakeEnable,
	})
}

// LookupIPv6 implements dns.IPv6Lookup.
func (s *DNS) LookupIPv6(domain string) ([]net.IP, error) {
	return s.lookupIPInternal(domain, dns.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
		FakeEnable: s.ipOption.FakeEnable,
	})
}

func (s *DNS) lookupIPInternal(domain string, option dns.IPOption) ([]net.IP, error) {
	if domain == "" {
		return nil, newError("empty domain name")
	}

	// Normalize the FQDN form query
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}

	// Static host lookup
	switch addrs := s.hosts.Lookup(domain, option); {
	case addrs == nil: // Domain not recorded in static host
		break
	case len(addrs) == 0: // Domain recorded, but no valid IP returned (e.g. IPv4 address with only IPv6 enabled)
		return nil, dns.ErrEmptyResponse
	case len(addrs) == 1 && addrs[0].Family().IsDomain(): // Domain replacement
		newError("domain replaced: ", domain, " -> ", addrs[0].Domain()).WriteToLog()
		domain = addrs[0].Domain()
	default: // Successfully found ip records in static host
		newError("returning ", len(addrs), " IP(s) for domain ", domain, " -> ", addrs).WriteToLog()
		return toNetIP(addrs)
	}

	// Name servers lookup
	errs := []error{}
	ctx := session.ContextWithInbound(s.ctx, &session.Inbound{Tag: s.tag})
	for _, client := range s.sortClients(domain) {
		if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
			newError("skip DNS resolution for domain ", domain, " at server ", client.Name()).AtDebug().WriteToLog()
			continue
		}
		ips, err := client.QueryIP(ctx, domain, option, s.disableCache)
		if len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			newError("failed to lookup ip for domain ", domain, " at server ", client.Name()).Base(err).WriteToLog()
			errs = append(errs, err)
		}
		if err != context.Canceled && err != context.DeadlineExceeded && err != errExpectedIPNonMatch {
			return nil, err
		}
	}

	return nil, newError("returning nil for domain ", domain).Base(errors.Combine(errs...))
}

// GetIPOption implements ClientWithIPOption.
func (s *DNS) GetIPOption() *dns.IPOption {
	return s.ipOption
}

// SetQueryOption implements ClientWithIPOption.
func (s *DNS) SetQueryOption(isIPv4Enable, isIPv6Enable bool) {
	s.ipOption.IPv4Enable = isIPv4Enable
	s.ipOption.IPv6Enable = isIPv6Enable
}

// SetFakeDNSOption implements ClientWithIPOption.
func (s *DNS) SetFakeDNSOption(isFakeEnable bool) {
	s.ipOption.FakeEnable = isFakeEnable
}

func (s *DNS) sortClients(domain string) []*Client {
	clients := make([]*Client, 0, len(s.clients))
	clientUsed := make([]bool, len(s.clients))
	clientNames := make([]string, 0, len(s.clients))
	domainRules := []string{}

	// Priority domain matching
	for _, match := range s.domainMatcher.Match(domain) {
		info := s.matcherInfos[match]
		client := s.clients[info.clientIdx]
		domainRule := client.domains[info.domainRuleIdx]
		domainRules = append(domainRules, fmt.Sprintf("%s(DNS idx:%d)", domainRule, info.clientIdx))
		if clientUsed[info.clientIdx] {
			continue
		}
		clientUsed[info.clientIdx] = true
		clients = append(clients, client)
		clientNames = append(clientNames, client.Name())
	}

	if !s.disableFallback {
		// Default round-robin query
		for idx, client := range s.clients {
			if clientUsed[idx] || client.skipFallback {
				continue
			}
			clientUsed[idx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
		}
	}

	if len(domainRules) > 0 {
		newError("domain ", domain, " matches following rules: ", domainRules).AtDebug().WriteToLog()
	}
	if len(clientNames) > 0 {
		newError("domain ", domain, " will use DNS in order: ", clientNames).AtDebug().WriteToLog()
	}

	if len(clients) == 0 {
		clients = append(clients, s.clients[0])
		clientNames = append(clientNames, s.clients[0].Name())
		newError("domain ", domain, " will use the first DNS: ", clientNames).AtDebug().WriteToLog()
	}

	return clients
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
