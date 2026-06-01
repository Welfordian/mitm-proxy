package policy

import (
	"net"
	"strconv"
	"strings"
)

type BlockDecision struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`
	RuleID  string `json:"rule_id,omitempty"`
}

type PolicyEngine interface {
	CheckPort(port int) BlockDecision
	CheckDomain(host string) BlockDecision
	CheckIP(ip net.IP) BlockDecision
}

type Engine struct {
	Ports   []int
	Domains []string
	IPs     []string
}

func New(ports []int, domains, ips []string) *Engine {
	return &Engine{Ports: ports, Domains: domains, IPs: ips}
}

func (e *Engine) CheckPort(port int) BlockDecision {
	for _, blocked := range e.Ports {
		if blocked == port {
			return BlockDecision{Blocked: true, Reason: "port blocked", RuleID: "port:" + strconv.Itoa(port)}
		}
	}
	return BlockDecision{}
}

func (e *Engine) CheckDomain(host string) BlockDecision {
	host = normalizeHost(host)
	for _, pattern := range e.Domains {
		if matchDomain(host, pattern) {
			return BlockDecision{Blocked: true, Reason: "domain blocked", RuleID: "domain:" + pattern}
		}
	}
	return BlockDecision{}
}

func (e *Engine) CheckIP(ip net.IP) BlockDecision {
	for _, rule := range e.IPs {
		if _, cidr, err := net.ParseCIDR(rule); err == nil && cidr.Contains(ip) {
			return BlockDecision{Blocked: true, Reason: "ip blocked", RuleID: "ip:" + rule}
		}
		if parsed := net.ParseIP(rule); parsed != nil && parsed.Equal(ip) {
			return BlockDecision{Blocked: true, Reason: "ip blocked", RuleID: "ip:" + rule}
		}
	}
	return BlockDecision{}
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, ":") {
		if split, _, err := net.SplitHostPort(host); err == nil {
			host = split
		}
	}
	return strings.TrimSuffix(host, ".")
}

func matchDomain(host, pattern string) bool {
	pattern = normalizeHost(pattern)
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == pattern
}
