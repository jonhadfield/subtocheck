package subtocheck

import (
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/publicsuffix"
)

// delegationChecker finds dangling NS delegations: a name delegated to nameservers that
// do not serve its zone, usually because the zone was deleted from the DNS host. It walks
// the delegations from the public suffix down to the name, asking each zone's own
// nameservers rather than a resolver, as resolvers only report SERVFAIL for these.
type delegationChecker struct {
	// resolve sends a recursive query to a public resolver
	resolve func(name string, qtype uint16) (*dns.Msg, error)
	// ask sends a non-recursive query to a nameserver at ip
	ask func(ip, name string, qtype uint16) (*dns.Msg, error)
	log *scanLog
}

func newDelegationChecker(log *scanLog) *delegationChecker {
	client := &dns.Client{Timeout: 2 * time.Second}
	exchange := func(server, name string, qtype uint16, recurse bool) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = recurse
		r, _, err := client.Exchange(m, net.JoinHostPort(server, "53"))
		return r, err
	}
	return &delegationChecker{
		resolve: func(name string, qtype uint16) (*dns.Msg, error) {
			return exchange(nameservers[rand.IntN(len(nameservers))], name, qtype, true)
		},
		ask: func(ip, name string, qtype uint16) (*dns.Msg, error) {
			return exchange(ip, name, qtype, false)
		},
		log: log,
	}
}

// check returns an issue for the first dangling delegation on the way to fqdn, or nil.
func (c *delegationChecker) check(fqdn string) *issue {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	suffix, _ := publicsuffix.PublicSuffix(fqdn)
	if suffix == "" || suffix == fqdn {
		return nil
	}
	// start from the nearest zone at or above the suffix: some suffixes are not zones
	start := suffix
	servers := c.addresses(c.nsNames(start))
	for len(servers) == 0 && strings.Contains(start, ".") {
		start = start[strings.Index(start, ".")+1:]
		servers = c.addresses(c.nsNames(start))
	}
	if len(servers) == 0 {
		return nil
	}
	for _, zone := range zonesBetween(start, fqdn) {
		resp := c.askAny(servers, zone, dns.TypeNS)
		if resp == nil {
			return nil
		}
		delegated := delegationTo(resp, zone)
		if len(delegated) == 0 {
			if resp.Rcode == dns.RcodeNameError {
				// nothing exists at or below this name
				return nil
			}
			// still within the current zone
			continue
		}
		c.log.debugf("%s is delegated to %s", zone, strings.Join(delegated, ", "))
		addresses := c.addresses(delegated)
		switch c.serving(addresses, zone) {
		case servingYes:
			servers = addresses
		case servingNo:
			return danglingDelegationIssue(fqdn, zone, delegated)
		default:
			// the nameservers could not be reached, so nothing can be concluded
			return nil
		}
	}
	return nil
}

// zonesBetween lists the names below suffix, down to and including fqdn, shortest first.
func zonesBetween(suffix, fqdn string) []string {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."+suffix), ".")
	zones := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		zones = append(zones, strings.Join(labels[i:], ".")+"."+suffix)
	}
	return zones
}

// delegationTo returns the nameservers a response delegates zone to, from a referral or an
// authoritative NS answer.
func delegationTo(resp *dns.Msg, zone string) []string {
	var names []string
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(strings.TrimSuffix(ns.Hdr.Name, "."), zone) {
				names = append(names, strings.ToLower(strings.TrimSuffix(ns.Ns, ".")))
			}
		}
		if len(names) > 0 {
			return names
		}
	}
	return nil
}

type serving int

const (
	servingUnknown serving = iota
	servingYes
	servingNo
)

// serving asks each nameserver for the zone's SOA. A nameserver serves the zone only if it
// answers authoritatively with the zone's own SOA: a refusal, or an answer from another
// zone on the same host, means it does not.
func (c *delegationChecker) serving(addresses []string, zone string) serving {
	result := servingUnknown
	for _, ip := range addresses {
		resp, err := c.ask(ip, zone, dns.TypeSOA)
		if err != nil || resp == nil {
			continue
		}
		if resp.Rcode == dns.RcodeSuccess && resp.Authoritative && hasSOAFor(resp.Answer, zone) {
			return servingYes
		}
		result = servingNo
	}
	return result
}

func hasSOAFor(rrs []dns.RR, zone string) bool {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok && strings.EqualFold(strings.TrimSuffix(soa.Hdr.Name, "."), zone) {
			return true
		}
	}
	return false
}

// nsNames resolves the nameservers of a zone through a resolver.
func (c *delegationChecker) nsNames(zone string) []string {
	resp, err := c.resolve(zone, dns.TypeNS)
	if err != nil || resp == nil {
		return nil
	}
	return delegationTo(resp, zone)
}

// addresses resolves nameserver hostnames to IPv4 addresses.
func (c *delegationChecker) addresses(hosts []string) []string {
	var ips []string
	for _, host := range hosts {
		resp, err := c.resolve(host, dns.TypeA)
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A.String())
				break
			}
		}
	}
	return ips
}

// askAny returns the first response from any of the servers.
func (c *delegationChecker) askAny(servers []string, name string, qtype uint16) *dns.Msg {
	for _, ip := range servers {
		if resp, err := c.ask(ip, name, qtype); err == nil && resp != nil {
			return resp
		}
	}
	return nil
}

// danglingDelegationIssue reports zone as delegated to nameservers that do not serve it. On
// a provider where anyone can create the zone again it is a potential takeover.
func danglingDelegationIssue(fqdn, zone string, delegated []string) *issue {
	nsList := strings.Join(delegated, ", ")
	if p, ok := nsProvider(delegated); ok {
		detail := zone + " is delegated to " + p.platform + ", which does not serve it"
		if p.note != "" {
			detail += " (" + p.note + ")"
		}
		return &issue{
			kind:     "vuln",
			platform: p.platform,
			fqdn:     fqdn,
			url:      fqdn,
			err:      errors.Errorf("NS for %s (%s) do not serve the zone, matches platform: %s", zone, nsList, p.platform),
			detail:   detail,
			edgeCase: p.edgeCase,
		}
	}
	return &issue{
		kind: "dns",
		fqdn: fqdn,
		err:  errors.Errorf("%s is a dangling delegation: %s is delegated to %s, which do not serve it", fqdn, zone, nsList),
	}
}
