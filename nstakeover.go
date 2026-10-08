package subtocheck

import (
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/publicsuffix"
)

// delegationChecker finds dangling NS delegations on the way to a name: delegations to
// nameservers that do not serve the zone, usually because it was deleted from the DNS host,
// and to nameservers on a domain that anyone could register. It walks the delegations from
// the public suffix down to the name, asking each zone's own nameservers rather than a
// resolver, as resolvers only report SERVFAIL for these.
type delegationChecker struct {
	// resolve sends a recursive query to a public resolver
	resolve func(name string, qtype uint16) (*dns.Msg, error)
	// ask sends a non-recursive query to a nameserver at ip
	ask func(ip, name string, qtype uint16) (*dns.Msg, error)
	// registration reports whether a nameserver's domain is registered
	registration registrationLookup
}

func newDelegationChecker(q *dnsQueries, registration registrationLookup) *delegationChecker {
	return &delegationChecker{resolve: q.resolve, ask: q.ask, registration: registration}
}

// check returns an issue for the first dangling delegation on the way to fqdn, or nil.
func (c *delegationChecker) check(fqdn string, log *scanLog) *issue {
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
		log.debugf("%s is delegated to %s", zone, strings.Join(delegated, ", "))
		if unregistered := c.unregisteredNameserver(fqdn, zone, delegated); unregistered != nil {
			return unregistered
		}
		served, notServing := c.servingByHost(delegated, zone)
		switch {
		case len(served) == 0 && len(notServing) == 0:
			// the nameservers could not be reached, so nothing can be concluded
			return nil
		case len(served) == 0:
			return danglingDelegationIssue(fqdn, zone, delegated)
		case len(notServing) > 0:
			// resolvers pick nameservers at random, so the ones that do not serve the zone
			// still receive a share of the queries for it
			return partlyDanglingIssue(fqdn, zone, notServing)
		}
		servers = served
	}
	return nil
}

// unregisteredNameserver reports a nameserver for zone whose hostname does not exist and
// whose domain is not registered. Whoever registers it answers queries for the zone, even
// when the other nameservers are healthy. Nameservers within the zone itself are skipped:
// they cannot be registered separately.
func (c *delegationChecker) unregisteredNameserver(fqdn, zone string, delegated []string) *issue {
	zoneDomain := registeredDomain(zone)
	for _, host := range delegated {
		domain := registeredDomain(host)
		if domain == "" || domain == zoneDomain {
			continue
		}
		resp, err := c.resolve(host, dns.TypeA)
		if err != nil || resp == nil || resp.Rcode != dns.RcodeNameError {
			continue
		}
		subject := zone + " is delegated to nameserver " + host
		if i := registrationIssue(fqdn, subject, domain, c.registration(domain), time.Now()); i != nil {
			return i
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

// servingByHost asks each delegated nameserver for the zone's SOA. It returns the
// addresses of the nameservers that serve the zone, and the hostnames of those that do not.
// A nameserver serves the zone only if it answers authoritatively with the zone's own SOA:
// a refusal, or an answer from another zone on the same host, means it does not. Nameservers
// that cannot be resolved or do not respond are in neither list.
func (c *delegationChecker) servingByHost(hosts []string, zone string) (served, notServing []string) {
	for _, host := range hosts {
		addresses := c.addresses([]string{host})
		if len(addresses) == 0 {
			continue
		}
		resp, err := c.ask(addresses[0], zone, dns.TypeSOA)
		// a truncated reply that could not be retried says nothing either way
		if err != nil || resp == nil || resp.Truncated {
			continue
		}
		if resp.Rcode == dns.RcodeSuccess && resp.Authoritative && hasSOAFor(resp.Answer, zone) {
			served = append(served, addresses[0])
		} else {
			notServing = append(notServing, host)
		}
	}
	return served, notServing
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

// partlyDanglingIssue reports zone as delegated to some nameservers that do not serve it,
// alongside others that do. If those nameservers are on a provider where anyone can create
// the zone, whoever does so answers the share of queries sent to them.
func partlyDanglingIssue(fqdn, zone string, notServing []string) *issue {
	nsList := strings.Join(notServing, ", ")
	if p, ok := nsProvider(notServing); ok {
		detail := zone + " is also delegated to " + p.platform + ", which does not serve it, so whoever creates the zone there answers a share of its queries"
		if p.note != "" {
			detail += " (" + p.note + ")"
		}
		return &issue{
			kind:     "vuln",
			platform: p.platform,
			fqdn:     fqdn,
			url:      fqdn,
			err:      errors.Errorf("NS for %s include %s, which do not serve the zone, matches platform: %s", zone, nsList, p.platform),
			detail:   detail,
			edgeCase: p.edgeCase,
		}
	}
	return &issue{
		kind: "dns",
		fqdn: fqdn,
		err:  errors.Errorf("%s is a partly dangling delegation: %s is delegated to %s, which do not serve it, alongside nameservers that do", fqdn, zone, nsList),
	}
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
