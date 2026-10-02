package subtocheck

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// fakeDNS scripts the responses a delegationChecker sees, keyed by server ("resolver" for
// recursive queries, otherwise an IP), name and type. Unscripted queries fail.
type fakeDNS map[string]*dns.Msg

func key(server, name string, qtype uint16) string {
	return server + "|" + strings.ToLower(name) + "|" + dns.TypeToString[qtype]
}

func (f fakeDNS) checker() *delegationChecker {
	lookup := func(k string) (*dns.Msg, error) {
		if m, ok := f[k]; ok {
			return m, nil
		}
		return nil, errors.New("timeout")
	}
	return &delegationChecker{
		resolve: func(name string, qtype uint16) (*dns.Msg, error) { return lookup(key("resolver", name, qtype)) },
		ask:     func(ip, name string, qtype uint16) (*dns.Msg, error) { return lookup(key(ip, name, qtype)) },
		// tests that look up a registration script their own
		registration: func(string) registrationStatus { return statusDelegated },
	}
}

func nsRRs(zone string, hosts ...string) []dns.RR {
	var rrs []dns.RR
	for _, h := range hosts {
		rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: dns.Fqdn(h)})
	}
	return rrs
}

// host makes a nameserver hostname resolve to ip.
func (f fakeDNS) host(name, ip string) {
	f[key("resolver", name, dns.TypeA)] = &dns.Msg{Answer: []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(ip)},
	}}
}

// referral makes the server at ip delegate zone to hosts.
func (f fakeDNS) referral(ip, zone string, hosts ...string) {
	f[key(ip, zone, dns.TypeNS)] = &dns.Msg{Ns: nsRRs(zone, hosts...)}
}

// serves makes the server at ip answer authoritatively for zone.
func (f fakeDNS) serves(ip, zone string) {
	m := &dns.Msg{Answer: []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}}
	m.Authoritative = true
	f[key(ip, zone, dns.TypeSOA)] = m
}

// refuses makes the server at ip refuse queries for zone.
func (f fakeDNS) refuses(ip, zone string) {
	m := &dns.Msg{}
	m.Rcode = dns.RcodeRefused
	f[key(ip, zone, dns.TypeSOA)] = m
}

// world returns DNS in which .com delegates example.com to a working nameserver.
func world() fakeDNS {
	f := fakeDNS{}
	f[key("resolver", "com", dns.TypeNS)] = &dns.Msg{Answer: nsRRs("com", "a.gtld-servers.net")}
	f.host("a.gtld-servers.net", "192.0.2.1")
	f.referral("192.0.2.1", "example.com", "ns1.example-dns.test")
	f.host("ns1.example-dns.test", "192.0.2.2")
	f.serves("192.0.2.2", "example.com")
	// within example.com: app.sub.example.com is in sub.example.com, unless delegated
	f[key("192.0.2.2", "app.sub.example.com", dns.TypeNS)] = &dns.Msg{}
	return f
}

func TestDanglingDelegationToVulnerableProvider(t *testing.T) {
	f := world()
	f.referral("192.0.2.2", "sub.example.com", "ns1.digitalocean.com", "ns2.digitalocean.com")
	f.host("ns1.digitalocean.com", "192.0.2.3")
	f.host("ns2.digitalocean.com", "192.0.2.4")
	f.refuses("192.0.2.3", "sub.example.com")
	f.refuses("192.0.2.4", "sub.example.com")

	got := f.checker().check("app.sub.example.com", nil)
	if got == nil || got.kind != "vuln" || got.platform != "DigitalOcean DNS" || got.edgeCase {
		t.Fatalf("expected a DigitalOcean DNS finding, got %+v", got)
	}
	if got.fqdn != "app.sub.example.com" || !strings.Contains(got.detail, "sub.example.com is delegated to DigitalOcean DNS") {
		t.Errorf("unexpected finding: %+v", got)
	}
}

func TestHealthyDelegation(t *testing.T) {
	f := world()
	f.referral("192.0.2.2", "sub.example.com", "ns1.digitalocean.com")
	f.host("ns1.digitalocean.com", "192.0.2.3")
	f.serves("192.0.2.3", "sub.example.com")
	f[key("192.0.2.3", "app.sub.example.com", dns.TypeNS)] = &dns.Msg{}
	if got := f.checker().check("app.sub.example.com", nil); got != nil {
		t.Errorf("expected no issue, got %+v", got)
	}
}

func TestDanglingDelegationToUnlistedProviderIsDNSIssue(t *testing.T) {
	f := world()
	f.referral("192.0.2.2", "sub.example.com", "ns-1.awsdns-00.com")
	f.host("ns-1.awsdns-00.com", "192.0.2.3")
	f.refuses("192.0.2.3", "sub.example.com")
	got := f.checker().check("app.sub.example.com", nil)
	if got == nil || got.kind != "dns" || !strings.Contains(got.err.Error(), "dangling delegation") {
		t.Fatalf("expected a dangling delegation DNS issue, got %+v", got)
	}
}

// A host serving a parent zone for another customer answers authoritatively, but with that
// zone's SOA rather than the delegated zone's.
func TestAnswerFromAnotherZoneIsNotServing(t *testing.T) {
	f := world()
	f.referral("192.0.2.2", "sub.example.com", "ns1.linode.com")
	f.host("ns1.linode.com", "192.0.2.3")
	m := &dns.Msg{Ns: []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}}
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	f[key("192.0.2.3", "sub.example.com", dns.TypeSOA)] = m
	got := f.checker().check("app.sub.example.com", nil)
	if got == nil || got.platform != "Linode DNS" {
		t.Fatalf("expected a Linode DNS finding, got %+v", got)
	}
}

func TestUnreachableNameserversAreInconclusive(t *testing.T) {
	f := world()
	f.referral("192.0.2.2", "sub.example.com", "ns1.digitalocean.com")
	f.host("ns1.digitalocean.com", "192.0.2.3")
	// no scripted SOA response: the query times out
	if got := f.checker().check("app.sub.example.com", nil); got != nil {
		t.Errorf("expected no conclusion when nameservers do not respond, got %+v", got)
	}
}

func TestDanglingRegisteredDomain(t *testing.T) {
	f := world()
	f.referral("192.0.2.1", "example.com", "ns1-01.azure-dns.com", "ns2-01.azure-dns.net")
	f.host("ns1-01.azure-dns.com", "192.0.2.5")
	f.host("ns2-01.azure-dns.net", "192.0.2.6")
	f.refuses("192.0.2.5", "example.com")
	f.refuses("192.0.2.6", "example.com")
	got := f.checker().check("www.example.com", nil)
	if got == nil || got.platform != "Azure DNS" || !got.edgeCase {
		t.Fatalf("expected an Azure DNS edge case, got %+v", got)
	}
}

func TestNonexistentNameStopsTheWalk(t *testing.T) {
	f := world()
	nx := &dns.Msg{}
	nx.Rcode = dns.RcodeNameError
	f[key("192.0.2.2", "sub.example.com", dns.TypeNS)] = nx
	if got := f.checker().check("app.sub.example.com", nil); got != nil {
		t.Errorf("expected no issue for a name that does not exist, got %+v", got)
	}
}

func TestNSProviderRequiresEveryNameserverToMatch(t *testing.T) {
	if p, ok := nsProvider([]string{"ns1.digitalocean.com", "ns2.digitalocean.com"}); !ok || p.platform != "DigitalOcean DNS" {
		t.Errorf("expected DigitalOcean DNS, got %+v %v", p, ok)
	}
	if _, ok := nsProvider([]string{"ns1.digitalocean.com", "ns1.example-dns.test"}); ok {
		t.Error("expected no match when only some nameservers belong to the provider")
	}
	if _, ok := nsProvider(nil); ok {
		t.Error("expected no match for no nameservers")
	}
	for _, ns := range []string{"ns-cloud-a1.googledomains.com", "ns3-07.azure-dns.org", "ns1abc.name.com", "yns2.yahoo.com"} {
		if _, ok := nsProvider([]string{ns}); !ok {
			t.Errorf("expected %s to match a provider", ns)
		}
	}
}

func TestZonesBetween(t *testing.T) {
	got := strings.Join(zonesBetween("co.uk", "a.b.example.co.uk"), ",")
	if want := "example.co.uk,b.example.co.uk,a.b.example.co.uk"; got != want {
		t.Errorf("expected %s, got %s", want, got)
	}
}

// nxdomain makes a nameserver hostname not exist.
func (f fakeDNS) nxdomain(name string) {
	m := &dns.Msg{}
	m.Rcode = dns.RcodeNameError
	f[key("resolver", name, dns.TypeA)] = m
}

func TestNameserverOnUnregisteredDomain(t *testing.T) {
	f := world()
	// one nameserver is healthy, so the name still resolves
	f.referral("192.0.2.2", "sub.example.com", "ns1.example-dns.test", "ns2.expired-dns.test")
	f.nxdomain("ns2.expired-dns.test")
	c := f.checker()
	var looked []string
	c.registration = func(domain string) registrationStatus {
		looked = append(looked, domain)
		return statusUnregistered
	}
	got := c.check("app.sub.example.com", nil)
	if got == nil || got.kind != "vuln" || got.platform != "Unregistered domain" || got.edgeCase {
		t.Fatalf("expected an unregistered domain finding, got %+v", got)
	}
	if !strings.Contains(got.detail, "sub.example.com is delegated to nameserver ns2.expired-dns.test; expired-dns.test is not registered") {
		t.Errorf("unexpected detail %q", got.detail)
	}
	// only the nameserver that does not exist is looked up
	if strings.Join(looked, ",") != "expired-dns.test" {
		t.Errorf("expected only expired-dns.test to be looked up, got %v", looked)
	}
}

func TestNameserverWithinTheZoneIsNotLookedUp(t *testing.T) {
	f := world()
	f.referral("192.0.2.2", "sub.example.com", "ns1.sub.example.com")
	f.nxdomain("ns1.sub.example.com")
	c := f.checker()
	c.registration = func(domain string) registrationStatus {
		t.Errorf("a nameserver in the zone's own domain should not be looked up, got %s", domain)
		return statusUnregistered
	}
	if got := c.check("app.sub.example.com", nil); got != nil && got.platform == "Unregistered domain" {
		t.Errorf("expected no registration finding, got %+v", got)
	}
}

func TestRegisteredDomainWithNameserverOnExpiredDomain(t *testing.T) {
	f := world()
	f.referral("192.0.2.1", "example.com", "ns1.gone-dns.test", "ns2.gone-dns.test")
	f.nxdomain("ns1.gone-dns.test")
	f.nxdomain("ns2.gone-dns.test")
	c := f.checker()
	c.registration = func(string) registrationStatus { return statusUndelegated }
	got := c.check("www.example.com", nil)
	if got == nil || got.platform != "Undelegated domain" || !got.edgeCase || !strings.Contains(got.detail, "example.com is delegated to nameserver ns1.gone-dns.test") {
		t.Fatalf("expected an undelegated domain edge case, got %+v", got)
	}
}

func TestQueryCacheSendsEachQueryOnce(t *testing.T) {
	q := newDNSQueries()
	var mu sync.Mutex
	sent := 0
	query := func() (*dns.Msg, error) {
		mu.Lock()
		sent++
		mu.Unlock()
		return &dns.Msg{}, nil
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = q.cached("192.0.2.1", "Example.com", dns.TypeNS, query)
		}()
	}
	wg.Wait()
	_, _ = q.cached("192.0.2.1", "example.com", dns.TypeNS, query)
	if sent != 1 {
		t.Errorf("expected one query, got %d", sent)
	}
	_, _ = q.cached("192.0.2.1", "example.com", dns.TypeSOA, query)
	if sent != 2 {
		t.Errorf("expected a different type to be queried separately, got %d queries", sent)
	}
}
