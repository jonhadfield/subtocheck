package subtocheck

import (
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var nameservers = []string{
	"8.8.8.8",         // google
	"8.8.4.4",         // google
	"209.244.0.3",     // level3
	"209.244.0.4",     // level3
	"1.1.1.1",         // cloudflare
	"1.0.0.1",         // cloudflare
	"9.9.9.9",         // quad9
	"149.112.112.112", // quad9
}

// checkResolves resolves the fqdn and returns any DNS issues along with the CNAME
// targets followed, so later checks can tell which provider serves the name.
func checkResolves(fqdn string, log *scanLog) (issues issues, cnames []string) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = true
	c.Timeout = 1500 * time.Millisecond
	var record *dns.Msg
	var err error
	ns := rand.IntN(len(nameservers))
	log.debugf("resolving %q with nameserver %s", fqdn, nameservers[ns])
	record, err = exchangeDNS(c, m, net.JoinHostPort(nameservers[ns], "53"))
	if err == nil {
		cnames = cnameTargets(record)
	}
	if err != nil {
		err = errors.Errorf("%s could not be resolved (%v)", fqdn, err)
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	} else if record.Rcode == dns.RcodeNameError && len(cnames) > 0 {
		// the name exists but the CNAME points at a name that does not
		issues = append(issues, danglingCNAMEIssue(fqdn, cnames[len(cnames)-1], registrations.status))
		err = issues[len(issues)-1].err
	} else if record.Rcode == dns.RcodeServerFailure || record.Rcode == dns.RcodeRefused {
		// what a resolver returns for a name delegated to nameservers that do not serve it
		if dangling := delegations.check(fqdn, log); dangling != nil {
			issues = append(issues, *dangling)
			err = dangling.err
		} else {
			err = errors.Errorf("%s could not be resolved (%s from %s)", fqdn, dns.RcodeToString[record.Rcode],
				nameservers[ns])
			issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
		}
	} else if len(record.Answer) == 0 {
		err = errors.Errorf("%s could not be resolved (no answer from %s)", fqdn, nameservers[ns])
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	} else if record.Rcode != 0 {
		err = errors.Errorf("%s could not be resolved (%s from %s)", fqdn, dns.RcodeToString[record.Rcode],
			nameservers[ns])
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	}
	if err != nil {
		log.debugf("%s", about(fqdn, err))
	}

	return
}

// cnameTargets returns the target of each CNAME in the answer, in the order followed.
func cnameTargets(record *dns.Msg) (targets []string) {
	for _, rr := range record.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			targets = append(targets, strings.ToLower(strings.TrimSuffix(cname.Target, ".")))
		}
	}
	return
}

// danglingCNAMEIssue reports a CNAME whose target does not exist. It is a potential
// vulnerability if the target belongs to a provider where deleted names can be registered
// again, or if the target's own domain is not registered, so anyone could register it.
func danglingCNAMEIssue(fqdn, target string, lookup registrationLookup) issue {
	for _, pattern := range cnamePatterns {
		if hasSuffix(target, pattern.suffixes) {
			return issue{
				kind:     "vuln",
				platform: pattern.platform,
				fqdn:     fqdn,
				url:      fqdn,
				err:      errors.Errorf("CNAME to %s, which does not exist, matches platform: %s", target, pattern.platform),
				detail:   "CNAME to " + target + ", which does not exist",
			}
		}
	}
	notExist := issue{
		kind: "dns",
		fqdn: fqdn,
		err:  errors.Errorf("%s is a dangling CNAME: target %s does not exist", fqdn, target),
	}
	domain := registeredDomain(target)
	// a target within the scanned name's own domain cannot be registered by anyone else
	if domain == "" || domain == registeredDomain(fqdn) {
		return notExist
	}
	if i := registrationIssue(fqdn, "CNAME to "+target, domain, lookup(domain), time.Now()); i != nil {
		return *i
	}
	return notExist
}

// hasSuffix reports whether host is, or is a subdomain of, any of the domains.
func hasSuffix(host string, domains []string) bool {
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// dnsQueries sends DNS queries and caches the responses, and failures, for the rest of the
// scan: the domains in a scan share zones, nameservers and registrations, so most walks
// repeat queries already made.
type dnsQueries struct {
	client *dns.Client
	mu     sync.Mutex
	cache  map[string]*cachedQuery
}

type cachedQuery struct {
	once sync.Once
	resp *dns.Msg
	err  error
}

func newDNSQueries() *dnsQueries {
	return &dnsQueries{client: &dns.Client{Timeout: 2 * time.Second}, cache: map[string]*cachedQuery{}}
}

// resolve sends a recursive query to a public resolver.
func (q *dnsQueries) resolve(name string, qtype uint16) (*dns.Msg, error) {
	return q.cached("resolver", name, qtype, func() (*dns.Msg, error) {
		return q.exchange(nameservers[rand.IntN(len(nameservers))], name, qtype, true)
	})
}

// ask sends a non-recursive query to the nameserver at ip.
func (q *dnsQueries) ask(ip, name string, qtype uint16) (*dns.Msg, error) {
	return q.cached(ip, name, qtype, func() (*dns.Msg, error) {
		return q.exchange(ip, name, qtype, false)
	})
}

func (q *dnsQueries) cached(server, name string, qtype uint16, query func() (*dns.Msg, error)) (*dns.Msg, error) {
	key := server + "|" + strings.ToLower(name) + "|" + dns.TypeToString[qtype]
	q.mu.Lock()
	entry, ok := q.cache[key]
	if !ok {
		entry = &cachedQuery{}
		q.cache[key] = entry
	}
	q.mu.Unlock()
	// concurrent callers for the same query wait for the one in flight
	entry.once.Do(func() { entry.resp, entry.err = query() })
	return entry.resp, entry.err
}

func (q *dnsQueries) exchange(server, name string, qtype uint16, recurse bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = recurse
	return exchangeDNS(q.client, m, net.JoinHostPort(server, "53"))
}

// ednsBufferSize is the UDP payload size advertised with EDNS, as recommended to avoid
// fragmentation. Without EDNS, replies are limited to 512 bytes, which signed zones often
// exceed.
const ednsBufferSize = 1232

// exchangeDNS sends a query to address (host:port) over UDP with EDNS, and again over TCP
// if the reply was truncated, as a truncated reply can leave out the records asked for.
func exchangeDNS(client *dns.Client, m *dns.Msg, address string) (*dns.Msg, error) {
	if m.IsEdns0() == nil {
		m.SetEdns0(ednsBufferSize, false)
	}
	r, _, err := client.Exchange(m, address)
	if err == nil && r != nil && r.Truncated {
		tcp := *client
		tcp.Net = "tcp"
		r, _, err = tcp.Exchange(m, address)
	}
	return r, err
}
