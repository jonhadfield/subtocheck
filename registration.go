package subtocheck

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// rdapBootstrapURL is IANA's registry of the RDAP service for each top-level domain.
const rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

// registrationStatus is what is known about whether a domain is registered.
type registrationStatus int

const (
	// statusUnknown: the lookups failed, so nothing can be concluded
	statusUnknown registrationStatus = iota
	// statusDelegated: the domain has nameservers, so it is registered
	statusDelegated
	// statusUndelegated: the registry has a record of the domain but it has no
	// nameservers, as when a registration has expired
	statusUndelegated
	// statusUnregistered: the domain has no nameservers and the registry has no record of it
	statusUnregistered
	// statusUnconfirmed: the domain has no nameservers and its registry has no RDAP
	// service to confirm whether it is registered
	statusUnconfirmed
)

// registrationLookup reports the registration status of a registered domain, such as
// example.com.
type registrationLookup func(domain string) registrationStatus

// registrationChecker looks domains up in DNS and, if they have no nameservers, in their
// registry's RDAP service. Results are cached, as many names can point at one domain.
type registrationChecker struct {
	resolve   func(name string, qtype uint16) (*dns.Msg, error)
	rdapBases func() map[string]string // RDAP base URL by top-level domain
	client    *http.Client

	mu    sync.Mutex
	cache map[string]registrationStatus
}

func newRegistrationChecker() *registrationChecker {
	client := &http.Client{Timeout: 10 * time.Second}
	return &registrationChecker{
		resolve:   queries.resolve,
		rdapBases: sync.OnceValue(func() map[string]string { return fetchRDAPBootstrap(client, rdapBootstrapURL) }),
		client:    client,
		cache:     map[string]registrationStatus{},
	}
}

// registrations is shared across a scan so each domain and the RDAP bootstrap are only
// looked up once.
var registrations = newRegistrationChecker()

func (r *registrationChecker) status(domain string) registrationStatus {
	r.mu.Lock()
	if s, ok := r.cache[domain]; ok {
		r.mu.Unlock()
		return s
	}
	r.mu.Unlock()

	s := r.lookup(domain)
	r.mu.Lock()
	r.cache[domain] = s
	r.mu.Unlock()
	return s
}

func (r *registrationChecker) lookup(domain string) registrationStatus {
	resp, err := r.resolve(domain, dns.TypeNS)
	if err != nil || resp == nil {
		return statusUnknown
	}
	if resp.Rcode == dns.RcodeSuccess {
		return statusDelegated
	}
	if resp.Rcode != dns.RcodeNameError {
		return statusUnknown
	}
	tld := domain[strings.LastIndex(domain, ".")+1:]
	base, ok := r.rdapBases()[tld]
	if !ok {
		return statusUnconfirmed
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(base, "/")+"/domain/"+domain, nil)
	if err != nil {
		return statusUnconfirmed
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "subtocheck")
	rdapResp, err := r.client.Do(req)
	if err != nil {
		return statusUnconfirmed
	}
	_ = rdapResp.Body.Close()
	switch rdapResp.StatusCode {
	case http.StatusOK:
		return statusUndelegated
	case http.StatusNotFound:
		return statusUnregistered
	default:
		return statusUnconfirmed
	}
}

// fetchRDAPBootstrap returns the RDAP base URL for each top-level domain, or an empty map
// if the registry cannot be fetched.
func fetchRDAPBootstrap(client *http.Client, url string) map[string]string {
	bases := map[string]string{}
	resp, err := client.Get(url)
	if err != nil {
		return bases
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return bases
	}
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bootstrap); err != nil {
		return bases
	}
	for _, service := range bootstrap.Services {
		if len(service) != 2 || len(service[1]) == 0 {
			continue
		}
		// prefer an https URL where a registry lists several
		base := service[1][0]
		for _, u := range service[1] {
			if strings.HasPrefix(u, "https://") {
				base = u
				break
			}
		}
		for _, tld := range service[0] {
			bases[strings.ToLower(tld)] = base
		}
	}
	return bases
}

// registeredDomain returns the domain someone would register to control host, such as
// example.co.uk for www.example.co.uk.
func registeredDomain(host string) string {
	domain, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(host, "."))
	if err != nil {
		return ""
	}
	return domain
}
