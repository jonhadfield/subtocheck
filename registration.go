package subtocheck

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
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
	// nameservers, as when a registration has expired; the registration's states and
	// expiry say how far through expiry it is
	statusUndelegated
	// statusUnregistered: the domain has no nameservers and the registry has no record of it
	statusUnregistered
	// statusUnconfirmed: the domain has no nameservers and its registry could not confirm
	// whether it is registered, through RDAP or WHOIS
	statusUnconfirmed
)

// registration is what a registry says about a domain.
type registration struct {
	status registrationStatus
	// states are the registry's status values, in RDAP's lower case form, such as
	// "redemption period", "pending delete" or "client hold"
	states  []string
	expires time.Time
}

func (r registration) has(state string) bool {
	return slices.Contains(r.states, state)
}

// registrationLookup reports the registration of a registered domain, such as example.com.
type registrationLookup func(domain string) registration

// registrationChecker looks domains up in DNS and, if they have no nameservers, in their
// registry's RDAP service, or WHOIS for registries without one. Results are cached, as many
// names can point at one domain.
type registrationChecker struct {
	resolve   func(name string, qtype uint16) (*dns.Msg, error)
	rdapBases func() map[string]string // RDAP base URL by top-level domain
	client    *http.Client
	whois     func(domain string) (string, bool) // a registry's WHOIS reply, if it has a server

	mu    sync.Mutex
	cache map[string]registration
}

func newRegistrationChecker(resolve func(string, uint16) (*dns.Msg, error), rdapBases func() map[string]string, whois func(string) (string, bool)) *registrationChecker {
	return &registrationChecker{
		resolve:   resolve,
		rdapBases: rdapBases,
		client:    &http.Client{Timeout: 10 * time.Second},
		whois:     whois,
		cache:     map[string]registration{},
	}
}

// defaultRDAPBases fetches IANA's RDAP bootstrap once, when first needed.
func defaultRDAPBases() func() map[string]string {
	client := &http.Client{Timeout: 10 * time.Second}
	return sync.OnceValue(func() map[string]string { return fetchRDAPBootstrap(client, rdapBootstrapURL) })
}

func (r *registrationChecker) status(domain string) registration {
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

func (r *registrationChecker) lookup(domain string) registration {
	resp, err := r.resolve(domain, dns.TypeNS)
	if err != nil || resp == nil {
		return registration{status: statusUnknown}
	}
	if resp.Rcode == dns.RcodeSuccess {
		return registration{status: statusDelegated}
	}
	if resp.Rcode != dns.RcodeNameError {
		return registration{status: statusUnknown}
	}
	tld := domain[strings.LastIndex(domain, ".")+1:]
	if base, ok := r.rdapBases()[tld]; ok {
		return r.rdap(base, domain)
	}
	if reply, ok := r.whois(domain); ok {
		return parseWhois(domain, reply)
	}
	return registration{status: statusUnconfirmed}
}

// rdap asks a registry's RDAP service about a domain.
func (r *registrationChecker) rdap(base, domain string) registration {
	unconfirmed := registration{status: statusUnconfirmed}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(base, "/")+"/domain/"+domain, nil)
	if err != nil {
		return unconfirmed
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "subtocheck")
	resp, err := r.client.Do(req)
	if err != nil {
		return unconfirmed
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return registration{status: statusUnregistered}
	case http.StatusOK:
		var record struct {
			Status []string `json:"status"`
			Events []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
		}
		found := registration{status: statusUndelegated}
		// a record that cannot be parsed still shows the domain is registered
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&record) == nil {
			for _, state := range record.Status {
				found.states = append(found.states, strings.ToLower(state))
			}
			for _, e := range record.Events {
				if e.Action == "expiration" {
					found.expires, _ = time.Parse(time.RFC3339, e.Date)
				}
			}
		}
		return found
	default:
		return unconfirmed
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

// registrationIssue reports that something fqdn depends on, described by subject, is on a
// domain that anyone could register, or nil if the domain's status gives no such reason.
func registrationIssue(fqdn, subject, domain string, reg registration, now time.Time) *issue {
	finding := func(platform, detail string, edgeCase bool) *issue {
		return &issue{
			kind:     "vuln",
			platform: platform,
			fqdn:     fqdn,
			url:      fqdn,
			err:      errors.Errorf("%s: %s", subject, detail),
			detail:   subject + "; " + detail,
			edgeCase: edgeCase,
		}
	}
	switch reg.status {
	case statusUnregistered:
		return finding("Unregistered domain", domain+" is not registered, so may be available to register", false)
	case statusUnconfirmed:
		return finding("Unregistered domain", domain+" has no DNS and its registry could not confirm whether it is registered", true)
	case statusUndelegated:
		platform, detail := lifecycle(domain, reg, now)
		return finding(platform, detail, true)
	default:
		return nil
	}
}

// lifecycle describes how far a registered domain without nameservers is through expiry,
// from the registry's status values and expiry date, most advanced stage first.
func lifecycle(domain string, reg registration, now time.Time) (platform, detail string) {
	expired := !reg.expires.IsZero() && reg.expires.Before(now)
	switch {
	case reg.has("pending delete"):
		platform, detail = "Domain pending deletion", domain+" is pending deletion, so will be available to register within days"
	case reg.has("redemption period"):
		platform, detail = "Domain in redemption", domain+" is in its redemption period: unless the registrant restores it, it will be deleted and available to register"
	case reg.has("client hold") || reg.has("server hold"):
		platform, detail = "Domain on hold", domain+" is registered but on hold, so it does not resolve"
	case reg.has("auto renew period") || expired:
		platform, detail = "Expired domain", domain+" has expired and is in its renewal grace period"
	default:
		platform, detail = "Undelegated domain", domain+" is registered but has no nameservers"
		if reg.expires.IsZero() {
			detail += ", so its registration may have expired"
		}
	}
	switch {
	case expired:
		detail += " (expired " + reg.expires.Format("2006-01-02") + ")"
	case !reg.expires.IsZero():
		detail += " (expires " + reg.expires.Format("2006-01-02") + ")"
	}
	return platform, detail
}
