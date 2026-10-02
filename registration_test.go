package subtocheck

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDanglingCNAMEToUnregisteredDomain(t *testing.T) {
	cases := []struct {
		status   registrationStatus
		kind     string
		platform string
		edgeCase bool
		detail   string
	}{
		{statusUnregistered, "vuln", "Unregistered domain", false, "old-vendor.com is not registered"},
		{statusUnconfirmed, "vuln", "Unregistered domain", true, "registry could not confirm"},
		{statusUndelegated, "vuln", "Undelegated domain", true, "may have expired"},
		{statusDelegated, "dns", "", false, ""},
		{statusUnknown, "dns", "", false, ""},
	}
	for _, c := range cases {
		var looked string
		got := danglingCNAMEIssue("app.example.com", "cdn.old-vendor.com", func(domain string) registration {
			looked = domain
			return registration{status: c.status}
		})
		if looked != "old-vendor.com" {
			t.Errorf("status %d: expected old-vendor.com to be looked up, got %q", c.status, looked)
		}
		if got.kind != c.kind || got.platform != c.platform || got.edgeCase != c.edgeCase || !strings.Contains(got.detail, c.detail) {
			t.Errorf("status %d: got %s/%q edge=%v %q", c.status, got.kind, got.platform, got.edgeCase, got.detail)
		}
	}
}

func TestDanglingCNAMEWithinOwnDomainIsNotLookedUp(t *testing.T) {
	got := danglingCNAMEIssue("app.example.com", "old.example.com", func(string) registration {
		t.Error("a target in the scanned name's own domain should not be looked up")
		return registration{status: statusUnregistered}
	})
	if got.kind != "dns" {
		t.Errorf("expected a DNS issue, got %+v", got)
	}
}

// fakeRegistry returns a checker whose DNS answers with rcode for every name and whose RDAP
// service for .com answers with rdapStatus.
func fakeRegistry(t *testing.T, rcode, rdapStatus int) (*registrationChecker, *int) {
	t.Helper()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/rdap/domain/old-vendor.com" || r.Header.Get("Accept") != "application/rdap+json" {
			t.Errorf("unexpected RDAP request %s %v", r.URL.Path, r.Header)
		}
		w.WriteHeader(rdapStatus)
	}))
	t.Cleanup(server.Close)
	r := &registrationChecker{
		resolve: func(string, uint16) (*dns.Msg, error) {
			m := &dns.Msg{}
			m.Rcode = rcode
			return m, nil
		},
		rdapBases: func() map[string]string { return map[string]string{"com": server.URL + "/rdap/"} },
		client:    server.Client(),
		whois:     func(string) (string, bool) { return "", false },
		cache:     map[string]registration{},
	}
	return r, &requests
}

func TestRegistrationStatus(t *testing.T) {
	cases := []struct {
		name       string
		rcode      int
		rdapStatus int
		want       registrationStatus
		wantRDAP   bool
	}{
		{"has nameservers", dns.RcodeSuccess, http.StatusOK, statusDelegated, false},
		{"not in the registry", dns.RcodeNameError, http.StatusNotFound, statusUnregistered, true},
		{"in the registry without nameservers", dns.RcodeNameError, http.StatusOK, statusUndelegated, true},
		{"registry error", dns.RcodeNameError, http.StatusTooManyRequests, statusUnconfirmed, true},
		{"resolver failure", dns.RcodeServerFailure, http.StatusOK, statusUnknown, false},
	}
	for _, c := range cases {
		r, requests := fakeRegistry(t, c.rcode, c.rdapStatus)
		if got := r.status("old-vendor.com").status; got != c.want {
			t.Errorf("%s: expected status %d, got %d", c.name, c.want, got)
		}
		if (*requests > 0) != c.wantRDAP {
			t.Errorf("%s: expected RDAP lookup %v, got %d requests", c.name, c.wantRDAP, *requests)
		}
	}
}

func TestRegistrationStatusIsCached(t *testing.T) {
	r, requests := fakeRegistry(t, dns.RcodeNameError, http.StatusNotFound)
	r.status("old-vendor.com")
	r.status("old-vendor.com")
	if *requests != 1 {
		t.Errorf("expected one RDAP request, got %d", *requests)
	}
}

func TestRegistrationStatusWithoutRDAPService(t *testing.T) {
	r, requests := fakeRegistry(t, dns.RcodeNameError, http.StatusNotFound)
	if got := r.status("old-vendor.io").status; got != statusUnconfirmed {
		t.Errorf("expected unconfirmed for a TLD with no RDAP service, got %d", got)
	}
	if *requests != 0 {
		t.Errorf("expected no RDAP request, got %d", *requests)
	}
}

func TestRegistrationStatusWhenDNSFails(t *testing.T) {
	r, _ := fakeRegistry(t, dns.RcodeNameError, http.StatusNotFound)
	r.resolve = func(string, uint16) (*dns.Msg, error) { return nil, errors.New("timeout") }
	if got := r.status("old-vendor.com").status; got != statusUnknown {
		t.Errorf("expected unknown when DNS fails, got %d", got)
	}
}

func TestFetchRDAPBootstrap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, `{"version":"1.0","services":[
			[["com","NET"],["https://rdap.example/com/v1/"]],
			[["org"],["http://rdap.example/org/","https://rdap.example/org/"]],
			[["broken"]]
		]}`)
	}))
	defer server.Close()
	got := fetchRDAPBootstrap(server.Client(), server.URL)
	want := map[string]string{
		"com": "https://rdap.example/com/v1/",
		"net": "https://rdap.example/com/v1/",
		"org": "https://rdap.example/org/",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for tld, url := range want {
		if got[tld] != url {
			t.Errorf("%s: expected %s, got %s", tld, url, got[tld])
		}
	}
	if len(fetchRDAPBootstrap(server.Client(), server.URL+"/missing")) != 0 {
		t.Error("expected no services when the bootstrap cannot be fetched")
	}
}

func TestRegisteredDomain(t *testing.T) {
	for host, want := range map[string]string{
		"cdn.old-vendor.com":   "old-vendor.com",
		"a.b.example.co.uk.":   "example.co.uk",
		"user.github.io":       "user.github.io",
		"com":                  "",
		"x.old-vendor.example": "old-vendor.example",
	} {
		if got := registeredDomain(host); got != want {
			t.Errorf("%s: expected %q, got %q", host, want, got)
		}
	}
}

func TestLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	past := time.Date(2026, 8, 14, 4, 0, 0, 0, time.UTC)
	future := time.Date(2027, 8, 13, 4, 0, 0, 0, time.UTC)
	cases := []struct {
		reg      registration
		platform string
		detail   string
	}{
		{registration{states: []string{"redemption period", "pending delete"}, expires: past},
			"Domain pending deletion", "old-vendor.com is pending deletion, so will be available to register within days (expired 2026-08-14)"},
		{registration{states: []string{"redemption period"}, expires: past},
			"Domain in redemption", "old-vendor.com is in its redemption period: unless the registrant restores it, it will be deleted and available to register (expired 2026-08-14)"},
		{registration{states: []string{"client hold"}, expires: future},
			"Domain on hold", "old-vendor.com is registered but on hold, so it does not resolve (expires 2027-08-13)"},
		{registration{states: []string{"server hold"}},
			"Domain on hold", "old-vendor.com is registered but on hold, so it does not resolve"},
		{registration{states: []string{"auto renew period"}, expires: past},
			"Expired domain", "old-vendor.com has expired and is in its renewal grace period (expired 2026-08-14)"},
		// an expiry date in the past is enough to say it has expired
		{registration{states: []string{"client transfer prohibited"}, expires: past},
			"Expired domain", "old-vendor.com has expired and is in its renewal grace period (expired 2026-08-14)"},
		{registration{states: []string{"inactive"}, expires: future},
			"Undelegated domain", "old-vendor.com is registered but has no nameservers (expires 2027-08-13)"},
		{registration{},
			"Undelegated domain", "old-vendor.com is registered but has no nameservers, so its registration may have expired"},
	}
	for _, c := range cases {
		platform, detail := lifecycle("old-vendor.com", c.reg, now)
		if platform != c.platform || detail != c.detail {
			t.Errorf("%v: got %q %q", c.reg.states, platform, detail)
		}
	}
}

func TestRDAPRecordStatesAndExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"objectClassName":"domain","ldhName":"OLD-VENDOR.COM",
			"status":["Redemption Period","client transfer prohibited"],
			"events":[{"eventAction":"registration","eventDate":"2015-08-14T04:00:00Z"},
			          {"eventAction":"expiration","eventDate":"2026-08-14T04:00:00Z"}]}`)
	}))
	defer server.Close()
	r := &registrationChecker{client: server.Client()}
	got := r.rdap(server.URL+"/", "old-vendor.com")
	if got.status != statusUndelegated || !got.has("redemption period") || !got.has("client transfer prohibited") {
		t.Errorf("unexpected registration %+v", got)
	}
	if want := time.Date(2026, 8, 14, 4, 0, 0, 0, time.UTC); !got.expires.Equal(want) {
		t.Errorf("expected expiry %v, got %v", want, got.expires)
	}
}

func TestRDAPRecordThatCannotBeParsedIsStillRegistered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "not json")
	}))
	defer server.Close()
	r := &registrationChecker{client: server.Client()}
	if got := r.rdap(server.URL+"/", "old-vendor.com"); got.status != statusUndelegated || len(got.states) != 0 {
		t.Errorf("unexpected registration %+v", got)
	}
}

func TestParseWhois(t *testing.T) {
	cases := []struct {
		name, domain, reply string
		status              registrationStatus
		states              []string
		expires             string
	}{
		{"io not found", "old-vendor.io", "Domain not found.\r\n>>> Last update of WHOIS database <<<\r\n", statusUnregistered, nil, ""},
		{"co not found", "old-vendor.co", "The queried object does not exist: DOMAIN NOT FOUND\r\n", statusUnregistered, nil, ""},
		{"de free", "old-vendor.de", "Domain: old-vendor.de\nStatus: free\n", statusUnregistered, nil, ""},
		{"ru not found", "old-vendor.ru", "No entries found for the selected source(s).\n", statusUnregistered, nil, ""},
		{"jp not found", "old-vendor.jp", "No match!!\nWith JPRS WHOIS, you can query...\n", statusUnregistered, nil, ""},
		{"record in redemption", "old-vendor.io",
			"Domain Name: old-vendor.io\nRegistry Expiry Date: 2026-08-14T04:00:00Z\nDomain Status: redemptionPeriod https://icann.org/epp#redemptionPeriod\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n",
			statusUndelegated, []string{"redemption period", "client transfer prohibited"}, "2026-08-14"},
		{"ru record", "old-vendor.ru", "domain:        OLD-VENDOR.RU\nstate:         REGISTERED, NOT DELEGATED\npaid-till:     2026-03-04T21:00:00Z\n",
			statusUndelegated, nil, "2026-03-04"},
		{"rate limited", "old-vendor.de", "55000000002 Connection refused; access control limit reached\n", statusUnconfirmed, nil, ""},
	}
	for _, c := range cases {
		got := parseWhois(c.domain, c.reply)
		if got.status != c.status || strings.Join(got.states, ",") != strings.Join(c.states, ",") {
			t.Errorf("%s: got status %d states %v", c.name, got.status, got.states)
		}
		if gotDate := map[bool]string{true: "", false: got.expires.Format("2006-01-02")}[got.expires.IsZero()]; gotDate != c.expires {
			t.Errorf("%s: expected expiry %q, got %q", c.name, c.expires, gotDate)
		}
	}
}

func TestWhoisServerDiscovery(t *testing.T) {
	var queries []string
	w := &whoisClient{servers: map[string]string{}, query: func(server, q string) (string, error) {
		queries = append(queries, server+" "+q)
		switch {
		case server == "whois.iana.org" && q == "io":
			return "domain:       IO\nwhois:        whois.nic.io\n", nil
		case server == "whois.iana.org" && q == "jp":
			return "refer:        whois.jprs.jp\n", nil
		case server == "whois.iana.org":
			return "domain:       EXAMPLE\n", nil
		default:
			return "Domain not found.\n", nil
		}
	}}
	if _, ok := w.lookup("a.io"); !ok {
		t.Fatal("expected a reply for .io")
	}
	_, _ = w.lookup("b.io")
	_, _ = w.lookup("c.jp")
	if _, ok := w.lookup("d.example"); ok {
		t.Error("expected no reply for a TLD without a WHOIS server")
	}
	want := "whois.iana.org io|whois.nic.io a.io|whois.nic.io b.io|whois.iana.org jp|whois.jprs.jp c.jp/e|whois.iana.org example"
	if got := strings.Join(queries, "|"); got != want {
		t.Errorf("unexpected queries:\n got %s\nwant %s", got, want)
	}
}

func TestWhoisFallbackForTLDWithoutRDAP(t *testing.T) {
	r, requests := fakeRegistry(t, dns.RcodeNameError, http.StatusNotFound)
	r.whois = func(domain string) (string, bool) { return "Domain not found.\n", true }
	if got := r.status("old-vendor.io"); got.status != statusUnregistered {
		t.Errorf("expected WHOIS to confirm the domain is unregistered, got %+v", got)
	}
	if *requests != 0 {
		t.Errorf("expected no RDAP request, got %d", *requests)
	}
}
