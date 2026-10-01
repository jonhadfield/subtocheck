package subtocheck

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		{statusUnconfirmed, "vuln", "Unregistered domain", true, "no RDAP service"},
		{statusUndelegated, "vuln", "Undelegated domain", true, "may have expired"},
		{statusDelegated, "dns", "", false, ""},
		{statusUnknown, "dns", "", false, ""},
	}
	for _, c := range cases {
		var looked string
		got := danglingCNAMEIssue("app.example.com", "cdn.old-vendor.com", func(domain string) registrationStatus {
			looked = domain
			return c.status
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
	got := danglingCNAMEIssue("app.example.com", "old.example.com", func(string) registrationStatus {
		t.Error("a target in the scanned name's own domain should not be looked up")
		return statusUnregistered
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
		cache:     map[string]registrationStatus{},
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
		if got := r.status("old-vendor.com"); got != c.want {
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
	if got := r.status("old-vendor.io"); got != statusUnconfirmed {
		t.Errorf("expected unconfirmed for a TLD with no RDAP service, got %d", got)
	}
	if *requests != 0 {
		t.Errorf("expected no RDAP request, got %d", *requests)
	}
}

func TestRegistrationStatusWhenDNSFails(t *testing.T) {
	r, _ := fakeRegistry(t, dns.RcodeNameError, http.StatusNotFound)
	r.resolve = func(string, uint16) (*dns.Msg, error) { return nil, errors.New("timeout") }
	if got := r.status("old-vendor.com"); got != statusUnknown {
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
