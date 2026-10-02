//go:build live

package subtocheck

// Live checks of everything subtocheck relies on outside itself: providers' pages, DNS
// hosts' behaviour, and registries' RDAP and WHOIS replies. They query real services, so
// they only build with the live tag:
//
//	go test -tags live -run TestLive -v .
//
// The fingerprints workflow runs them weekly and opens an issue when one fails, so a
// provider changing its page or a registry rewording a reply is noticed rather than
// quietly turning findings into misses.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// unclaimedHost is a name no provider has configured, so each answers it the way it
// answers a dangling custom domain.
const unclaimedHost = "subtocheck-live-check-7f3k2.example.com"

// liveFingerprints lists, for each fingerprint confirmed against its provider, an endpoint
// that serves the provider's page for hosts it does not know.
var liveFingerprints = []struct{ platform, endpoint string }{
	{"Campaign Monitor", "cname.createsend.com"},
	{"Canny", "cname.canny.io"},
	{"GetResponse", "getresponsepages.com"},
	{"Ghost", "ghost.io"},
	{"GitHub Pages", "github.io"},
	{"Heroku", "herokuapp.com"},
	{"Pingdom", "stats.pingdom.com"},
	{"S3", "s3.amazonaws.com"},
	{"Short.io", "cname.short.io"},
	{"SmartJobBoard", "52.16.160.97"},
	{"Surge.sh", "na-west1.surge.sh"},
	{"Tilda", "tilda.ws"},
	{"Tumblr", "domains.tumblr.com"},
	{"Uberflip", "read.uberflip.com"},
}

func TestLiveFingerprints(t *testing.T) {
	for _, f := range liveFingerprints {
		t.Run(f.platform, func(t *testing.T) {
			t.Parallel()
			var results []string
			for _, scheme := range []string{"https", "http"} {
				platform, summary := probe(scheme, f.endpoint)
				if platform == f.platform {
					return
				}
				results = append(results, scheme+": "+summary)
			}
			t.Errorf("%s no longer matches its fingerprint via %s:\n  %s", f.platform, f.endpoint, strings.Join(results, "\n  "))
		})
	}
}

// probe requests unclaimedHost from endpoint and returns the platform it matches, if any,
// and a summary of the response for diagnosing a mismatch.
func probe(scheme, endpoint string) (string, string) {
	var redirects []string
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: unclaimedHost},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// send the unclaimed host to the endpoint; redirects elsewhere resolve normally
				if host, port, _ := net.SplitHostPort(addr); host == unclaimedHost {
					addr = net.JoinHostPort(endpoint, port)
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.URL.String())
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(scheme + "://" + unclaimedHost + "/")
	if err != nil {
		return "", "error: " + err.Error()
	}
	status := resp.Status
	got := checkVulnerable(scheme+"://"+unclaimedHost, resp, []string{"x." + endpoint, endpoint}, redirects)
	if got.platform != "" {
		return got.platform, status
	}
	return "", status + ", no fingerprint matched"
}

// liveDNSHosts lists, for each DNS host subtocheck identifies, one of its nameservers and
// a zone it hosts.
var liveDNSHosts = []struct{ platform, nameserver, zone string }{
	{"Hurricane Electric DNS", "ns1.he.net", "he.net"},
	{"Azure DNS", "ns1-39.azure-dns.com", "microsoft.com"},
	{"DNS Made Easy", "ns0.dnsmadeeasy.com", "dnsmadeeasy.com"},
	{"Reg.ru DNS", "ns1.reg.ru", "reg.ru"},
	{"DreamHost DNS", "ns1.dreamhost.com", "dreamhost.com"},
	{"Google Cloud DNS", "ns-cloud-a1.googledomains.com", "spotify.com"},
}

// unhostedZone is a zone no DNS host serves.
const unhostedZone = "subtocheck-unhosted-7f3k2.com"

func TestLiveDNSHosts(t *testing.T) {
	c := newDelegationChecker(newDNSQueries(), nil)
	for _, h := range liveDNSHosts {
		t.Run(h.platform, func(t *testing.T) {
			if p, ok := nsProvider([]string{h.nameserver}); !ok || p.platform != h.platform {
				t.Errorf("%s is no longer identified as %s", h.nameserver, h.platform)
			}
			if served, _ := c.servingByHost([]string{h.nameserver}, h.zone); len(served) == 0 {
				t.Errorf("%s does not count as serving %s, a zone it hosts", h.nameserver, h.zone)
			}
			if _, notServing := c.servingByHost([]string{h.nameserver}, unhostedZone); len(notServing) == 0 {
				t.Errorf("%s does not count as not serving %s, a zone it does not host", h.nameserver, unhostedZone)
			}
		})
	}
}

// unregisteredName is a label not registered under any TLD checked.
const unregisteredName = "subtocheck-unreg-7f3k2"

func TestLiveRegistries(t *testing.T) {
	r := newRegistrationChecker()
	// .com, .org and .co.uk are answered by RDAP; the rest by WHOIS, as their registries
	// have no RDAP service
	for _, tld := range []string{"com", "org", "co.uk", "io", "co", "de", "ru", "jp", "me"} {
		t.Run(tld, func(t *testing.T) {
			domain := unregisteredName + "." + tld
			if got := r.status(domain); got.status != statusUnregistered {
				t.Errorf("%s is no longer confirmed as unregistered: status %d", domain, got.status)
			}
		})
	}
	t.Run("registered", func(t *testing.T) {
		if got := r.rdap(r.rdapBases()["com"], "example.com"); got.status != statusUndelegated || got.expires.IsZero() {
			t.Errorf("example.com's RDAP record no longer parses: %+v", got)
		}
	})
}
