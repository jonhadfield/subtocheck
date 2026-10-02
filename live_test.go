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

// unclaimedLabel is a subdomain label no account has claimed. It has only letters and
// digits, as some platforms, such as WordPress.com, reject other site names.
const unclaimedLabel = "subtocheckunclaimed7f3k2"

// liveFingerprints lists each fingerprint confirmed against its provider, with how to see
// the provider's page for a name nobody has configured: either an endpoint, sent a host it
// does not know (as a dangling custom domain would be), or a domain whose unclaimed
// subdomains show the same page.
var liveFingerprints = []struct{ platform, endpoint, subdomainOf string }{
	{platform: "Airee.ru", subdomainOf: "airee.ru"},
	{platform: "Anima", subdomainOf: "animaapp.io"},
	{platform: "Azure Front Door", endpoint: "star-azurefd-prod.trafficmanager.net"},
	{platform: "Bitbucket", subdomainOf: "bitbucket.io"},
	{platform: "Campaign Monitor", endpoint: "cname.createsend.com"},
	{platform: "Canny", endpoint: "cname.canny.io"},
	{platform: "Cargo Collective", endpoint: "cargo.site"},
	{platform: "Framer", subdomainOf: "framer.app"},
	{platform: "Gemfury", subdomainOf: "fury.site"},
	{platform: "GetResponse", endpoint: "getresponsepages.com"},
	{platform: "Ghost", endpoint: "ghost.io"},
	{platform: "GitBook", subdomainOf: "gitbook.io"},
	{platform: "GitHub Pages", endpoint: "github.io"},
	{platform: "HatenaBlog", subdomainOf: "hatenablog.com"},
	{platform: "Help Juice", subdomainOf: "helpjuice.com"},
	{platform: "Help Scout", subdomainOf: "helpscoutdocs.com"},
	{platform: "Heroku", endpoint: "herokuapp.com"},
	{platform: "LaunchRock", subdomainOf: "launchrock.com"},
	{platform: "Leadpages", endpoint: "custom-proxy.leadpages.net"},
	{platform: "Ngrok", subdomainOf: "ngrok.io"},
	{platform: "Pantheon", endpoint: "23.185.0.1"},
	{platform: "Pingdom", endpoint: "stats.pingdom.com"},
	{platform: "S3", endpoint: "s3.amazonaws.com"},
	{platform: "Short.io", endpoint: "cname.short.io"},
	{platform: "SmartJobBoard", endpoint: "52.16.160.97"},
	{platform: "Surge.sh", endpoint: "na-west1.surge.sh"},
	{platform: "Tilda", endpoint: "tilda.ws"},
	{platform: "Tumblr", endpoint: "domains.tumblr.com"},
	{platform: "Uberflip", endpoint: "read.uberflip.com"},
	{platform: "UserVoice", subdomainOf: "uservoice.com"},
	{platform: "Wasabi", endpoint: "s3.wasabisys.com"},
	{platform: "WordPress.com", subdomainOf: "wordpress.com"},
	{platform: "Wufoo", subdomainOf: "wufoo.com"},
}

func TestLiveFingerprints(t *testing.T) {
	for _, f := range liveFingerprints {
		t.Run(f.platform, func(t *testing.T) {
			t.Parallel()
			var results []string
			blocked := true
			for _, scheme := range []string{"https", "http"} {
				var platform, summary string
				var status int
				if f.subdomainOf != "" {
					platform, status, summary = probeSubdomain(scheme, f.subdomainOf)
				} else {
					platform, status, summary = probe(scheme, f.endpoint)
				}
				if platform == f.platform {
					return
				}
				blocked = blocked && blockingStatus(status)
				results = append(results, scheme+": "+summary)
			}
			details := strings.Join(results, "\n  ")
			if blocked {
				// some providers refuse requests from hosting networks, such as CI runners
				t.Skipf("%s refused the request, so its fingerprint could not be checked from this network:\n  %s", f.platform, details)
			}
			t.Errorf("%s no longer matches its fingerprint via %s%s:\n  %s", f.platform, f.endpoint, f.subdomainOf, details)
		})
	}
}

// blockingStatus reports whether an HTTP status means the request was refused, rather than
// answered with the provider's page. Anti-bot protection replies with various errors (403
// from Tumblr and 456 from Tilda for CI runners), while providers' pages for unknown hosts
// use 200, 404, 410 or, for Azure Front Door, 400. A page that changes but keeps one of
// those statuses still fails the check.
func blockingStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusGone:
		return false
	}
	return status >= http.StatusBadRequest
}

// probe requests unclaimedHost from endpoint and returns the platform it matches, if any,
// the HTTP status, and a summary of the response for diagnosing a mismatch.
func probe(scheme, endpoint string) (string, int, string) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: unclaimedHost},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// send the unclaimed host to the endpoint; redirects elsewhere resolve normally
			if host, port, _ := net.SplitHostPort(addr); host == unclaimedHost {
				addr = net.JoinHostPort(endpoint, port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return request(transport, scheme+"://"+unclaimedHost+"/", []string{"x." + endpoint, endpoint})
}

// probeSubdomain requests an unclaimed subdomain of domain, resolved normally.
func probeSubdomain(scheme, domain string) (string, int, string) {
	host := unclaimedLabel + "." + domain
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return request(transport, scheme+"://"+host+"/", []string{host})
}

func request(transport *http.Transport, url string, cnames []string) (string, int, string) {
	var redirects []string
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.URL.String())
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, "error: " + err.Error()
	}
	got := checkVulnerable(url, resp, cnames, redirects)
	if got.platform != "" {
		return got.platform, resp.StatusCode, resp.Status
	}
	return "", resp.StatusCode, resp.Status + ", no fingerprint matched"
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
