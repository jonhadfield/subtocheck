package subtocheck

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// fakeInternet is DNS, web servers and a registry for a whole scan to run against. One DNS
// server plays every role: recursive resolver for queries that ask for recursion, and every
// zone's authoritative nameserver for those that do not.
type fakeInternet struct {
	a     map[string]string // A records
	cname map[string]string // CNAME records
	// delegated maps a zone to the nameservers it is delegated to, which refuse to serve it
	delegated map[string][]string
	// zones answer NS queries through the resolver, as the TLD and registered domains do
	zones map[string]bool
}

func (f fakeInternet) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	q := req.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if req.RecursionDesired {
		f.resolve(m, name, q.Qtype)
	} else {
		f.authoritative(m, name, q.Qtype)
	}
	_ = w.WriteMsg(m)
}

func (f fakeInternet) delegatedZone(name string) (string, bool) {
	for zone := range f.delegated {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return zone, true
		}
	}
	return "", false
}

// resolve answers as a recursive resolver would.
func (f fakeInternet) resolve(m *dns.Msg, name string, qtype uint16) {
	if _, ok := f.delegatedZone(name); ok {
		// resolvers cannot get an answer from nameservers that refuse the zone
		m.Rcode = dns.RcodeServerFailure
		return
	}
	if qtype == dns.TypeNS {
		if f.zones[name] {
			m.Answer = []dns.RR{&dns.NS{Hdr: header(name, dns.TypeNS), Ns: "ns.fake.test."}}
		} else {
			m.Rcode = dns.RcodeNameError
		}
		return
	}
	for current := name; ; {
		if ip, ok := f.a[current]; ok {
			m.Answer = append(m.Answer, &dns.A{Hdr: header(current, dns.TypeA), A: net.ParseIP(ip)})
			return
		}
		target, ok := f.cname[current]
		if !ok {
			m.Rcode = dns.RcodeNameError
			return
		}
		m.Answer = append(m.Answer, &dns.CNAME{Hdr: header(current, dns.TypeCNAME), Target: dns.Fqdn(target)})
		current = target
	}
}

// authoritative answers as a zone's own nameservers would.
func (f fakeInternet) authoritative(m *dns.Msg, name string, qtype uint16) {
	zone, delegated := f.delegatedZone(name)
	switch {
	case delegated && qtype == dns.TypeNS && name == zone:
		// a referral from the parent zone
		for _, ns := range f.delegated[zone] {
			m.Ns = append(m.Ns, &dns.NS{Hdr: header(zone, dns.TypeNS), Ns: dns.Fqdn(ns)})
		}
	case delegated:
		m.Rcode = dns.RcodeRefused
	default:
		// the name is within a zone these nameservers serve, with nothing delegated
		m.Authoritative = true
	}
}

func header(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: rrtype, Class: dns.ClassINET, Ttl: 60}
}

// startDNS serves f on a local port over UDP and TCP and returns the port.
func startDNS(t *testing.T, f fakeInternet) string {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port)
	tcp, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Skipf("could not listen on tcp port %s: %v", port, err)
	}
	var started sync.WaitGroup
	started.Add(2)
	udpServer := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(f.handle), NotifyStartedFunc: started.Done}
	tcpServer := &dns.Server{Listener: tcp, Handler: dns.HandlerFunc(f.handle), NotifyStartedFunc: started.Done}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() })
	started.Wait()
	return port
}

// webPages serves each host's page, over http and https.
func webPages(t *testing.T, pages map[string]func(http.ResponseWriter)) dialFunc {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if page, ok := pages[host]; ok {
			page(w)
			return
		}
		_, _ = w.Write([]byte("<html><body>Welcome</body></html>"))
	})
	plain := httptest.NewServer(handler)
	secure := httptest.NewTLSServer(handler)
	t.Cleanup(plain.Close)
	t.Cleanup(secure.Close)
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		target := plain.Listener.Addr().String()
		if strings.HasSuffix(address, ":443") {
			target = secure.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, target)
	}
}

// testEnvironment returns an environment that resolves through f, serves pages, and has an
// RDAP registry for .test that knows no domains.
func testEnvironment(t *testing.T, f fakeInternet, pages map[string]func(http.ResponseWriter), stdout *bytes.Buffer) environment {
	t.Helper()
	port := startDNS(t, f)
	registry := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(registry.Close)
	return environment{
		resolvers: []string{"127.0.0.1:" + port},
		dnsPort:   port,
		dial:      webPages(t, pages),
		rdapBases: func() map[string]string { return map[string]string{"test": registry.URL + "/"} },
		whois:     func(string) (string, bool) { return "", false },
		stdout:    stdout,
	}
}

func writeDomains(t *testing.T, domains ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte(strings.Join(domains, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// scanInternet has one domain for each kind of finding, one healthy and one missing.
var scanInternet = fakeInternet{
	a: map[string]string{
		"ok.example.test":      "127.0.0.1",
		"s3.example.test":      "127.0.0.1",
		"ns.fake.test":         "127.0.0.1",
		"ns1.digitalocean.com": "127.0.0.1",
	},
	cname: map[string]string{
		"azure.example.test": "old-app.azurewebsites.net",
		"cdn.example.test":   "cdn.gone-vendor.test",
	},
	delegated: map[string][]string{"sub.example.test": {"ns1.digitalocean.com"}},
	zones:     map[string]bool{"test": true, "example.test": true},
}

var scanPages = map[string]func(http.ResponseWriter){
	"s3.example.test": func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>s3.example.test</BucketName></Error>"))
	},
}

func TestScanFindsEachKindOfTakeover(t *testing.T) {
	var stdout bytes.Buffer
	env := testEnvironment(t, scanInternet, scanPages, &stdout)
	path := writeDomains(t, "ok.example.test", "s3.example.test", "azure.example.test", "cdn.example.test", "app.sub.example.test", "missing.example.test")
	logPath := filepath.Join(t.TempDir(), "scan.log")

	findings, err := scan(path, Options{LogPath: logPath, JSON: true}, env)
	if err != nil {
		t.Fatal(err)
	}
	if findings != 4 {
		t.Errorf("expected 4 findings, got %d", findings)
	}

	var got struct {
		Domains  int `json:"domains"`
		Findings []struct {
			Host     string   `json:"host"`
			Platform string   `json:"platform"`
			Kind     string   `json:"kind"`
			URLs     []string `json:"urls"`
		} `json:"findings"`
		DNSIssues []struct {
			Target string `json:"target"`
		} `json:"dns_issues"`
		RequestErrors []any  `json:"request_errors"`
		Log           string `json:"log"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	var found []string
	for _, f := range got.Findings {
		found = append(found, f.Host+" "+f.Platform+" "+f.Kind)
	}
	sort.Strings(found)
	want := []string{
		"app.sub.example.test DigitalOcean DNS takeover",
		"azure.example.test Azure takeover",
		"cdn.example.test Unregistered domain takeover",
		"s3.example.test S3 takeover",
	}
	if strings.Join(found, "\n") != strings.Join(want, "\n") {
		t.Errorf("unexpected findings:\n got %v\nwant %v", found, want)
	}
	for _, f := range got.Findings {
		if f.Host == "s3.example.test" && len(f.URLs) != 2 {
			t.Errorf("expected the S3 finding over http and https, got %v", f.URLs)
		}
	}
	if got.Domains != 6 || len(got.DNSIssues) != 1 || got.DNSIssues[0].Target != "missing.example.test" || len(got.RequestErrors) != 0 {
		t.Errorf("unexpected counts or issues: %+v", got)
	}
	if got.Log != logPath {
		t.Errorf("expected log %s, got %s", logPath, got.Log)
	}

	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FINDING https://s3.example.test", "FINDING azure.example.test", "DNS     missing.example.test could not be resolved"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log missing %q:\n%s", want, log)
		}
	}
}

func TestScanConsoleOutput(t *testing.T) {
	var stdout bytes.Buffer
	env := testEnvironment(t, scanInternet, scanPages, &stdout)
	path := writeDomains(t, "ok.example.test", "s3.example.test", "missing.example.test")

	findings, err := scan(path, Options{LogPath: filepath.Join(t.TempDir(), "scan.log")}, env)
	if err != nil || findings != 1 {
		t.Fatalf("expected 1 finding, got %d (%v)", findings, err)
	}
	out := stdout.String()
	for _, want := range []string{"TAKEOVER  s3.example.test  S3", "Scanned 3 domains", "1 potential takeover", "1 DNS issue", "Details: "} {
		if !strings.Contains(out, want) {
			t.Errorf("console output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("expected no escape codes when stdout is not a terminal:\n%q", out)
	}
}

func TestScanOfHealthyDomainsFindsNothing(t *testing.T) {
	var stdout bytes.Buffer
	env := testEnvironment(t, scanInternet, scanPages, &stdout)
	logPath := filepath.Join(t.TempDir(), "scan.log")

	findings, err := scan(writeDomains(t, "ok.example.test"), Options{LogPath: logPath, JSON: true}, env)
	if err != nil || findings != 0 {
		t.Fatalf("expected no findings, got %d (%v)", findings, err)
	}
	if !strings.Contains(stdout.String(), `"findings": []`) {
		t.Errorf("expected no findings in the JSON:\n%s", stdout.String())
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("expected no log for a scan with nothing to record, got %v", err)
	}
}

func TestScanReadsDomainsFromStdin(t *testing.T) {
	var stdout bytes.Buffer
	env := testEnvironment(t, scanInternet, scanPages, &stdout)
	env.stdin = strings.NewReader("ok.example.test\n\n  s3.example.test  \n")

	findings, err := scan("-", Options{LogPath: filepath.Join(t.TempDir(), "scan.log"), JSON: true}, env)
	if err != nil || findings != 1 {
		t.Fatalf("expected 1 finding from the domains on stdin, got %d (%v)", findings, err)
	}
	if !strings.Contains(stdout.String(), `"domains": 2`) || !strings.Contains(stdout.String(), `"host": "s3.example.test"`) {
		t.Errorf("expected both domains from stdin to be scanned:\n%s", stdout.String())
	}
}

func TestScanWithMissingDomainsFile(t *testing.T) {
	var stdout bytes.Buffer
	env := testEnvironment(t, scanInternet, scanPages, &stdout)
	if _, err := scan(filepath.Join(t.TempDir(), "missing.txt"), Options{}, env); err == nil || !strings.Contains(err.Error(), "failed to read domains list") {
		t.Errorf("expected an error reading a missing domains file, got %v", err)
	}
}
