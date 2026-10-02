package subtocheck

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// whoisClient queries registries' WHOIS servers, for the top-level domains whose
// registries have no RDAP service. Each TLD's server is found through IANA's WHOIS server
// and cached for the scan.
type whoisClient struct {
	query func(server, q string) (string, error)

	mu      sync.Mutex
	servers map[string]string // WHOIS server by TLD; empty if it has none
}

func newWhoisClient() *whoisClient {
	return &whoisClient{query: queryWhois, servers: map[string]string{}}
}

// lookup returns the registry's WHOIS reply for domain, and false if there is no WHOIS
// server for its TLD or the query failed.
func (w *whoisClient) lookup(domain string) (string, bool) {
	tld := domain[strings.LastIndex(domain, ".")+1:]
	server := w.server(tld)
	if server == "" {
		return "", false
	}
	q := domain
	if server == "whois.jprs.jp" {
		// JPRS replies in Japanese unless asked for English
		q += "/e"
	}
	reply, err := w.query(server, q)
	if err != nil {
		return "", false
	}
	return reply, true
}

var whoisReferral = regexp.MustCompile(`(?mi)^(?:whois|refer):\s*(\S+)`)

func (w *whoisClient) server(tld string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if server, ok := w.servers[tld]; ok {
		return server
	}
	var server string
	if reply, err := w.query("whois.iana.org", tld); err == nil {
		if m := whoisReferral.FindStringSubmatch(reply); m != nil {
			server = strings.ToLower(m[1])
		}
	}
	w.servers[tld] = server
	return server
}

// queryWhois sends a WHOIS query (RFC 3912) and returns the reply.
func queryWhois(server, q string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), 10*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, q+"\r\n"); err != nil {
		return "", err
	}
	reply, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	return string(reply), err
}

// whoisNotFound are registries' replies for a domain that is not registered, in lower
// case. Each was checked against its registry in October 2026: .io and .me ("domain not
// found."), .co ("domain not found"), .de ("status: free"), .ru ("no entries found") and
// .jp ("no match!!").
var whoisNotFound = []string{"domain not found", "status: free", "no entries found", "no match!!"}

var (
	whoisStatus = regexp.MustCompile(`(?mi)^\s*(?:domain )?status:\s*([a-z]+)`)
	whoisExpiry = regexp.MustCompile(`(?mi)^\s*(?:registry expiry date|registrar registration expiration date|expiry date|expiration date|expires on|paid-till|\[expires on\])\s*:?\s*(\d{4}[-/]\d{2}[-/]\d{2}(?:T[0-9:.]+Z?)?)`)
	camelCase   = regexp.MustCompile(`([a-z])([A-Z])`)
)

// parseWhois interprets a registry's WHOIS reply for domain. A reply that neither says the
// domain is not found nor contains a record for it, such as a rate limit message, leaves
// the registration unconfirmed.
func parseWhois(domain, reply string) registration {
	lower := strings.ToLower(reply)
	for _, notFound := range whoisNotFound {
		if strings.Contains(lower, notFound) {
			return registration{status: statusUnregistered}
		}
	}
	if !hasWhoisRecord(domain, reply) {
		return registration{status: statusUnconfirmed}
	}
	found := registration{status: statusUndelegated}
	for _, m := range whoisStatus.FindAllStringSubmatch(reply, -1) {
		// EPP statuses are camel case, such as redemptionPeriod; RDAP's form is
		// "redemption period"
		state := strings.ToLower(camelCase.ReplaceAllString(m[1], "$1 $2"))
		if state != "" && !found.has(state) {
			found.states = append(found.states, state)
		}
	}
	if m := whoisExpiry.FindStringSubmatch(reply); m != nil {
		date := strings.ReplaceAll(m[1], "/", "-")
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
			if t, err := time.Parse(layout, date); err == nil {
				found.expires = t
				break
			}
		}
	}
	return found
}

// hasWhoisRecord reports whether a WHOIS reply contains a record for domain: a line naming
// the domain alongside a domain field, as in "Domain Name: EXAMPLE.CO" or
// "[Domain Name]  EXAMPLE.JP".
func hasWhoisRecord(domain, reply string) bool {
	scanner := bufio.NewScanner(strings.NewReader(reply))
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.Contains(line, "domain") && strings.Contains(line, strings.ToLower(domain)) {
			return true
		}
	}
	return false
}
