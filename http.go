package subtocheck

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	httpPrefix  = "http://"
	httpsPrefix = "https://"
	protocols   = []string{"http", "https"}
)

func checkResponse(fqdn string, cnames []string, protocols []string, log *scanLog) (issues issues) {
	var clientTransportTimeoutSecs = 3
	var responseHeaderTimeoutSecs = 2

	tr := &http.Transport{
		ResponseHeaderTimeout: time.Duration(responseHeaderTimeoutSecs) * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		// each host is requested once, so idle connections would only be left open
		DisableKeepAlives: true,
	}
	// request each protocol at once, so a host that does not respond costs one timeout
	// rather than one per protocol; results are kept in protocol order
	results := make([][]issue, len(protocols))
	var wg sync.WaitGroup
	for i, protocol := range protocols {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = checkProtocol(fqdn, protocol, cnames, tr, clientTransportTimeoutSecs, responseHeaderTimeoutSecs, log)
		}()
	}
	wg.Wait()
	for _, r := range results {
		issues = append(issues, r...)
	}
	return
}

func checkProtocol(fqdn, protocol string, cnames []string, tr *http.Transport, clientTimeoutSecs, headerTimeoutSecs int, log *scanLog) (issues issues) {
	// record redirect locations, as some providers only identify themselves in those
	var redirects []string
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(clientTimeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			redirects = append(redirects, req.URL.String())
			return nil
		},
	}
	var httpURL string
	switch protocol {
	case "http":
		httpURL = httpPrefix + fqdn
	case "https":
		httpURL = httpsPrefix + fqdn
	}
	log.debugf("requesting %q with client timeout %ds and response header timeout %ds",
		httpURL, clientTimeoutSecs, headerTimeoutSecs)
	httpResp, err := client.Get(httpURL)
	if err != nil {
		return []issue{{kind: "request", fqdn: fqdn, url: httpURL, err: err}}
	}
	vulnIssue := checkVulnerable(httpURL, httpResp, cnames, redirects)
	if vulnIssue.kind != "" {
		vulnIssue.fqdn = fqdn
		issues = append(issues, vulnIssue)
	}
	return
}

// maxBodyBytes limits how much of a response is read for fingerprinting
const maxBodyBytes = 1 << 20

func checkVulnerable(url string, response *http.Response, cnames []string, redirects []string) (vuln issue) {
	// read the body once: every pattern is checked against the same content
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	_ = response.Body.Close()
	bodyText := string(body)
	headerText := headersToLower(response.Header)

	for _, pattern := range vPatterns {
		if matchesPattern(pattern, response.StatusCode, bodyText, headerText, cnames, redirects) {
			msg := "matches pattern for platform: " + pattern.platform
			var detail string
			if pattern.edgeCase {
				detail = "takeover depends on provider conditions, verify manually"
				msg += " (edge case: " + detail + ")"
			}
			return issue{
				url:      url,
				kind:     "vuln",
				platform: pattern.platform,
				err:      errors.New(msg),
				detail:   detail,
				edgeCase: pattern.edgeCase,
			}
		}
	}
	return
}

func matchesPattern(pattern vPattern, statusCode int, body, headers string, cnames, redirects []string) bool {
	if len(pattern.cnames) > 0 && !anyHasSuffix(cnames, pattern.cnames) {
		return false
	}
	if len(pattern.responseCodes) > 0 && !contains(pattern.responseCodes, statusCode) {
		return false
	}
	if len(pattern.redirectStrings) > 0 && !anyContains(redirects, pattern.redirectStrings) {
		return false
	}
	for _, s := range pattern.headerStrings {
		if !strings.Contains(headers, strings.ToLower(s)) {
			return false
		}
	}
	for _, s := range pattern.notHeaderStrings {
		if strings.Contains(headers, strings.ToLower(s)) {
			return false
		}
	}
	for _, s := range pattern.notBodyStrings {
		if strings.Contains(body, s) {
			return false
		}
	}
	if len(pattern.bodyStrings) > 0 && !checkBodyResponse(pattern, body) {
		return false
	}
	// a pattern must match on something beyond DNS and status alone
	return len(pattern.bodyStrings) > 0 || len(pattern.redirectStrings) > 0 || len(pattern.headerStrings) > 0
}

func checkBodyResponse(pattern vPattern, bodyText string) bool {
	for _, bodyString := range pattern.bodyStrings {
		found := strings.Contains(bodyText, bodyString)
		if found && pattern.bodyStringMatch != "all" {
			return true
		}
		if !found && pattern.bodyStringMatch == "all" {
			return false
		}
	}
	return pattern.bodyStringMatch == "all"
}

// headersToLower renders headers as lower case "name: value" lines for substring matching.
func headersToLower(header http.Header) string {
	var b strings.Builder
	for name, values := range header {
		for _, value := range values {
			b.WriteString(strings.ToLower(name + ": " + value + "\n"))
		}
	}
	return b.String()
}

func anyHasSuffix(hosts []string, domains []string) bool {
	for _, host := range hosts {
		if hasSuffix(host, domains) {
			return true
		}
	}
	return false
}

func anyContains(values []string, substrings []string) bool {
	for _, value := range values {
		for _, sub := range substrings {
			if strings.Contains(value, sub) {
				return true
			}
		}
	}
	return false
}
