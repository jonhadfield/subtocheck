package subtocheck

import (
	"bufio"
	"crypto/tls"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var (
	httpPrefix   = "http://"
	httpsPrefix  = "https://"
	protocols    = []string{"http", "https"}
	resolveMutex sync.Mutex
	nameservers  = []string{
		"8.8.8.8",         // google
		"8.8.4.4",         // google
		"209.244.0.3",     // level3
		"209.244.0.4",     // level3
		"1.1.1.1",         // cloudflare
		"1.0.0.1",         // cloudflare
		"9.9.9.9",         // quad9
		"149.112.112.112", // quad9
	}
)

type issue struct {
	kind     string // vuln, request, dns
	platform string
	fqdn     string
	url      string
	err      error
	detail   string // for findings, extra context shown after the platform
	edgeCase bool   // for findings, takeover depends on provider conditions
}

type issues []issue

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
	resolveMutex.Lock()
	ns := rand.IntN(len(nameservers))
	log.debugf("resolving %q with nameserver %s", fqdn, nameservers[ns])
	record, _, err = c.Exchange(m, net.JoinHostPort(nameservers[ns], strconv.Itoa(53)))
	resolveMutex.Unlock()
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
		if dangling := newDelegationChecker(log).check(fqdn); dangling != nil {
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
func danglingCNAMEIssue(fqdn, target string, registration registrationLookup) issue {
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
	finding := func(platform, detail string, edgeCase bool) issue {
		return issue{
			kind:     "vuln",
			platform: platform,
			fqdn:     fqdn,
			url:      fqdn,
			err:      errors.Errorf("CNAME to %s: %s", target, detail),
			detail:   "CNAME to " + target + "; " + detail,
			edgeCase: edgeCase,
		}
	}
	switch registration(domain) {
	case statusUnregistered:
		return finding("Unregistered domain", domain+" is not registered, so may be available to register", false)
	case statusUnconfirmed:
		return finding("Unregistered domain", domain+" has no DNS and its registry has no RDAP service to confirm whether it is registered", true)
	case statusUndelegated:
		return finding("Undelegated domain", domain+" is registered but has no nameservers, so its registration may have expired", true)
	default:
		return notExist
	}
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

func checkResponse(fqdn string, cnames []string, protocols []string, log *scanLog) (issues issues) {
	var clientTransportTimeoutSecs = 3
	var responseHeaderTimeoutSecs = 2

	tr := &http.Transport{
		ResponseHeaderTimeout: time.Duration(responseHeaderTimeoutSecs) * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	for _, protocol := range protocols {
		// record redirect locations, as some providers only identify themselves in those
		var redirects []string
		client := &http.Client{
			Transport: tr,
			Timeout:   time.Duration(clientTransportTimeoutSecs) * time.Second,
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
		var httpResp *http.Response
		var err error
		log.debugf("requesting %q with client timeout %ds and response header timeout %ds",
			httpURL, clientTransportTimeoutSecs, responseHeaderTimeoutSecs)
		httpResp, err = client.Get(httpURL)
		if err != nil {
			issues = append(issues, issue{kind: "request", fqdn: fqdn, url: httpURL, err: err})
			continue
		}

		vulnIssue := checkVulnerable(httpURL, httpResp, cnames, redirects)
		if vulnIssue.kind != "" {
			vulnIssue.fqdn = fqdn
			issues = append(issues, vulnIssue)
		}
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

// scanResult is the outcome of checking one domain.
type scanResult struct {
	domain string
	issues issues
}

// CheckDomains is called from cmd/subtocheck/main.go to kick off the scans. Findings are
// shown as they are found and every issue is written to the log at logPath, or a
// timestamped file in the working directory if it is empty. It returns an error if the
// report could not be emailed.
func CheckDomains(path string, configPath *string, debug *bool, quiet *bool, logPath string) error {
	var conf config
	if *configPath != "" {
		conf = readConfig(*configPath)
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "failed to read domains list")
	}
	var domains []string
	domainScanner := bufio.NewScanner(file)
	for domainScanner.Scan() {
		if entry := strings.TrimSpace(domainScanner.Text()); entry != "" {
			domains = append(domains, entry)
		}
	}
	_ = file.Close()

	start := time.Now()
	if logPath == "" {
		logPath = defaultLogPath(start)
	}
	log := newScanLog(logPath, *debug)
	con := newConsole(*quiet, len(domains))

	jobs := make(chan string, len(domains))
	results := make(chan scanResult, len(domains))
	for w := 1; w <= 10; w++ {
		go worker(w, jobs, results, log)
	}
	for _, domain := range domains {
		jobs <- domain
	}
	close(jobs)

	// a nil channel never fires, so the spinner only animates on a terminal
	var ticks <-chan time.Time
	if con.interactive {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		ticks = ticker.C
	}
	con.drawBar()
	var all issues
	for received := 0; received < len(domains); {
		select {
		case r := <-results:
			received++
			for _, i := range r.issues {
				log.issue(i)
				if i.kind == "vuln" {
					con.finding(i)
				}
			}
			all = append(all, r.issues...)
			con.progress(r.domain)
		case <-ticks:
			con.tick()
		}
	}

	pIssues := getIssuesSummary(all)
	var summaryLogPath string
	if log.written() {
		summaryLogPath = logPath
	}
	logErr := log.Close()
	con.summary(pIssues, time.Since(start), summaryLogPath, logErr)

	// send notifications
	if len(all) == 0 {
		return nil
	}
	if conf.Email.SkipNoVulns && len(pIssues.potVulns) == 0 {
		return nil
	}
	if conf.Email.Provider != "" {
		return emailResults(conf.Email, pIssues)
	}
	return nil
}

func worker(id int, jobs <-chan string, results chan<- scanResult, log *scanLog) {
	for domain := range jobs {
		log.debugf("worker %d: checking %s", id, domain)
		found, cnames := checkResolves(domain, log)
		if len(found) == 0 {
			found = checkResponse(domain, cnames, protocols, log)
		}
		results <- scanResult{domain: domain, issues: found}
	}
}
