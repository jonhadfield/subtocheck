package subtocheck

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"reflect"

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
}

type issues []issue

// checkResolves resolves the fqdn and returns any DNS issues along with the CNAME
// targets followed, so later checks can tell which provider serves the name.
func checkResolves(fqdn string, debug *bool) (issues issues, cnames []string) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = true
	c.Timeout = 1500 * time.Millisecond
	var record *dns.Msg
	var err error
	resolveMutex.Lock()
	ns := rand.IntN(len(nameservers))
	if *debug {
		fmt.Printf("DEBUG: resolving \"%s\" with nameserver %s\n", fqdn, nameservers[ns])
	}
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
		issues = append(issues, danglingCNAMEIssue(fqdn, cnames[len(cnames)-1]))
		err = issues[len(issues)-1].err
	} else if len(record.Answer) == 0 {
		err = errors.Errorf("%s could not be resolved (no answer from %s)", fqdn, nameservers[ns])
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	} else if record.Rcode != 0 {
		err = errors.Errorf("%s could not be resolved (%s from %s)", fqdn, dns.RcodeToString[record.Rcode],
			nameservers[ns])
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	}
	if *debug && err != nil {
		fmt.Printf("DEBUG: error: %v\n", err)
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

// danglingCNAMEIssue reports a CNAME whose target does not exist. If the target belongs to
// a provider where deleted names can be registered again, it is a potential vulnerability.
func danglingCNAMEIssue(fqdn, target string) issue {
	for _, pattern := range cnamePatterns {
		if hasSuffix(target, pattern.suffixes) {
			return issue{
				kind:     "vuln",
				platform: pattern.platform,
				fqdn:     fqdn,
				url:      fqdn,
				err:      errors.Errorf("CNAME to %s, which does not exist, matches platform: %s", target, pattern.platform),
			}
		}
	}
	return issue{
		kind: "dns",
		fqdn: fqdn,
		err:  errors.Errorf("%s is a dangling CNAME: target %s does not exist", fqdn, target),
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

func checkResponse(fqdn string, cnames []string, protocols []string, debug *bool) (issues issues) {
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
		if *debug {
			fmt.Printf("DEBUG: requesting URL \"%s\" with client transport timeout: %d secs and resp. header"+
				" timeout: %d secs\n", httpURL, clientTransportTimeoutSecs, responseHeaderTimeoutSecs)
		}
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
			if pattern.edgeCase {
				msg += " (edge case: takeover depends on provider conditions, verify manually)"
			}
			return issue{
				url:      url,
				kind:     "vuln",
				platform: pattern.platform,
				err:      errors.New(msg),
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

var (
	domainIssues      issues
	domainIssuesMutex sync.Mutex
)

func addIssues(i issues) {
	domainIssuesMutex.Lock()
	defer domainIssuesMutex.Unlock()
	domainIssues = append(domainIssues, i...)
}

// CheckDomains is called from cmd/subtocheck/main.go to kick off the scans
func CheckDomains(path string, configPath *string, debug *bool, quiet *bool) {
	var conf config
	if *configPath != "" {
		conf = readConfig(*configPath)
	}
	file, _ := os.Open(path)
	domainScanner := bufio.NewScanner(file)
	var domains []string
	for domainScanner.Scan() {
		entry := domainScanner.Text()
		if entry != "" {
			domains = append(domains, entry)
		}
	}
	jobs := make(chan string, len(domains))
	results := make(chan bool, len(domains))

	for w := 1; w <= 10; w++ {
		go worker(w, jobs, results, debug)
	}
	numDomains := len(domains)
	for j := 0; j < numDomains; j++ {
		jobs <- domains[j]
	}
	close(jobs)

	var progress string
	for a := 1; a <= numDomains; a++ {
		if !*quiet {
			progress = fmt.Sprintf("Processing... %d/%d %s", a, numDomains, domains[a-1])
			progress = padToWidth(progress, true)
			width := terminalWidth()
			if len(progress) == width {
				fmt.Print(progress[0:width-3] + "   \r")
			} else {
				fmt.Print(progress)
			}
		}

		<-results
	}
	pIssues := getIssuesSummary(domainIssues)
	var noIssuesFound, noVulnsFound bool

	if !*quiet {
		fmt.Printf("%s", padToWidth(" ", false))
		if !reflect.DeepEqual(pIssues, processedIssues{}) {
			displayIssues(pIssues)
			if len(pIssues.potVulns) == 0 {
				noVulnsFound = true
			}
		} else {
			noIssuesFound = true
			fmt.Println("\nno issues found.")
		}
	}
	// send notifications
	if noIssuesFound {
		if *debug {
			fmt.Println("\nDEBUG: no issues found. skipping email.")
		}
		return
	}
	if conf.Email.SkipNoVulns && noVulnsFound {
		if *debug {
			fmt.Println("\nDEBUG: no vulnerabilities found. skipping email.")
		}
		return
	}
	if conf.Email.Provider != "" {
		if *debug {
			fmt.Println("\nDEBUG: sending email")
		}
		emailErr := emailResults(conf.Email, pIssues)
		if emailErr != nil {
			fmt.Println("failed to send email")
			fmt.Println("-- error --")
			fmt.Printf("%+v\n", emailErr)
		}
	}
}

func worker(id int, jobs <-chan string, results chan<- bool, debug *bool) {
	for j := range jobs {
		if *debug {
			fmt.Printf("DEBUG: worker: %d\n", id)
		}
		resolveIssues, cnames := checkResolves(j, debug)
		if len(resolveIssues) > 0 {
			addIssues(resolveIssues)
		} else {
			addIssues(checkResponse(j, cnames, protocols, debug))
		}
		results <- true
	}
}
