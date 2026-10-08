package subtocheck

import (
	"bufio"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// scanResult is the outcome of checking one domain.
type scanResult struct {
	domain string
	issues issues
}

// DefaultWorkers is the number of domains checked at once unless Options says otherwise.
// More are faster, but busier hosts time out more often, and a request that times out is
// a check that was not made.
const DefaultWorkers = 10

// Options configures a scan.
type Options struct {
	ConfigPath string // email configuration, if any
	LogPath    string // log file; a timestamped file in the working directory if empty
	Debug      bool   // write debug messages to the log
	Quiet      bool   // no console output
	JSON       bool   // write the result to stdout as JSON instead of console output
	Workers    int    // domains checked at once; DefaultWorkers if not positive
}

// CheckDomains is called from cmd/subtocheck/main.go to scan the domains listed in the
// file at path. Findings are shown as they are found and every issue is written to the log.
// It returns the number of potential takeovers found, including those to verify manually,
// and an error if the domains could not be read or the report could not be emailed.
func CheckDomains(path string, opts Options) (int, error) {
	var conf config
	if opts.ConfigPath != "" {
		conf = readConfig(opts.ConfigPath)
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrap(err, "failed to read domains list")
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
	logPath := opts.LogPath
	if logPath == "" {
		logPath = defaultLogPath(start)
	}
	log := newScanLog(logPath, opts.Debug)
	// JSON output replaces the console's, so stdout holds only the JSON
	con := newConsole(opts.Quiet || opts.JSON, len(domains))

	jobs := make(chan string, len(domains))
	results := make(chan scanResult, len(domains))
	workers := opts.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	for w := 1; w <= workers; w++ {
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
	elapsed := time.Since(start)
	con.summary(pIssues, elapsed, summaryLogPath, logErr)
	r := newReport(pIssues, len(domains), elapsed, summaryLogPath)
	if opts.JSON {
		if err := writeJSON(os.Stdout, newJSONReport(r, pIssues)); err != nil {
			return 0, errors.Wrap(err, "failed to write JSON")
		}
	}
	takeovers, verify := countFindings(pIssues.potVulns)
	findings := takeovers + verify

	// send notifications
	if len(all) == 0 {
		return findings, nil
	}
	if conf.Email.SkipNoVulns && len(pIssues.potVulns) == 0 {
		return findings, nil
	}
	if conf.Email.Provider != "" {
		return findings, emailResults(conf.Email, r)
	}
	return findings, nil
}

func worker(id int, jobs <-chan string, results chan<- scanResult, log *scanLog) {
	for domain := range jobs {
		log.debugf("worker %d: checking %s", id, domain)
		found, cnames := checkResolves(domain, log)
		if len(found) == 0 {
			// a name that resolves can still be delegated to a nameserver on a domain anyone
			// could register; names that fail to resolve are walked by checkResolves. The walk
			// runs alongside the HTTP requests, which take longer.
			var dangling *issue
			walked := make(chan struct{})
			go func() {
				defer close(walked)
				dangling = delegations.check(domain, log)
			}()
			responses := checkResponse(domain, cnames, protocols, log)
			<-walked
			if dangling != nil {
				found = append(found, *dangling)
			}
			found = append(found, responses...)
		}
		results <- scanResult{domain: domain, issues: found}
	}
}
