package subtocheck

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/term"
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

// dialFunc makes a network connection, as net.Dialer.DialContext does.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// environment is what a scan talks to. Scans use defaultEnvironment; tests replace parts of
// it to run a whole scan against local servers.
type environment struct {
	resolvers []string // recursive resolvers, as host:port
	dnsPort   string   // port authoritative nameservers are asked on
	dial      dialFunc // makes HTTP connections; nil to dial normally
	rdapBases func() map[string]string
	whois     func(domain string) (string, bool)
	stdin     io.Reader // the domain list when its path is "-"
	stdout    io.Writer
	terminal  bool // stdout is a terminal
}

func defaultEnvironment() environment {
	return environment{
		resolvers: defaultResolvers,
		dnsPort:   "53",
		rdapBases: defaultRDAPBases(),
		whois:     newWhoisClient().lookup,
		stdin:     os.Stdin,
		stdout:    os.Stdout,
		terminal:  term.IsTerminal(int(os.Stdout.Fd())),
	}
}

// scanner holds what one scan shares between domains: its environment, the DNS responses
// and registrations already looked up, and its log.
type scanner struct {
	env           environment
	queries       *dnsQueries
	delegations   *delegationChecker
	registrations *registrationChecker
	log           *scanLog
}

func newScanner(env environment, log *scanLog) *scanner {
	q := newDNSQueries(env.resolvers, env.dnsPort)
	registrations := newRegistrationChecker(q.resolve, env.rdapBases, env.whois)
	return &scanner{
		env:           env,
		queries:       q,
		delegations:   newDelegationChecker(q, registrations.status),
		registrations: registrations,
		log:           log,
	}
}

// CheckDomains is called from cmd/subtocheck/main.go to scan the domains listed in the
// file at path. Findings are shown as they are found and every issue is written to the log.
// It returns the number of potential takeovers found, including those to verify manually,
// and an error if the domains could not be read or the report could not be emailed.
func CheckDomains(path string, opts Options) (int, error) {
	return scan(path, opts, defaultEnvironment())
}

func scan(path string, opts Options, env environment) (int, error) {
	var conf config
	if opts.ConfigPath != "" {
		conf = readConfig(opts.ConfigPath)
	}
	domains, err := readDomains(path, env.stdin)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	logPath := opts.LogPath
	if logPath == "" {
		logPath = defaultLogPath(start)
	}
	log := newScanLog(logPath, opts.Debug)
	// JSON output replaces the console's, so stdout holds only the JSON
	con := newConsole(env.stdout, env.terminal, opts.Quiet || opts.JSON, len(domains))
	s := newScanner(env, log)

	jobs := make(chan string, len(domains))
	results := make(chan scanResult, len(domains))
	workers := opts.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	for w := 1; w <= workers; w++ {
		go s.worker(w, jobs, results)
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
		if err := writeJSON(env.stdout, newJSONReport(r, pIssues)); err != nil {
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

func (s *scanner) worker(id int, jobs <-chan string, results chan<- scanResult) {
	log := s.log
	for domain := range jobs {
		log.debugf("worker %d: checking %s", id, domain)
		found, cnames := s.checkResolves(domain)
		if len(found) == 0 {
			// a name that resolves can still be delegated to a nameserver on a domain anyone
			// could register; names that fail to resolve are walked by checkResolves. The walk
			// runs alongside the HTTP requests, which take longer.
			var dangling *issue
			walked := make(chan struct{})
			go func() {
				defer close(walked)
				dangling = s.delegations.check(domain, log)
			}()
			responses := checkResponse(domain, cnames, protocols, s.env.dial, log)
			<-walked
			if dangling != nil {
				found = append(found, *dangling)
			}
			found = append(found, responses...)
		}
		results <- scanResult{domain: domain, issues: found}
	}
}

// readDomains reads the domain list, one name per line, from the file at path, or from
// stdin if path is "-". Blank lines are skipped.
func readDomains(path string, stdin io.Reader) ([]string, error) {
	in := stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read domains list")
		}
		defer func() { _ = file.Close() }()
		in = file
	}
	var domains []string
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		if entry := strings.TrimSpace(scanner.Text()); entry != "" {
			domains = append(domains, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to read domains list")
	}
	return domains, nil
}
