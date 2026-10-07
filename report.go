package subtocheck

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// report is what a scan found, for the email report.
type report struct {
	Domains       int
	Duration      time.Duration
	Findings      []reportFinding
	Takeovers     int
	Verify        int
	DNSIssues     int
	RequestErrors int
	// LogPath is the log with every issue in detail, or empty if none was written.
	LogPath string
}

// reportFinding is a potential takeover of one host on one platform.
type reportFinding struct {
	Host     string
	Platform string
	Detail   string
	// Verify is set for edge cases, where takeover depends on the provider's conditions.
	Verify bool
	// URLs are where the finding was made, for findings from HTTP responses.
	URLs []string
}

func newReport(p processedIssues, domains int, elapsed time.Duration, logPath string) report {
	r := report{
		Domains:       domains,
		Duration:      elapsed,
		DNSIssues:     len(p.DNS),
		RequestErrors: len(p.request),
		LogPath:       logPath,
	}
	// a host usually matches over both http and https: report it once, with both URLs
	index := map[string]int{}
	for _, v := range p.potVulns {
		key := v.fqdn + "|" + v.platform
		i, ok := index[key]
		if !ok {
			i = len(r.Findings)
			index[key] = i
			r.Findings = append(r.Findings, reportFinding{Host: v.fqdn, Platform: v.platform, Detail: v.detail, Verify: v.edgeCase})
		}
		if v.url != "" && v.url != v.fqdn && !slices.Contains(r.Findings[i].URLs, v.url) {
			r.Findings[i].URLs = append(r.Findings[i].URLs, v.url)
		}
	}
	// takeovers before edge cases to verify, then by host and platform
	slices.SortFunc(r.Findings, func(a, b reportFinding) int {
		if a.Verify != b.Verify {
			if a.Verify {
				return 1
			}
			return -1
		}
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return strings.Compare(a.Platform, b.Platform)
	})
	for _, f := range r.Findings {
		if f.Verify {
			r.Verify++
		} else {
			r.Takeovers++
		}
	}
	return r
}

// headline summarises the findings, as for an email subject.
func (r report) headline() string {
	if r.Takeovers+r.Verify == 0 {
		return "no potential takeovers found"
	}
	var parts []string
	if r.Takeovers > 0 {
		parts = append(parts, plural(r.Takeovers, "1 potential takeover", strconv.Itoa(r.Takeovers)+" potential takeovers"))
	}
	if r.Verify > 0 {
		parts = append(parts, strconv.Itoa(r.Verify)+" to verify")
	}
	return strings.Join(parts, ", ")
}
