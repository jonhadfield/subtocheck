package subtocheck

import (
	"encoding/json"
	"io"
	"math"
)

// jsonReport is the scan result written by --json. Field names are part of the output's
// contract, so they only change with care.
type jsonReport struct {
	Domains         int           `json:"domains"`
	DurationSeconds float64       `json:"duration_seconds"`
	Summary         jsonSummary   `json:"summary"`
	Findings        []jsonFinding `json:"findings"`
	DNSIssues       []jsonProblem `json:"dns_issues"`
	RequestErrors   []jsonProblem `json:"request_errors"`
	Log             string        `json:"log,omitempty"`
}

type jsonSummary struct {
	Takeovers     int `json:"takeovers"`
	Verify        int `json:"verify"`
	DNSIssues     int `json:"dns_issues"`
	RequestErrors int `json:"request_errors"`
}

type jsonFinding struct {
	Host     string `json:"host"`
	Platform string `json:"platform"`
	// Kind is "takeover", or "verify" for edge cases where takeover depends on the
	// provider's conditions.
	Kind   string   `json:"kind"`
	Detail string   `json:"detail,omitempty"`
	URLs   []string `json:"urls,omitempty"`
}

// jsonProblem is a DNS issue or request error: the host or URL it concerns, and the error.
type jsonProblem struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

func newJSONReport(r report, p processedIssues) jsonReport {
	out := jsonReport{
		Domains:         r.Domains,
		DurationSeconds: math.Round(r.Duration.Seconds()*10) / 10,
		Summary: jsonSummary{
			Takeovers:     r.Takeovers,
			Verify:        r.Verify,
			DNSIssues:     r.DNSIssues,
			RequestErrors: r.RequestErrors,
		},
		// empty lists rather than null, so consumers can iterate without checking
		Findings:      []jsonFinding{},
		DNSIssues:     []jsonProblem{},
		RequestErrors: []jsonProblem{},
		Log:           r.LogPath,
	}
	for _, f := range r.Findings {
		kind := "takeover"
		if f.Verify {
			kind = "verify"
		}
		out.Findings = append(out.Findings, jsonFinding{Host: f.Host, Platform: f.Platform, Kind: kind, Detail: f.Detail, URLs: f.URLs})
	}
	for _, i := range p.DNS {
		out.DNSIssues = append(out.DNSIssues, jsonProblem{Target: i.fqdn, Error: errorText(i.err)})
	}
	for _, i := range p.request {
		out.RequestErrors = append(out.RequestErrors, jsonProblem{Target: i.url, Error: errorText(i.err)})
	}
	return out
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// writeJSON writes the report as indented JSON.
func writeJSON(w io.Writer, r jsonReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}
