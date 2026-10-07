package subtocheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
)

func TestJSONReport(t *testing.T) {
	p := processedIssues{
		potVulns: []issue{
			{kind: "vuln", fqdn: "a.example.com", url: "https://a.example.com", platform: "S3"},
			{kind: "vuln", fqdn: "b.example.com", url: "http://b.example.com", platform: "GitHub Pages", edgeCase: true, detail: "verify manually"},
		},
		DNS:     []issue{{kind: "dns", fqdn: "c.example.com", err: errors.New("c.example.com could not be resolved")}},
		request: []issue{{kind: "request", url: "https://d.example.com", err: errors.New("timeout")}},
	}
	r := newReport(p, 4, 1260*time.Millisecond, "subtocheck.log")
	var buf bytes.Buffer
	if err := writeJSON(&buf, newJSONReport(r, p)); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got["domains"] != 4.0 || got["duration_seconds"] != 1.3 || got["log"] != "subtocheck.log" {
		t.Errorf("unexpected scan fields: %v", got)
	}
	summary := got["summary"].(map[string]any)
	if summary["takeovers"] != 1.0 || summary["verify"] != 1.0 || summary["dns_issues"] != 1.0 || summary["request_errors"] != 1.0 {
		t.Errorf("unexpected summary: %v", summary)
	}
	findings := got["findings"].([]any)
	first, second := findings[0].(map[string]any), findings[1].(map[string]any)
	if first["host"] != "a.example.com" || first["kind"] != "takeover" || first["platform"] != "S3" || second["kind"] != "verify" || second["detail"] != "verify manually" {
		t.Errorf("unexpected findings: %v", findings)
	}
	dns := got["dns_issues"].([]any)[0].(map[string]any)
	if dns["target"] != "c.example.com" || !strings.Contains(dns["error"].(string), "could not be resolved") {
		t.Errorf("unexpected DNS issue: %v", dns)
	}
	if req := got["request_errors"].([]any)[0].(map[string]any); req["target"] != "https://d.example.com" || req["error"] != "timeout" {
		t.Errorf("unexpected request error: %v", req)
	}
}

func TestJSONReportWithNothingFound(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, newJSONReport(newReport(processedIssues{}, 1, time.Second, ""), processedIssues{})); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// lists are empty rather than null, and no log is named when none was written
	for _, want := range []string{`"findings": []`, `"dns_issues": []`, `"request_errors": []`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"log"`) {
		t.Errorf("expected no log field:\n%s", out)
	}
}
