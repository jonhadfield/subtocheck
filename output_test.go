package subtocheck

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/colorprofile"
	"github.com/pkg/errors"
)

// newTestConsole returns a console writing plain text to buf, as it would when piped.
func newTestConsole(buf *bytes.Buffer, quiet, interactive bool, total int) *console {
	return &console{
		out:         colorprofile.NewWriter(buf, nil),
		interactive: interactive,
		quiet:       quiet,
		total:       total,
		seen:        map[string]bool{},
	}
}

func finding(fqdn, platform string, edgeCase bool) issue {
	return issue{kind: "vuln", fqdn: fqdn, url: "https://" + fqdn, platform: platform, edgeCase: edgeCase}
}

func TestFindingsShownOncePerHostAndPlatform(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConsole(&buf, false, false, 2)
	c.finding(finding("a.example.com", "S3", false))
	c.finding(finding("a.example.com", "S3", false)) // the same finding over http
	c.finding(finding("b.example.com", "GitHub Pages", true))

	out := buf.String()
	if n := strings.Count(out, "a.example.com"); n != 1 {
		t.Errorf("expected a.example.com once, got %d times:\n%s", n, out)
	}
	if !strings.Contains(out, "TAKEOVER  a.example.com  S3") {
		t.Errorf("expected a TAKEOVER line for S3:\n%s", out)
	}
	if !strings.Contains(out, "VERIFY   b.example.com  GitHub Pages") {
		t.Errorf("expected a VERIFY line for the edge case:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("expected no escape codes when not writing to a terminal:\n%q", out)
	}
}

func TestSummary(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConsole(&buf, false, false, 5)
	p := processedIssues{
		potVulns: []issue{
			finding("a.example.com", "S3", false),
			finding("a.example.com", "S3", false),
			finding("b.example.com", "GitHub Pages", true),
		},
		DNS:     []issue{{kind: "dns"}, {kind: "dns"}},
		request: []issue{{kind: "request"}},
	}
	c.summary(p, 1234*time.Millisecond, "scan.log", nil)
	out := buf.String()
	for _, want := range []string{"Scanned 5 domains in 1.2s", "1 potential takeover", "1 to verify manually", "2 DNS issues", "1 request error", "Details: scan.log"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestSummaryWithNothingFound(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConsole(&buf, false, false, 1)
	c.summary(processedIssues{}, time.Second, "", nil)
	out := buf.String()
	if !strings.Contains(out, "Scanned 1 domain in") || !strings.Contains(out, "No potential takeovers found") {
		t.Errorf("unexpected summary:\n%s", out)
	}
	if strings.Contains(out, "Details:") {
		t.Errorf("expected no log path when nothing was logged:\n%s", out)
	}
}

func TestQuietConsolePrintsNothing(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConsole(&buf, true, false, 1)
	c.finding(finding("a.example.com", "S3", false))
	c.progress("a.example.com")
	c.summary(processedIssues{potVulns: []issue{finding("a.example.com", "S3", false)}}, time.Second, "scan.log", nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output in quiet mode, got:\n%s", buf.String())
	}
}

func TestProgressBarRedrawsOneLine(t *testing.T) {
	var buf bytes.Buffer
	c := newTestConsole(&buf, false, true, 10)
	c.progress("a.example.com")
	c.progress("b.example.com")
	c.progress("c.example.com")
	out := buf.String()
	last := out[strings.LastIndex(out, "\r")+1:]
	if !strings.Contains(last, "3/10") || !strings.Contains(last, "c.example.com") {
		t.Errorf("expected the last redraw to show 3/10 and c.example.com, got %q", last)
	}
	if strings.Contains(out, "\n") {
		t.Errorf("expected the progress bar to stay on one line, got %q", out)
	}
	// a finding clears the bar, prints on its own line and redraws the bar below it
	c.finding(finding("d.example.com", "S3", false))
	after := buf.String()[len(out):]
	if !strings.Contains(after, "TAKEOVER  d.example.com  S3\n") || !strings.HasSuffix(strings.TrimRight(after, " "), "c.example.com") {
		t.Errorf("unexpected output after a finding: %q", after)
	}
}

func TestScanLogCreatedOnlyWhenWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.log")
	l := newScanLog(path, false)
	l.debugf("not written: debug is off")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected no log file, got %v", err)
	}
	if l.written() {
		t.Error("expected written to be false")
	}
}

func TestScanLogRecordsIssues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.log")
	l := newScanLog(path, true)
	l.issue(issue{kind: "dns", fqdn: "a.example.com", err: errors.New("no answer")})
	l.issue(issue{kind: "request", url: "https://b.example.com", err: errors.New("timeout")})
	l.issue(issue{kind: "vuln", url: "https://c.example.com", err: errors.New("matches pattern for platform: S3")})
	l.debugf("resolving %q", "d.example.com")
	// an error that already names its subject is not prefixed again
	l.issue(issue{kind: "dns", fqdn: "e.example.com", err: errors.New("e.example.com could not be resolved")})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"DNS     a.example.com: no answer",
		"DNS     e.example.com could not be resolved",
		"REQUEST https://b.example.com: timeout",
		"FINDING https://c.example.com: matches pattern for platform: S3",
		`DEBUG   resolving "d.example.com"`,
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("log missing %q:\n%s", want, content)
		}
	}
}

func TestScanLogReportsWriteFailure(t *testing.T) {
	l := newScanLog(filepath.Join(t.TempDir(), "missing-dir", "scan.log"), false)
	l.issue(issue{kind: "dns", fqdn: "a.example.com", err: errors.New("no answer")})
	if err := l.Close(); err == nil {
		t.Error("expected an error for a log in a directory that does not exist")
	}
}

func TestNilScanLogIsSafe(t *testing.T) {
	var l *scanLog
	l.issue(issue{kind: "dns", err: errors.New("x")})
	l.debugf("x")
	if l.written() || l.Close() != nil {
		t.Error("expected a nil log to do nothing")
	}
}
