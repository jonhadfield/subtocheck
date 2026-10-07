package subtocheck

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
)

func testReport() report {
	return newReport(processedIssues{
		potVulns: []issue{
			{kind: "vuln", fqdn: "b.example.com", url: "http://b.example.com", platform: "GitHub Pages", edgeCase: true, detail: "takeover depends on provider conditions, verify manually"},
			{kind: "vuln", fqdn: "a.example.com", url: "http://a.example.com", platform: "S3"},
			{kind: "vuln", fqdn: "a.example.com", url: "https://a.example.com", platform: "S3"},
			{kind: "vuln", fqdn: "c.example.com", url: "c.example.com", platform: "Azure", detail: "CNAME to old.azurewebsites.net, which does not exist"},
		},
		DNS:     []issue{{kind: "dns", fqdn: "d.example.com", err: errors.New("no answer")}},
		request: []issue{{kind: "request", url: "https://e.example.com", err: errors.New("timeout")}},
	}, 5, 1234*time.Millisecond, "")
}

func TestNewReport(t *testing.T) {
	r := testReport()
	if r.Takeovers != 2 || r.Verify != 1 || r.DNSIssues != 1 || r.RequestErrors != 1 || r.Domains != 5 {
		t.Errorf("unexpected counts %+v", r)
	}
	var order []string
	for _, f := range r.Findings {
		order = append(order, f.Host+"/"+f.Platform)
	}
	// takeovers first, then by host; the edge case last
	if got, want := strings.Join(order, ","), "a.example.com/S3,c.example.com/Azure,b.example.com/GitHub Pages"; got != want {
		t.Errorf("expected order %s, got %s", want, got)
	}
	// the S3 finding over http and https is one finding with both URLs; a DNS finding has none
	if got := strings.Join(r.Findings[0].URLs, ","); got != "http://a.example.com,https://a.example.com" {
		t.Errorf("unexpected URLs %q", got)
	}
	if len(r.Findings[1].URLs) != 0 {
		t.Errorf("expected no URLs for a DNS finding, got %v", r.Findings[1].URLs)
	}
}

func TestRenderEmail(t *testing.T) {
	r := testReport()
	r.LogPath = "/var/log/subtocheck-20261007-070000.log"
	subject, text, html, err := renderEmail("", r)
	if err != nil {
		t.Fatal(err)
	}
	if subject != "subtocheck scan - 2 potential takeovers, 1 to verify" {
		t.Errorf("unexpected subject %q", subject)
	}
	for _, want := range []string{
		"subtocheck scanned 5 domains in 1.2s: 2 potential takeovers, 1 to verify.",
		"TAKEOVER  a.example.com  (S3)",
		"VERIFY    b.example.com  (GitHub Pages)",
		"CNAME to old.azurewebsites.net, which does not exist",
		"https://a.example.com",
		"DNS issues:     1",
		"Every issue is detailed in the attached log, subtocheck-20261007-070000.log.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text body missing %q:\n%s", want, text)
		}
	}
	for _, want := range []string{"subtocheck: 2 potential takeovers, 1 to verify", ">TAKEOVER<", ">VERIFY<", "<b>a.example.com</b>", "subtocheck-20261007-070000.log"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML body missing %q", want)
		}
	}
	if strings.Contains(html, "/var/log") || strings.Contains(text, "/var/log") {
		t.Error("expected only the log's file name, not its path")
	}
}

func TestRenderEmailSubjects(t *testing.T) {
	for _, c := range []struct {
		takeovers, verify int
		want              string
	}{
		{0, 0, "Nightly - no potential takeovers found"},
		{1, 0, "Nightly - 1 potential takeover"},
		{0, 2, "Nightly - 2 to verify"},
	} {
		subject, _, _, err := renderEmail("Nightly", report{Takeovers: c.takeovers, Verify: c.verify})
		if err != nil || subject != c.want {
			t.Errorf("expected %q, got %q (%v)", c.want, subject, err)
		}
	}
}

// Finding details include DNS data, which whoever controls that DNS can set.
func TestRenderEmailEscapesFindings(t *testing.T) {
	r := report{Takeovers: 1, Findings: []reportFinding{{
		Host:     "a.example.com",
		Platform: "Unregistered domain",
		Detail:   `CNAME to <script>alert(1)</script>.example.net; <img src=x onerror=alert(1)>`,
	}}}
	_, _, html, err := renderEmail("", r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img") {
		t.Errorf("expected the detail to be escaped:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the escaped detail to be shown")
	}
}

func TestEmailSMTPFailureReturnsError(t *testing.T) {
	// a port with nothing listening on it
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	_ = listener.Close()

	email := emailConfig{
		Provider:   "smtp",
		Host:       "127.0.0.1",
		Port:       port,
		Source:     "subtocheck@example.com",
		Recipients: []string{"security@example.com"},
	}
	err = emailResults(email, testReport())
	if err == nil || !strings.Contains(err.Error(), "failed to send email via SMTP server 127.0.0.1:"+port) {
		t.Fatalf("expected an SMTP send error, got %v", err)
	}
}

func TestEmailInvalidSettingsReturnsError(t *testing.T) {
	for _, provider := range []string{"ses", "smtp"} {
		email := emailConfig{
			Provider:   provider,
			Region:     "eu-west-1",
			Source:     "subtocheck@example.com",
			Recipients: []string{"not an address"},
		}
		err := emailResults(email, testReport())
		if err == nil || !strings.Contains(err.Error(), "invalid email settings: invalid email address 'not an address'") {
			t.Errorf("%s: expected an invalid settings error, got %v", provider, err)
		}
	}
}

// fakeSMTP accepts one message and returns it.
func fakeSMTP(t *testing.T) (port string, received <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		reply := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		reply("220 localhost ESMTP")
		var data strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
				reply("250 localhost")
			case strings.HasPrefix(command, "DATA"):
				reply("354 end with .")
				for {
					l, err := reader.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				messages <- data.String()
				reply("250 queued")
			case strings.HasPrefix(command, "QUIT"):
				reply("221 bye")
				return
			default:
				reply("250 ok")
			}
		}
	}()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), messages
}

func TestEmailSentOverSMTP(t *testing.T) {
	port, received := fakeSMTP(t)
	logPath := filepath.Join(t.TempDir(), "subtocheck-20261007-070000.log")
	if err := os.WriteFile(logPath, []byte("2026-10-07T06:00:00Z DNS     d.example.com could not be resolved\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := testReport()
	r.LogPath = logPath
	email := emailConfig{
		Provider:   "smtp",
		Host:       "127.0.0.1",
		Port:       port,
		Subject:    "Nightly",
		Source:     "subtocheck@example.com",
		Recipients: []string{"security@example.com", "ops@example.com"},
	}
	if err := emailResults(email, r); err != nil {
		t.Fatal(err)
	}
	var message string
	select {
	case message = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("no message received")
	}
	for _, want := range []string{
		"To: security@example.com, ops@example.com",
		"Subject: Nightly - 2 potential takeovers, 1 to verify",
		"Content-Type: text/plain",
		"Content-Type: text/html",
		`filename="subtocheck-20261007-070000.log"`,
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message missing %q", want)
		}
	}
	// the log is the only attachment: the old per-kind issue lists are gone
	if strings.Contains(message, "dns_issues_") || strings.Contains(message, "request_issues_") {
		t.Error("expected no generated issue list attachments")
	}
}
