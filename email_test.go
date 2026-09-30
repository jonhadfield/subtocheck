package subtocheck

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

func testIssues() processedIssues {
	return processedIssues{
		DNS:     []issue{{kind: "dns", fqdn: "a.example.com", err: errors.New("no answer")}},
		request: []issue{{kind: "request", url: "https://b.example.com", err: errors.New("timeout")}},
	}
}

// attachmentsLeft returns any issue list files left in the working directory.
func attachmentsLeft(t *testing.T) []string {
	t.Helper()
	left, err := filepath.Glob("*_issues_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	return left
}

func TestEmailSMTPFailureReturnsError(t *testing.T) {
	t.Chdir(t.TempDir())
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
	err = emailResults(email, testIssues())
	if err == nil || !strings.Contains(err.Error(), "failed to send email via SMTP server 127.0.0.1:"+port) {
		t.Fatalf("expected an SMTP send error, got %v", err)
	}
	if left := attachmentsLeft(t); len(left) > 0 {
		t.Errorf("attachments not cleaned up after failure: %v", left)
	}
}

func TestEmailSESInvalidSettingsReturnsError(t *testing.T) {
	t.Chdir(t.TempDir())
	email := emailConfig{
		Provider:   "ses",
		Region:     "eu-west-1",
		Source:     "subtocheck@example.com",
		Recipients: []string{"not an address"},
	}
	err := emailResults(email, testIssues())
	if err == nil || !strings.Contains(err.Error(), "invalid email settings: invalid email address 'not an address'") {
		t.Fatalf("expected an invalid settings error, got %v", err)
	}
	if left := attachmentsLeft(t); len(left) > 0 {
		t.Errorf("attachments not cleaned up after failure: %v", left)
	}
}

func TestEmailAttachmentWriteFailureReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// a read-only working directory makes writing the attachment fail
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	email := emailConfig{Provider: "smtp", Host: "127.0.0.1", Port: "25", Source: "subtocheck@example.com"}
	err := emailResults(email, testIssues())
	if err == nil || !strings.Contains(err.Error(), "failed to write DNS issues attachment") {
		t.Fatalf("expected an attachment write error, got %v", err)
	}
}
