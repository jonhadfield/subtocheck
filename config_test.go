package subtocheck

import (
	"strings"
	"testing"
)

func TestParseConfigFileContent(t *testing.T) {
	t.Run("smtp", func(t *testing.T) {
		got, err := parseConfigFileContent([]byte(`
email:
  provider: smtp
  host: mail.example.com
  port: "587"
  username: scanner
  password: secret
  subject: nightly scan
  source: from@example.com
  recipients:
    - a@example.com
    - b@example.com
  skip_no_vulns: true
`))
		if err != nil {
			t.Fatal(err)
		}
		e := got.Email
		if e.Provider != "smtp" || e.Host != "mail.example.com" || e.Port != "587" {
			t.Errorf("unexpected SMTP fields %+v", e)
		}
		if e.Username != "scanner" || e.Password != "secret" || e.Subject != "nightly scan" {
			t.Errorf("unexpected auth/subject %+v", e)
		}
		if e.Source != "from@example.com" || !e.SkipNoVulns {
			t.Errorf("unexpected source/skip %+v", e)
		}
		if got, want := strings.Join(e.Recipients, ","), "a@example.com,b@example.com"; got != want {
			t.Errorf("recipients: got %q, want %q", got, want)
		}
	})

	t.Run("ses", func(t *testing.T) {
		got, err := parseConfigFileContent([]byte(`
email:
  provider: ses
  region: eu-west-1
  source: from@example.com
  recipients:
    - a@example.com
  aws_access_key_id: AKIATEST
  aws_secret_access_key: secret
  aws_session_token: token
`))
		if err != nil {
			t.Fatal(err)
		}
		e := got.Email
		if e.Provider != "ses" || e.Region != "eu-west-1" || e.Source != "from@example.com" {
			t.Errorf("unexpected SES fields %+v", e)
		}
		if e.AWSAccessKeyID != "AKIATEST" || e.AWSSecretAccessKey != "secret" || e.AWSSessionToken != "token" {
			t.Errorf("unexpected AWS credentials mapping %+v", e)
		}
		if e.SkipNoVulns {
			t.Error("expected skip_no_vulns to default to false")
		}
		if len(e.Recipients) != 1 || e.Recipients[0] != "a@example.com" {
			t.Errorf("unexpected recipients %v", e.Recipients)
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		_, err := parseConfigFileContent([]byte("email: [\n"))
		if err == nil {
			t.Fatal("expected an error for invalid YAML")
		}
	})
}
