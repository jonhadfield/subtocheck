package subtocheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	htmltemplate "html/template"
	"net"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/pkg/errors"
	"gopkg.in/gomail.v2"
)

func extractEmail(input string) (output string) {
	if strings.Contains(input, "<") {
		output = getStringInBetween(input, "<", ">")
	} else {
		output = input
	}
	return
}

func emailConfigDefined(email emailConfig) (result bool) {
	if !reflect.DeepEqual(email, emailConfig{}) {
		result = true
	}
	return
}

func validateEmailSettings(email emailConfig) (err error) {
	supportedProviders := []string{"ses", "smtp"}
	if emailConfigDefined(email) {
		if email.Provider == "" {
			err = fmt.Errorf("email provider not specified")
			return
		}

		if email.Source == "" {
			err = fmt.Errorf("email source not specified")
			return
		}

		if !stringInSlice(email.Provider, supportedProviders) {
			err = fmt.Errorf("email provider '%s' not supported", email.Provider)
			return
		}
		emailRegexp := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
		// validate recipient email addresses
		for _, emailAddr := range email.Recipients {
			if !emailRegexp.MatchString(extractEmail(emailAddr)) {
				err = fmt.Errorf("invalid email address '%s'", extractEmail(emailAddr))
				return
			}
		}
		// validate source email address
		if !emailRegexp.MatchString(extractEmail(email.Source)) {
			err = fmt.Errorf("invalid email address '%s'", extractEmail(email.Source))
			return
		}
	}
	return
}

// defaultSubject is the email subject unless one is configured. The findings' headline is
// appended to it.
const defaultSubject = "subtocheck scan"

var emailText = texttemplate.Must(texttemplate.New("text").Funcs(texttemplate.FuncMap{"plural": plural}).Parse(`subtocheck scanned {{.Domains}} {{plural .Domains "domain" "domains"}} in {{.Duration}}: {{.Headline}}.
{{if .Findings}}
Potential takeovers
{{range .Findings}}
{{if .Verify}}VERIFY  {{else}}TAKEOVER{{end}}  {{.Host}}  ({{.Platform}}){{if .Detail}}
          {{.Detail}}{{end}}{{range .URLs}}
          {{.}}{{end}}
{{end}}{{end}}
DNS issues:     {{.DNSIssues}}
Request errors: {{.RequestErrors}}
{{if .LogPath}}
Every issue is detailed in the attached log, {{.LogName}}.
{{end}}`))

var emailHTML = htmltemplate.Must(htmltemplate.New("html").Funcs(htmltemplate.FuncMap{"plural": plural}).Parse(`<!DOCTYPE html>
<html><body style="margin:0;padding:24px;background:#f6f6f6;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:#1c1c1c">
<div style="max-width:720px;margin:0 auto;background:#ffffff;border:1px solid #e2e2e2;border-radius:8px;padding:24px">
<h2 style="margin:0 0 4px 0;font-size:20px">subtocheck: {{.Headline}}</h2>
<p style="margin:0 0 20px 0;color:#6b6b6b;font-size:14px">Scanned {{.Domains}} {{plural .Domains "domain" "domains"}} in {{.Duration}}</p>
<table cellpadding="0" cellspacing="0" style="margin-bottom:20px;font-size:14px"><tr>
<td style="padding:8px 14px;border-radius:6px;background:{{if .Takeovers}}#ffe5e5{{else}}#f0f0f0{{end}}"><b style="font-size:18px">{{.Takeovers}}</b> {{plural .Takeovers "potential takeover" "potential takeovers"}}</td><td style="width:8px"></td>
<td style="padding:8px 14px;border-radius:6px;background:{{if .Verify}}#fff4d6{{else}}#f0f0f0{{end}}"><b style="font-size:18px">{{.Verify}}</b> to verify</td><td style="width:8px"></td>
<td style="padding:8px 14px;border-radius:6px;background:#f0f0f0"><b style="font-size:18px">{{.DNSIssues}}</b> {{plural .DNSIssues "DNS issue" "DNS issues"}}</td><td style="width:8px"></td>
<td style="padding:8px 14px;border-radius:6px;background:#f0f0f0"><b style="font-size:18px">{{.RequestErrors}}</b> {{plural .RequestErrors "request error" "request errors"}}</td>
</tr></table>
{{if .Findings}}<table cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;font-size:14px">
{{range .Findings}}<tr><td style="width:1%;padding:10px 12px 10px 0;border-top:1px solid #eeeeee;vertical-align:top;white-space:nowrap">{{if .Verify}}<span style="background:#ffd75f;color:#1c1c1c;font-weight:bold;font-size:12px;padding:2px 8px;border-radius:4px">VERIFY</span>{{else}}<span style="background:#ff5f5f;color:#ffffff;font-weight:bold;font-size:12px;padding:2px 8px;border-radius:4px">TAKEOVER</span>{{end}}</td>
<td style="padding:10px 0;border-top:1px solid #eeeeee;vertical-align:top"><b>{{.Host}}</b> <span style="color:#0b7fa8">{{.Platform}}</span>{{if .Detail}}<br><span style="color:#6b6b6b">{{.Detail}}</span>{{end}}{{range .URLs}}<br><span style="color:#6b6b6b;font-family:Menlo,Consolas,monospace;font-size:12px">{{.}}</span>{{end}}</td></tr>
{{end}}</table>
{{else}}<p style="font-size:14px;color:#2e7d32">No potential takeovers were found.</p>{{end}}
{{if .LogPath}}<p style="margin:20px 0 0 0;color:#6b6b6b;font-size:13px">Every issue is detailed in the attached log, {{.LogName}}.</p>{{end}}
</div></body></html>
`))

// emailView is what the templates render.
type emailView struct {
	report
	Headline string
	LogName  string
}

// renderEmail returns the subject and the plain text and HTML bodies of the email report.
func renderEmail(subject string, r report) (string, string, string, error) {
	if subject == "" {
		subject = defaultSubject
	}
	view := emailView{report: r, Headline: r.headline(), LogName: filepath.Base(r.LogPath)}
	view.Duration = r.Duration.Round(100 * time.Millisecond)
	var text, html bytes.Buffer
	if err := emailText.Execute(&text, view); err != nil {
		return "", "", "", errors.Wrap(err, "failed to render email")
	}
	if err := emailHTML.Execute(&html, view); err != nil {
		return "", "", "", errors.Wrap(err, "failed to render email")
	}
	return subject + " - " + view.Headline, text.String(), html.String(), nil
}

func emailResults(email emailConfig, r report) (err error) {
	if err = validateEmailSettings(email); err != nil {
		return errors.Wrap(err, "invalid email settings")
	}
	subject, text, html, err := renderEmail(email.Subject, r)
	if err != nil {
		return err
	}
	msg := gomail.NewMessage()
	msg.SetHeader("From", email.Source)
	msg.SetHeader("To", email.Recipients...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", text)
	msg.AddAlternative("text/html", html)
	if r.LogPath != "" {
		msg.Attach(r.LogPath)
	}

	switch email.Provider {
	case "ses":
		var raw bytes.Buffer
		if _, err = msg.WriteTo(&raw); err != nil {
			return errors.Wrap(err, "failed to build email")
		}
		opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(email.Region)}
		if email.AWSAccessKeyID != "" && email.AWSSecretAccessKey != "" {
			// use static credentials, with session token if provided
			opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				email.AWSAccessKeyID, email.AWSSecretAccessKey, email.AWSSessionToken)))
		}
		// otherwise credentials are discovered from the environment
		ctx := context.Background()
		var cfg aws.Config
		cfg, err = awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return errors.Wrap(err, "failed to load AWS configuration")
		}
		svc := ses.NewFromConfig(cfg)
		input := ses.SendRawEmailInput{
			Source:       aws.String(email.Source),
			Destinations: email.Recipients,
			RawMessage:   &types.RawMessage{Data: raw.Bytes()},
		}
		if _, err = svc.SendRawEmail(ctx, &input); err != nil {
			return errors.Wrap(err, "failed to send email via SES")
		}
	case "smtp":
		host := email.Host
		port, _ := strconv.Atoi(email.Port)
		dialer := gomail.NewDialer(host, port, email.Username, email.Password)
		dialer.TLSConfig = &tls.Config{ServerName: host}
		if err = dialer.DialAndSend(msg); err != nil {
			return errors.Wrapf(err, "failed to send email via SMTP server %s", net.JoinHostPort(host, email.Port))
		}
	}
	return nil
}
