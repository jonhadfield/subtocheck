package subtocheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"crypto/tls"
	"os"

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

func generateDNSIssueList(dnsIssues []issue) (filePath string, err error) {
	timeStamp := time.Now().UTC().Format("20060102150405")
	filePath = fmt.Sprintf("dns_issues_%s.txt", timeStamp)
	// convert issues to file content
	var buffer bytes.Buffer
	for _, dnsIssue := range dnsIssues {
		buffer.WriteString(dnsIssue.fqdn + " - " + dnsIssue.err.Error() + "\n")
	}
	if err = os.WriteFile(filePath, buffer.Bytes(), 0o644); err != nil {
		err = errors.Wrap(err, "failed to write DNS issues attachment")
	}
	return
}

func generateRequestIssueList(requestIssues []issue) (filePath string, err error) {
	timeStamp := time.Now().UTC().Format("20060102150405")
	filePath = fmt.Sprintf("request_issues_%s.txt", timeStamp)
	// convert issues to file content
	var buffer bytes.Buffer
	for _, requestIssue := range requestIssues {
		buffer.WriteString(requestIssue.url + " - " + requestIssue.err.Error() + "\n")
	}
	if err = os.WriteFile(filePath, buffer.Bytes(), 0o644); err != nil {
		err = errors.Wrap(err, "failed to write request issues attachment")
	}
	return
}

func emailResults(email emailConfig, pIssues processedIssues) (err error) {
	msg := gomail.NewMessage()
	msg.SetHeader("From", email.Source)
	var emailSubject string
	if email.Subject != "" {
		emailSubject = email.Subject
	} else {
		emailSubject = "AWS Account Scan"
	}

	if len(pIssues.potVulns) > 0 {
		emailSubject += " - potential vulnerabilities found"
	} else {
		emailSubject += " - no potential vulnerabilities found"
	}
	msg.SetHeader("Subject", emailSubject)

	body := "<font face=\"Courier New, Courier, monospace\">" +
		"&nbsp;Issues<br/>" +
		"--------" +
		"<br/>" +
		"</font>" +
		"<table border=\"0\" cellpadding=\"3\" cellspacing=\"3\" width=\"300\">" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">Potentially vulnerable</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(len(pIssues.potVulns)) + "</font></td>" +
		"</tr>" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">DNS</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(len(pIssues.DNS)) + "</font></td>" +
		"</tr>" +
		"<tr>" +
		"<td><font face=\"Courier New, Courier, monospace\">Request</font></td>" +
		"<td><font face=\"Courier New, Courier, monospace\">&nbsp;" + strconv.Itoa(len(pIssues.request)) + "</font></td>" +
		"</tr>" +
		"</table>" +
		"<br/><font face=\"Courier New, Courier, monospace\">" +
		"&nbsp;Potentially vulnerable URLs<br/>" +
		"-----------------------------" +
		"<br/>" +
		"</font>" +
		"<table border=\"0\" cellpadding=\"3\" cellspacing=\"4\" width=\"300\">"

	if len(pIssues.potVulns) > 0 {
		for _, vuln := range pIssues.potVulns {
			body += "<tr><td width=\"300\"><font face=\"Courier New, Courier, monospace\">" + vuln.url + " (" + vuln.platform + ")</font></td></tr>"
		}
	} else {
		body += "<tr><td width=\"300\"><font face=\"Courier New, Courier, monospace\">none found</font></td></tr>"
	}
	// close table
	body = body + "</table>"
	msg.SetBody("text/html", body)

	var dnsIssuesFilePath, requestIssuesFilePath string
	// the attachments are only removed if sending fails
	defer func() {
		if err != nil {
			cleanUpFiles(dnsIssuesFilePath, requestIssuesFilePath)
		}
	}()
	if len(pIssues.DNS) > 0 {
		// generate DNS issues file to attach
		if dnsIssuesFilePath, err = generateDNSIssueList(pIssues.DNS); err != nil {
			return
		}
		msg.Attach(dnsIssuesFilePath)
	}

	if len(pIssues.request) > 0 {
		// generate requests issues file to attach
		if requestIssuesFilePath, err = generateRequestIssueList(pIssues.request); err != nil {
			return
		}
		msg.Attach(requestIssuesFilePath)
	}

	var emailRaw bytes.Buffer
	_, err = msg.WriteTo(&emailRaw)
	if err != nil {
		err = errors.Wrap(err, "failed to build email")
		return
	}

	switch email.Provider {
	case "ses":
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
			err = errors.Wrap(err, "failed to load AWS configuration")
			return
		}
		err = validateEmailSettings(email)
		if err != nil {
			err = errors.Wrap(err, "invalid email settings")
			return
		}
		msg.SetHeader("To", strings.Join(email.Recipients, ","))
		svc := ses.NewFromConfig(cfg)
		input := ses.SendRawEmailInput{
			Source:       aws.String(email.Source),
			Destinations: email.Recipients,
			RawMessage:   &types.RawMessage{Data: emailRaw.Bytes()},
		}
		_, err = svc.SendRawEmail(ctx, &input)
		if err != nil {
			err = errors.Wrap(err, "failed to send email via SES")
		}
	case "smtp":
		msg.SetHeader("To", email.Recipients...)
		host := email.Host
		port, _ := strconv.Atoi(email.Port)
		dialer := gomail.NewDialer(host, port, email.Username, email.Password)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		}
		dialer.TLSConfig = tlsConfig
		err = dialer.DialAndSend(msg)
		if err != nil {
			err = errors.Wrapf(err, "failed to send email via SMTP server %s", net.JoinHostPort(host, email.Port))
		}
	}
	return
}

func cleanUpFiles(dnsIssuesFilePath string, requestIssuesFilePath string) {
	if dnsIssuesFilePath != "" {
		delDNSErr := os.Remove(dnsIssuesFilePath)
		if delDNSErr != nil {
			fmt.Println(delDNSErr)
		}
	}
	if requestIssuesFilePath != "" {
		delReqErr := os.Remove(requestIssuesFilePath)
		if delReqErr != nil {
			fmt.Println(delReqErr)
		}
	}
}
