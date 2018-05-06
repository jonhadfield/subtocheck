// Copyright 2018, Jon Hadfield <jon@lessknown.co.uk>
// This file is part of subtocheck.

// subtocheck is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// subtocheck is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with subtocheck.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"github.com/pkg/errors"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"fmt"
	"bufio"
	"net/http"

	"github.com/miekg/dns"
	"net"
	"strconv"
	"time"
	"crypto/tls"
	"strings"
	"io"
	"bytes"
)

var (
	domainListPath = kingpin.Arg("domain-list", "domain list file path").Default("domains.txt").String()
	debug          = kingpin.Flag("debug", "enable debug").Bool()
)

// overwritten at build time
var version, versionOutput, tag, sha, buildDate string

func getDomainListFilePath(path string) (result string, err error) {
	if _, fErr := os.Stat(path); !os.IsNotExist(fErr) {
		result = path
	} else {
		err = errors.Errorf("domains list file path '%s' could not be found", path)
	}
	return
}

var usageTemplate = `{{define "FormatCommand"}}\
{{range .Args}} {{if not .Required}}[{{end}}<{{.Name}}>{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end}}\
{{if .FlagSummary}} {{.FlagSummary}}{{end}}\
{{end}}\
{{define "FormatCommands"}}\
{{range .FlattenedCommands}}\
{{if not .Hidden}}\
  {{.FullCommand}}{{if .Default}}*{{end}}{{template "FormatCommand" .}}
{{.Help|Wrap 4}}
{{end}}\
{{end}}\
{{end}}\
{{define "FormatUsage"}}\
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}
{{if .Help}}
{{.Help|Wrap 0}}\
{{end}}\
{{end}}\
{{if .Context.SelectedCommand}}\
usage: {{.App.Name}} {{.Context.SelectedCommand}}{{template "FormatUsage" .Context.SelectedCommand}}
{{else}}\
usage: {{.App.Name}}{{template "FormatUsage" .App}}
{{end}}\
{{if .Context.Flags}}\
Flags:
{{.Context.Flags|FlagsToTwoColumns|FormatTwoColumns}}
{{end}}\
{{if .Context.Args}}\
Args:
{{.Context.Args|ArgsToTwoColumns|FormatTwoColumns}}
{{end}}\
{{if .Context.SelectedCommand}}\
{{if len .Context.SelectedCommand.Commands}}\
Subcommands:
{{template "FormatCommands" .Context.SelectedCommand}}
{{end}}\
{{else if .App.Commands}}\
Commands:
{{template "FormatCommands" .App}}
{{end}}\
`
var (
	httpPrefix   = "http://"
	httpsPrefix  = "https://"
	resolverHost = "1.1.1.1"
	resolverPort = 53
	protocols    = []string{"http", "https"}
)

type issue struct {
	kind   string  // vuln, request, dns
	fqdn   string
	url    string
	detail string
	err    error
}

type issues []issue

func main() {
	if tag != "" && buildDate != "" {
		versionOutput = fmt.Sprintf("[%s-%s] %s UTC", tag, sha, buildDate)
	} else {
		versionOutput = version
	}
	kingpin.Version(versionOutput)
	kingpin.CommandLine.HelpFlag.Short('h')
	kingpin.Parse()
	kingpin.UsageTemplate(usageTemplate)

	var err error
	var domainsPath string
	domainsPath, err = getDomainListFilePath(*domainListPath)
	if err != nil {
		fmt.Printf(err.Error())
		os.Exit(1)
	} else {
		var issues issues
		issues = checkDomains(domainsPath)
		if len(issues) > 0 {
			displayIssues(issues)
		} else {
			fmt.Println("No issues found.")
		}

	}
}

func displayIssues(issues issues) {
	fmt.Printf("\n- Vulnerabilities\n\n")
	for _, issue := range issues {
		if issue.kind == "vuln" {
			fmt.Printf("  %s\n    %v\n", issue.url, issue.err)
		}
	}
	fmt.Printf("\n- Requests\n\n")
	for _, issue := range issues {
		if issue.kind == "request" {
			fmt.Printf("  %s\n    %v\n", issue.fqdn, issue.err)
		}
	}
	fmt.Printf("\n- DNS\n\n")
	for _, issue := range issues {
		if issue.kind == "dns" {
			fmt.Printf("  %s\n    %v\n", issue.fqdn, issue.err)
		}
	}
}

func checkResolves(fqdn string) (issues issues) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = true
	c.ReadTimeout = 2 * time.Second
	c.WriteTimeout = 2 * time.Second
	var record *dns.Msg
	var err error
	record, _, err = c.Exchange(m, net.JoinHostPort(resolverHost, strconv.Itoa(resolverPort)))
	if err != nil {
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
		return
	}
	if len(record.Answer) == 0 {
		err = errors.New("name could not be resolved")
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	}
	return
}

func checkResponse(fqdn string, protocols []string) (issues issues) {
	tr := &http.Transport{
		ResponseHeaderTimeout: 2 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   3 * time.Second,
	}
	for _, protocol := range protocols {
		var httpUrl string
		if protocol == "http" {
			httpUrl = httpPrefix + fqdn
		} else if protocol == "https" {
			httpUrl = httpsPrefix + fqdn
		}
		var httpResp *http.Response
		var err error
		httpResp, err = client.Get(httpUrl)
		if err != nil {
			issues = append(issues, issue{kind: "request", fqdn: fqdn, err: err})
		}
		if httpResp != nil {
			vulnIssue := checkVulnerable(httpUrl, httpResp)
			if vulnIssue.kind != "" {
				issues = append(issues, vulnIssue)
			}
		}
	}
	return
}

type vPattern struct {
	platform        string
	responseCodes   []int // 0 for all
	bodyStrings     []string
	bodyStringMatch string
}

var vPatterns = []vPattern{
	{
		platform:        "CloudFront",
		responseCodes:   []int{403},
		bodyStrings:     []string{"The request could not be satisfied."},
		bodyStringMatch: "all",
	},
	{
		platform:        "Heroku",
		responseCodes:   []int{404},
		bodyStrings:     []string{"//www.herokucdn.com/error-pages/no-such-app.html"},
		bodyStringMatch: "all",
	},
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func checkVulnerable(url string, response *http.Response) (vuln issue) {
	for _, pattern := range vPatterns {
		if len(pattern.responseCodes) > 0 {
			if pattern.responseCodes == nil || ! contains(pattern.responseCodes, response.StatusCode) {
				continue
			}
		}
		if checkBodyResponse(pattern.bodyStrings, response.Body) {
			return issue{
				url:    url,
				kind:   "vuln",
				err: 	errors.Errorf("matches pattern for platform: %s", pattern.platform),
			}
		}
	}
	return
}

func checkBodyResponse(bodyStrings []string, body io.ReadCloser) (result bool) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(body)
	bodyText := buf.String()
	for _, bodyString := range bodyStrings {
		if strings.Contains(bodyText, bodyString) {
			result = true
			return
		}
	}

	return
}

func checkDomains(path string) (domainIssues issues) {
	file, _ := os.Open(path)
	domainScanner := bufio.NewScanner(file)
	for domainScanner.Scan() {
		fmt.Printf("Checking: %s\n", domainScanner.Text())
		resolveIssues := checkResolves(domainScanner.Text())
		if len(resolveIssues) > 0 {
			domainIssues = append(domainIssues, resolveIssues...)
			continue
		}
		responseIssues := checkResponse(domainScanner.Text(), protocols)
		if len(responseIssues) > 0 {
			domainIssues = append(domainIssues, responseIssues...)
		}
	}
	return
}
