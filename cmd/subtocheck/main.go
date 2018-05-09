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
	"bufio"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"gopkg.in/alecthomas/kingpin.v2"

	"bytes"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh/terminal"
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
	httpPrefix  = "http://"
	httpsPrefix = "https://"
	protocols   = []string{"http", "https"}
)

type issue struct {
	kind string // vuln, request, dns
	fqdn string
	url  string
	err  error
}

type issues []issue

func main() {
	nameservers = []string{
		"8.8.8.8",         // google
		"8.8.4.4",         // google
		"209.244.0.3",     // level3
		"209.244.0.4",     // level3
		"1.1.1.1",         // cloudflare
		"1.0.0.1",         // cloudflare
		"9.9.9.9",         // quad9
		"149.112.112.112", // quad9
	}

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
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		checkDomains(domainsPath)
		if len(domainIssues) > 0 {
			displayIssues(domainIssues)
		} else {
			fmt.Println("\nNo issues found.")
		}

	}
}

func displayIssues(issues issues) {
	var reqIssues, DNSIssues, potVulns []issue
	var txtNoIssuesFound = "none found"
	for _, issue := range issues {
		switch issue.kind {
		case "request":
			reqIssues = append(reqIssues, issue)
		case "dns":
			DNSIssues = append(DNSIssues, issue)
		case "vuln":
			potVulns = append(potVulns, issue)
		}
	}

	fmt.Printf("\nRequest issues\n--------------\n")
	if len(reqIssues) > 0 {
		for _, issue := range reqIssues {
			if issue.kind == "request" {
				fmt.Printf("%v\n", issue.err)
			}
		}
	} else {
		fmt.Println(txtNoIssuesFound)
	}

	fmt.Printf("\nDNS issues\n----------\n")
	if len(DNSIssues) > 0 {
		for _, issue := range DNSIssues {
			if issue.kind == "dns" {
				fmt.Printf("%v\n", issue.err)
			}
		}
	} else {
		fmt.Println(txtNoIssuesFound)
	}
	fmt.Printf("\nPotential vulnerabilities\n-------------------------\n")
	if len(potVulns) > 0 {
		for _, issue := range potVulns {
			if issue.kind == "vuln" {
				fmt.Printf("%s %v\n", issue.url, issue.err)
			}
		}
	} else {
		fmt.Println(txtNoIssuesFound)
	}
}

var resolveMutex sync.Mutex
var nameservers []string

func padToWidth(input string, trimToWidth bool) (output string) {
	// Split string into lines
	var lines []string
	var newLines []string
	if strings.Contains(input, "\n") {
		lines = strings.Split(input, "\n")
	} else {
		lines = []string{input}
	}
	var paddingSize int
	for i, line := range lines {
		width, _, _ := terminal.GetSize(0)
		if width == -1 {
			width = 80
		}
		// No padding for a line that already meets or exceeds console width
		length := len(line)

		if length >= width {
			if trimToWidth {
				output = line[0:width]
			} else {
				output = input
			}
			return
		} else if i == len(lines)-1 {
			paddingSize = width - len(line)
			if paddingSize >= 1 {
				newLines = append(newLines, fmt.Sprintf("%s%s\r", line, strings.Repeat(" ", paddingSize)))
			} else {
				newLines = append(newLines, fmt.Sprintf("%s\r", line))
			}
		} else {
			var suffix string
			newLines = append(newLines, fmt.Sprintf("%s%s%s\n", line, strings.Repeat(" ", paddingSize), suffix))
		}
	}
	output = strings.Join(newLines, "")
	return
}

func checkResolves(fqdn string) (issues issues) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	m.RecursionDesired = true
	c.Timeout = 1500 * time.Millisecond
	var record *dns.Msg
	var err error
	resolveMutex.Lock()
	rand.Seed(time.Now().UnixNano())
	ns := rand.Int() % len(nameservers)
	record, _, err = c.Exchange(m, net.JoinHostPort(nameservers[ns], strconv.Itoa(53)))
	resolveMutex.Unlock()
	if err != nil {
		err = errors.Errorf("%s could not be resolved (%v)\n", fqdn, err)
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	} else if len(record.Answer) == 0 {
		err = errors.Errorf("%s could not be resolved (no answer from %s)", fqdn, nameservers[ns])
		issues = append(issues, issue{kind: "dns", fqdn: fqdn, err: err})
	} else if record.Rcode != 0 {
		err = errors.Errorf("%s could not be resolved (%s from %s)", fqdn, dns.RcodeToString[record.Rcode],
			nameservers[ns])
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
		var httpURL string
		if protocol == "http" {
			httpURL = httpPrefix + fqdn
		} else if protocol == "https" {
			httpURL = httpsPrefix + fqdn
		}
		var httpResp *http.Response
		var err error
		httpResp, err = client.Get(httpURL)
		if err != nil {
			issues = append(issues, issue{kind: "request", fqdn: fqdn, err: err})
		}
		if httpResp != nil {
			vulnIssue := checkVulnerable(httpURL, httpResp)
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
	{
		platform:        "S3",
		responseCodes:   []int{404},
		bodyStrings:     []string{"Code: NoSuchBucket"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Tumblr",
		responseCodes:   []int{404},
		bodyStrings:     []string{"Not found.", "assets.tumblr.com"},
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
			if pattern.responseCodes == nil || !contains(pattern.responseCodes, response.StatusCode) {
				continue
			}
		}
		if checkBodyResponse(pattern, response.Body) {
			return issue{
				url:  url,
				kind: "vuln",
				err:  errors.Errorf("matches pattern for platform: %s", pattern.platform),
			}
		}
	}
	return
}

func checkBodyResponse(pattern vPattern, body io.ReadCloser) (result bool) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(body)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
	bodyText := buf.String()
	for _, bodyString := range pattern.bodyStrings {
		if strings.Contains(bodyText, bodyString) {
			result = true
		} else if pattern.bodyStringMatch == "all" {
			result = false
			return
		}
	}
	return
}

var domainIssues issues

func checkDomains(path string) {
	file, _ := os.Open(path)
	domainScanner := bufio.NewScanner(file)
	var domains []string
	for domainScanner.Scan() {
		domains = append(domains, domainScanner.Text())
	}
	jobs := make(chan string, len(domains))
	results := make(chan bool, len(domains))

	for w := 1; w <= 10; w++ {
		go worker(w, jobs, results)
	}
	numDomains := len(domains)
	for j := 0; j < numDomains; j++ {
		jobs <- domains[j]
	}
	close(jobs)

	var progress string
	for a := 1; a <= numDomains; a++ {
		progress = fmt.Sprintf("Processing... %d/%d %s", a, numDomains, domains[a-1])
		progress = padToWidth(progress, true)
		width, _, _ := terminal.GetSize(0)
		if len(progress) == width {
			fmt.Printf(progress[0:width-3] + "   \r")
		} else {
			fmt.Print(progress)
		}
		<-results
	}
	// clear
	fmt.Printf("%s", padToWidth(" ", false))
}

func worker(id int, jobs <-chan string, results chan<- bool) {
	for j := range jobs {
		if *debug {
			fmt.Printf("worker: %d\n", id)
		}
		resolveIssues := checkResolves(j)
		if len(resolveIssues) > 0 {
			domainIssues = append(domainIssues, resolveIssues...)
		} else {
			responseIssues := checkResponse(j, protocols)
			if len(responseIssues) > 0 {
				domainIssues = append(domainIssues, responseIssues...)
			}
		}
		results <- true
	}
}
