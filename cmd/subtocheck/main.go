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
	"fmt"
	"os"
	"strconv"

	"github.com/alecthomas/kingpin/v2"
	"github.com/pkg/errors"

	"github.com/jonhadfield/subtocheck"
)

var (
	domainListPath = kingpin.Flag("domains", "domain list file path").Default("domains.txt").String()
	configPath     = kingpin.Flag("config", "config file").String()
	quiet          = kingpin.Flag("quiet", "suppress command line output").Bool()
	jsonOutput     = kingpin.Flag("json", "write the result to stdout as JSON instead of console output").Bool()
	debug          = kingpin.Flag("debug", "write debug messages to the log").Bool()
	logPath        = kingpin.Flag("log", "log file path (default: subtocheck-<timestamp>.log)").String()
	workers        = kingpin.Flag("workers", "number of domains to check at once").Default(strconv.Itoa(subtocheck.DefaultWorkers)).Int()
)

// exitFindings is the exit status when potential takeovers are found. Errors exit with 1.
const exitFindings = 2

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

	if *quiet && !*jsonOutput && *configPath == "" {
		// to stderr, so it never mixes with output meant for other tools
		fmt.Fprintln(os.Stderr, "warning: running without console output or email config: results are only written to the log file")
	}

	domainsPath, err := getDomainListFilePath(*domainListPath)
	if err != nil {
		kingpin.Fatalf("%v: create it with one domain per line, or set its path with --domains", err)
	}
	if *workers < 1 {
		kingpin.Fatalf("--workers must be at least 1")
	}
	findings, err := subtocheck.CheckDomains(domainsPath, subtocheck.Options{
		ConfigPath: *configPath,
		LogPath:    *logPath,
		Debug:      *debug,
		Quiet:      *quiet,
		JSON:       *jsonOutput,
		Workers:    *workers,
	})
	if err != nil {
		kingpin.Fatalf("%v", err)
	}
	if findings > 0 {
		// lets scripts and CI act on findings without parsing the output
		os.Exit(exitFindings)
	}
}
