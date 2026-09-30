package subtocheck

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"
)

var (
	colourRed    = lipgloss.Color("#FF5F5F")
	colourYellow = lipgloss.Color("#FFD75F")
	colourGreen  = lipgloss.Color("#5FD787")
	colourCyan   = lipgloss.Color("#5FD7FF")
	colourGrey   = lipgloss.Color("#8A8A8A")
	colourDark   = lipgloss.Color("#1C1C1C")

	styleTakeover = lipgloss.NewStyle().Bold(true).Foreground(colourDark).Background(colourRed).Padding(0, 1)
	styleVerify   = lipgloss.NewStyle().Bold(true).Foreground(colourDark).Background(colourYellow).Padding(0, 1)
	styleTarget   = lipgloss.NewStyle().Bold(true)
	stylePlatform = lipgloss.NewStyle().Foreground(colourCyan)
	styleDim      = lipgloss.NewStyle().Foreground(colourGrey)
	styleAccent   = lipgloss.NewStyle().Foreground(colourCyan)
	styleRed      = lipgloss.NewStyle().Bold(true).Foreground(colourRed)
	styleYellow   = lipgloss.NewStyle().Bold(true).Foreground(colourYellow)
	styleGreen    = lipgloss.NewStyle().Bold(true).Foreground(colourGreen)
	styleBox      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colourGrey).Padding(0, 1)

	spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
)

const progressBarWidth = 30

// console shows findings as they are found, a progress bar while scanning on a terminal,
// and a summary at the end. Colour is reduced or removed to suit the output, and honours
// NO_COLOR. It is used from a single goroutine.
type console struct {
	out         io.Writer
	interactive bool // draw the progress bar, which needs a terminal
	quiet       bool
	total, done int
	frame       int
	current     string
	barShown    bool
	seen        map[string]bool // findings already shown, as fqdn and platform
}

func newConsole(quiet bool, total int) *console {
	return &console{
		out:         colorprofile.NewWriter(os.Stdout, os.Environ()),
		interactive: !quiet && term.IsTerminal(int(os.Stdout.Fd())),
		quiet:       quiet,
		total:       total,
		seen:        map[string]bool{},
	}
}

// finding shows a potential takeover, once per host and platform: a host usually matches
// over both http and https.
func (c *console) finding(i issue) {
	key := i.fqdn + "|" + i.platform
	if c.quiet || c.seen[key] {
		return
	}
	c.seen[key] = true
	c.clearBar()
	badge := styleTakeover.Render("TAKEOVER")
	if i.edgeCase {
		badge = styleVerify.Render(" VERIFY ")
	}
	line := badge + " " + styleTarget.Render(i.fqdn) + "  " + stylePlatform.Render(i.platform)
	if i.detail != "" {
		line += "  " + styleDim.Render(i.detail)
	}
	_, _ = fmt.Fprintln(c.out, line)
	c.drawBar()
}

// progress records a completed domain.
func (c *console) progress(domain string) {
	c.done++
	c.current = domain
	c.drawBar()
}

// tick advances the spinner.
func (c *console) tick() {
	c.frame++
	c.drawBar()
}

func (c *console) drawBar() {
	if !c.interactive {
		return
	}
	filled := 0
	if c.total > 0 {
		filled = progressBarWidth * c.done / c.total
	}
	// the empty part uses a thinner line so progress is visible without colour
	bar := styleAccent.Render(strings.Repeat("━", filled)) + styleDim.Render(strings.Repeat("─", progressBarWidth-filled))
	line := styleAccent.Render(spinnerFrames[c.frame%len(spinnerFrames)]) + " Scanning " + bar + " " +
		styleTarget.Render(fmt.Sprint(c.done)) + styleDim.Render(fmt.Sprintf("/%d", c.total))
	if c.current != "" {
		line += "  " + styleDim.Render(c.current)
	}
	// keep to one line, or the redraw cannot overwrite it
	_, _ = fmt.Fprint(c.out, "\r"+ansi.EraseEntireLine+ansi.Truncate(line, terminalWidth()-1, "…"))
	c.barShown = true
}

func (c *console) clearBar() {
	if c.barShown {
		_, _ = fmt.Fprint(c.out, "\r"+ansi.EraseEntireLine)
		c.barShown = false
	}
}

// summary replaces the progress bar with the totals and where the details are.
func (c *console) summary(p processedIssues, elapsed time.Duration, logPath string, logErr error) {
	c.clearBar()
	if c.quiet {
		return
	}
	var takeovers, verify int
	counted := map[string]bool{}
	for _, v := range p.potVulns {
		key := v.fqdn + "|" + v.platform
		if counted[key] {
			continue
		}
		counted[key] = true
		if v.edgeCase {
			verify++
		} else {
			takeovers++
		}
	}

	lines := []string{
		styleTarget.Render(fmt.Sprintf("Scanned %d %s", c.total, plural(c.total, "domain", "domains"))) +
			styleDim.Render(" in "+elapsed.Round(100*time.Millisecond).String()),
		"",
	}
	if takeovers+verify == 0 {
		lines = append(lines, styleGreen.Render("✓")+" No potential takeovers found")
	} else {
		lines = append(lines,
			countLine(takeovers, styleRed, "potential takeover", "potential takeovers"),
			countLine(verify, styleYellow, "to verify manually", "to verify manually"))
	}
	lines = append(lines,
		countLine(len(p.DNS), styleDim, "DNS issue", "DNS issues"),
		countLine(len(p.request), styleDim, "request error", "request errors"))
	switch {
	case logErr != nil:
		lines = append(lines, "", styleYellow.Render("Could not write log: ")+logErr.Error())
	case logPath != "":
		lines = append(lines, "", styleDim.Render("Details: "+logPath))
	}
	_, _ = fmt.Fprintln(c.out, styleBox.Render(strings.Join(lines, "\n")))
}

func countLine(n int, style lipgloss.Style, singular, pluralForm string) string {
	if n == 0 {
		style = styleDim
	}
	return style.Render(fmt.Sprintf("%3d", n)) + " " + plural(n, singular, pluralForm)
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
