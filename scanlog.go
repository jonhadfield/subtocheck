package subtocheck

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// scanLog records every issue found during a scan, and debug messages when enabled, so the
// console only needs to show findings. The file is created on the first write, so a scan
// with nothing to report leaves no file behind. Methods are safe on a nil *scanLog, which
// discards everything.
type scanLog struct {
	mu    sync.Mutex
	path  string
	debug bool
	file  *os.File
	err   error // the first error creating or writing the file
}

// defaultLogPath names the log after the time the scan started.
func defaultLogPath(start time.Time) string {
	return "subtocheck-" + start.Format("20060102-150405") + ".log"
}

func newScanLog(path string, debug bool) *scanLog {
	return &scanLog{path: path, debug: debug}
}

func (l *scanLog) write(level, msg string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return
	}
	if l.file == nil {
		if l.file, l.err = os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); l.err != nil {
			return
		}
	}
	_, l.err = fmt.Fprintf(l.file, "%s %-7s %s\n", time.Now().UTC().Format(time.RFC3339), level, msg)
}

// issue records a DNS issue, request error or finding.
func (l *scanLog) issue(i issue) {
	switch i.kind {
	case "dns":
		l.write("DNS", about(i.fqdn, i.err))
	case "request":
		l.write("REQUEST", about(i.url, i.err))
	case "vuln":
		l.write("FINDING", about(i.url, i.err))
	}
}

// about prefixes an error with what it concerns, unless the message already names it.
func about(subject string, err error) string {
	msg := fmt.Sprint(err)
	if subject == "" || strings.Contains(msg, subject) {
		return msg
	}
	return subject + ": " + msg
}

func (l *scanLog) debugf(format string, args ...any) {
	if l == nil || !l.debug {
		return
	}
	l.write("DEBUG", fmt.Sprintf(format, args...))
}

// written reports whether the log file was created.
func (l *scanLog) written() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file != nil
}

// Close closes the file, returning the first error from creating, writing or closing it.
func (l *scanLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		if err := l.file.Close(); err != nil && l.err == nil {
			l.err = err
		}
	}
	return l.err
}
