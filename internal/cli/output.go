package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Result struct {
	URL            string   `json:"url"`
	FinalURL       string   `json:"final_url,omitempty"`
	StatusCode     int      `json:"status_code,omitempty"`
	Classification string   `json:"classification"`
	XFO            string   `json:"x_frame_options,omitempty"`
	CSP            string   `json:"content_security_policy,omitempty"`
	Redirects      []string `json:"redirects,omitempty"`
	Notes          []string `json:"notes,omitempty"`
	HTMLFile       string   `json:"html_file,omitempty"`
	ScreenshotFile string   `json:"screenshot_file,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type JSONReport struct {
	Tool        string   `json:"tool"`
	Version     string   `json:"version"`
	GeneratedAt string   `json:"generated_at"`
	Results     []Result `json:"results"`
}

type Printer struct {
	W     io.Writer
	Color bool
}

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
)

func (p *Printer) wrap(color, s string) string {
	if !p.Color {
		return s
	}
	return color + s + ansiReset
}

func (p *Printer) Progress(i, n int, url string) {
	fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiBlue, "[*]"), p.wrap(ansiBlue, fmt.Sprintf("[%d/%d] Analyzing headers of %s", i, n, url)))
}

func (p *Printer) Status(status string) {
	color := ansiYellow
	prefix := "[!]"
	switch status {
	case "PROTECTED":
		color = ansiGreen
		prefix = "[+]"
	case "CONFIRMED_FRAMEABLE":
		color = ansiRed
	case "INCONCLUSIVE":
		color = ansiDim
		prefix = "[*]"
	}
	fmt.Fprintf(p.W, "%s %s\n", p.wrap(color, prefix), p.wrap(color, "Classification: "+status))
}

func (p *Printer) Info(format string, args ...any) {
	fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiBlue, "[*]"), fmt.Sprintf(format, args...))
}

func (p *Printer) HeaderPresent(name, value string) {
	fmt.Fprintf(p.W, "%s Header %s is present! (Value: %s)\n", p.wrap(ansiBlue, "[*]"), p.wrap(ansiGreen, name), value)
}

func (p *Printer) HeaderMissing(name string) {
	fmt.Fprintf(p.W, "%s Security header missing: %s\n", p.wrap(ansiYellow, "[!]"), p.wrap(ansiYellow, name))
}

func (p *Printer) OK(format string, args ...any) {
	fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiGreen, "[+]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Warn(format string, args ...any) {
	fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiYellow, "[-]"), fmt.Sprintf(format, args...))
}

func (p *Printer) Note(format string, args ...any) {
	fmt.Fprintf(p.W, "%s\n", p.wrap(ansiDim, fmt.Sprintf(format, args...)))
}

func (p *Printer) Blank() {
	fmt.Fprintln(p.W)
}

func (p *Printer) Evidence(status, format string, args ...any) {
	color := ansiBold + ansiYellow
	if status == "CONFIRMED_FRAMEABLE" {
		color = ansiBold + ansiRed
	}
	fmt.Fprintf(p.W, "%s %s\n", p.wrap(color, "[!]"), p.wrap(color, fmt.Sprintf(format, args...)))
}

func (p *Printer) Summary(confirmed, potential int, findingsFile string) {
	fmt.Fprintln(p.W)
	fmt.Fprintf(p.W, "%s\n", p.wrap(ansiDim, strings.Repeat("-", 72)))
	if confirmed > 0 {
		fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiRed, "[!]"), p.wrap(ansiRed, fmt.Sprintf("Found %d confirmed frameable application(s)", confirmed)))
	}
	if potential > 0 {
		fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiYellow, "[!]"), p.wrap(ansiYellow, fmt.Sprintf("Found %d potentially frameable application(s)", potential)))
	}
	if confirmed > 0 || potential > 0 {
		fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiBlue, "[*]"), p.wrap(ansiBlue, "Findings list: "+findingsFile))
	} else {
		fmt.Fprintf(p.W, "%s %s\n", p.wrap(ansiGreen, "[+]"), p.wrap(ansiGreen, "No frameable applications found."))
	}
}

func MaskHeaderValue(v string) string {
	if len(v) <= 30 {
		return v
	}
	return v[:27] + "..."
}

func WriteJSON(w io.Writer, report JSONReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func FormatNotes(notes []string) string { return strings.Join(notes, "; ") }
