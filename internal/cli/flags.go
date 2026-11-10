package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"cl1ck/internal/fetch"
)

type Flags struct {
	URL             string
	File            string
	NoScreenshot    bool
	Headers         []string
	Save            bool
	JSON            bool
	OutDir          string
	Timeout         time.Duration
	ScreenshotDelay time.Duration
}

type headerList []string

func (h *headerList) String() string     { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

func Parse(args []string) (Flags, error) {
	var f Flags
	var headers headerList

	fs := flag.NewFlagSet("cl1ck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.URL, "u", "", "Target URL (single)")
	fs.StringVar(&f.File, "f", "", "File with target URLs, one per line")
	fs.BoolVar(&f.NoScreenshot, "no-screenshot", false, "Skip screenshot evidence (HTML only)")
	fs.Var(&headers, "H", "Custom HTTP header 'Key: Value' (repeatable)")
	fs.Var(&headers, "header", "Custom HTTP header 'Key: Value' (repeatable)")
	fs.BoolVar(&f.Save, "save", false, "Also persist the PoC HTML file as evidence")
	fs.BoolVar(&f.JSON, "json", false, "Print a JSON report for all targets on stdout")
	fs.StringVar(&f.OutDir, "out", "evidencias", "Evidence output directory")
	fs.DurationVar(&f.Timeout, "timeout", fetch.DefaultTimeout, "Per-request timeout")
	fs.DurationVar(&f.ScreenshotDelay, "screenshot-delay", 2*time.Second, "Delay before screenshot so the framed app can load")

	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if (f.URL == "") == (f.File == "") {
		return f, errors.New("exactly one of -u <url> or -f <file> is required")
	}
	f.Headers = headers
	return f, nil
}

func Usage() string {
	return `cl1ck - ` + Description + `
By: Cr0wtl3r

Usage:
  cl1ck -u <url> [options]
  cl1ck -f <file> [options]

Options:
  -u <url>            Single target URL
  -f <file>           File with target URLs, one per line
  -H, --header "K: V" Custom HTTP header (repeatable)
  --no-screenshot     Skip screenshot evidence (HTML only)
  --save              Also persist the PoC HTML file as evidence
  --json              Print a JSON report for all targets on stdout
  --out <dir>         Evidence output directory (default "evidencias")
  --timeout <dur>     Per-request timeout (default 10s)
  --screenshot-delay <dur>  Delay before screenshot so the framed app can load (default 2s)
`
}

func ParseHeaders(list []string) (map[string]string, []string) {
	headers := map[string]string{}
	var warnings []string
	for _, h := range list {
		key, value, ok := strings.Cut(h, ":")
		if !ok {
			warnings = append(warnings, fmt.Sprintf("ignoring malformed header (use 'Key: Value'): %s", h))
			continue
		}
		headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return headers, warnings
}
