package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cl1ck/internal/browser"
	"cl1ck/internal/cli"
	"cl1ck/internal/detect"
	"cl1ck/internal/fetch"
	"cl1ck/internal/poc"
	"cl1ck/internal/serve"
)

const (
	version      = "0.1.0"
	findingsFile = "url_with_clickjacking.txt"
	timeDisplay  = "2006-01-02 15:04:05"
	timeSlug     = "20060102_150405"
)

func main() {
	os.Exit(run())
}

func run() int {
	f, err := cli.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			cli.PrintBanner(os.Stdout)
			fmt.Print(cli.Usage())
			return 0
		}
		cli.PrintBanner(os.Stderr)
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, cli.Usage())
		return 2
	}

	human := os.Stdout
	if f.JSON {
		human = os.Stderr
	}
	if !f.JSON {
		cli.PrintBanner(human)
	}
	printer := &cli.Printer{W: human, Color: cli.ColorEnabled()}

	urls, err := loadURLs(f)
	if err != nil {
		fmt.Fprintf(human, "error: %v\n", err)
		return 1
	}

	headers, warnings := cli.ParseHeaders(f.Headers)
	for _, w := range warnings {
		printer.Warn("%s", w)
	}
	if len(headers) > 0 {
		printer.Info("Custom headers:")
		for k, v := range headers {
			fmt.Fprintf(human, "      %s: %s\n", k, cli.MaskHeaderValue(v))
		}
	}

	client := fetch.New(f.Timeout)
	results := make([]cli.Result, 0, len(urls))

	for i, rawURL := range urls {
		printer.Progress(i+1, len(urls), rawURL)
		res := cli.Result{URL: rawURL}

		fr := client.Get(context.Background(), rawURL, headers)
		res.FinalURL = fr.FinalURL
		res.StatusCode = fr.StatusCode
		res.Redirects = fr.Redirects

		if fr.Err != nil {
			res.Classification = string(detect.Inconclusive)
			res.Error = fr.Err.Error()
			printer.Status(res.Classification)
			printer.Warn("%s", fr.Err.Error())
			results = append(results, res)
			continue
		}

		if res.FinalURL != "" && res.FinalURL != rawURL {
			printer.Info("Effective URL: %s", res.FinalURL)
		}

		det := detect.Classify(fr.Header)
		res.Classification = string(det.Status)
		res.XFO = det.XFO
		res.CSP = det.CSP
		res.Notes = det.Notes

		var evidenceAt time.Time
		if det.Status == detect.PotentiallyVulnerable {
			evidenceAt = time.Now()
			res = generateEvidence(f, printer, res, rawURL, headers, evidenceAt)
			appendFinding(rawURL)
		}

		if res.XFO == "" {
			printer.HeaderMissing("X-Frame-Options")
		} else {
			printer.HeaderPresent("X-Frame-Options", res.XFO)
		}
		if res.CSP == "" {
			printer.HeaderMissing("Content-Security-Policy (frame-ancestors)")
		} else {
			printer.HeaderPresent("Content-Security-Policy", res.CSP)
		}

		if det.Status == detect.PotentiallyVulnerable {
			for _, n := range res.Notes {
				if isRedundantMissingNote(n, res) {
					continue
				}
				printer.Evidence(res.Classification, "%s", n)
			}
		} else {
			for _, n := range res.Notes {
				if res.Classification == string(detect.Protected) {
					printer.OK("%s", n)
				} else {
					printer.Info("%s", n)
				}
			}
		}

		printer.Status(res.Classification)

		if det.Status == detect.PotentiallyVulnerable {
			printer.Blank()
			printer.Note("Generated: %s | cl1ck v%s", evidenceAt.Format(timeDisplay), version)
			printer.Note("Manual check payload - save the line below as .html and open it in a browser:")
			printer.Note("<iframe src=%q width=\"800\" height=\"600\"></iframe>", rawURL)
		}
		if res.HTMLFile != "" {
			printer.OK("PoC HTML saved: %s", res.HTMLFile)
		}
		if res.ScreenshotFile != "" {
			printer.OK("Screenshot saved: %s", res.ScreenshotFile)
		}
		results = append(results, res)
	}

	confirmed, potential := countFindings(results)
	printer.Summary(confirmed, potential, findingsFile)

	if f.JSON {
		report := cli.JSONReport{
			Tool:        "cl1ck",
			Version:     version,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Results:     results,
		}
		if err := cli.WriteJSON(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON report: %v\n", err)
			return 1
		}
	}
	return 0
}

func isRedundantMissingNote(note string, res cli.Result) bool {
	return res.XFO == "" && res.CSP == "" && note == "no X-Frame-Options and no enforced CSP frame-ancestors"
}

func countFindings(results []cli.Result) (confirmed, potential int) {
	for _, res := range results {
		switch res.Classification {
		case string(detect.ConfirmedFrameable):
			confirmed++
		case string(detect.PotentiallyVulnerable):
			potential++
		}
	}
	return confirmed, potential
}

func loadURLs(f cli.Flags) ([]string, error) {
	if f.URL != "" {
		return []string{f.URL}, nil
	}
	data, err := os.ReadFile(f.File)
	if err != nil {
		return nil, fmt.Errorf("reading URL file: %w", err)
	}
	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			urls = append(urls, line)
		}
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs in %s", f.File)
	}
	return urls, nil
}

func generateEvidence(f cli.Flags, printer *cli.Printer, res cli.Result, rawURL string, headers map[string]string, now time.Time) cli.Result {
	slug := now.Format(timeSlug)
	domain := sanitizeDomain(rawURL)

	if err := os.MkdirAll(f.OutDir, 0o755); err != nil {
		printer.Warn("cannot create evidence directory: %v", err)
		return res
	}

	confirmedStatus, confirmedClass := finalStatusLabel(string(detect.ConfirmedFrameable))
	served := renderPoC(rawURL, domain, confirmedStatus, confirmedClass)

	server, err := serve.Start(served)
	if err != nil {
		printer.Warn("cannot serve PoC on loopback: %v", err)
	} else {
		defer server.Close()

		if !f.NoScreenshot {
			pngPath := filepath.Join(f.OutDir, domain+"_"+slug+".png")
			pending := pngPath + ".part"
			ev, err := browser.Screenshot(context.Background(), server.URL(), pending, browser.Options{
				Headers:   headers,
				TargetURL: rawURL,
				Delay:     f.ScreenshotDelay,
				Redirects: append(append([]string{}, res.Redirects...), res.FinalURL),
			})
			if err != nil {
				printer.Warn("screenshot unavailable: %v", err)
				res.Notes = append(res.Notes, "browser screenshot unavailable: "+err.Error())
				os.Remove(pending)
			} else {
				switch {
				case ev.FrameRefused:
					res.Notes = append(res.Notes, "browser refused to frame the target: "+ev.RefusalMessage)
				case ev.TargetLoaded:
					res.Classification = string(detect.ConfirmedFrameable)
					res.Notes = append(res.Notes, "browser validation: cross-origin framing of the target observed")
					if err := os.Rename(pending, pngPath); err != nil {
						printer.Warn("cannot keep screenshot evidence: %v", err)
					} else {
						res.ScreenshotFile = pngPath
					}
				default:
					res.Notes = append(res.Notes, "browser validation inconclusive: no target response observed")
				}
				if res.ScreenshotFile == "" {
					os.Remove(pending)
					res.Notes = append(res.Notes, "screenshot discarded: evidence is kept only for browser-validated framing")
				}
			}
		}
	}

	if f.Save || f.NoScreenshot {
		label, class := finalStatusLabel(res.Classification)
		final := renderPoC(rawURL, domain, label, class)
		htmlPath := filepath.Join(f.OutDir, domain+"_"+slug+".html")
		if err := os.WriteFile(htmlPath, final, 0o644); err != nil {
			printer.Warn("cannot save PoC HTML: %v", err)
		} else {
			res.HTMLFile = htmlPath
		}
	}
	return res
}

func renderPoC(rawURL, domain, status, class string) []byte {
	html, err := poc.Render(poc.Data{
		Description: cli.Description,
		Author:      "Cr0wtl3r",
		TargetURL:   rawURL,
		Domain:      domain,
		Status:      status,
		StatusClass: class,
	})
	if err != nil {
		panic(fmt.Sprintf("render PoC: %v", err))
	}
	return html
}

func finalStatusLabel(status string) (label, class string) {
	switch status {
	case string(detect.ConfirmedFrameable):
		return "CONFIRMED FRAMEABLE - cross-origin embedding validated in browser", "confirmed"
	case string(detect.Protected):
		return "PROTECTED - anti-framing headers in place", "protected"
	case string(detect.Inconclusive):
		return "INCONCLUSIVE - insufficient data", "inconclusive"
	default:
		return "POTENTIALLY VULNERABLE - framing not blocked by response headers (not validated in a browser)", "potential"
	}
}

func sanitizeDomain(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return strings.ReplaceAll(u.Host, ":", "_")
	}
	return strings.Map(func(r rune) rune {
		if r == '/' || r == ':' {
			return '_'
		}
		return r
	}, rawURL)
}

func appendFinding(rawURL string) {
	f, err := os.OpenFile(findingsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, rawURL)
}
