package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	f, err := Parse([]string{"-u", "https://x.example", "-H", "Cookie: a=1", "--header", "UA: t", "--save", "--json"})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if f.URL != "https://x.example" || !f.Save || !f.JSON {
		t.Errorf("flags = %+v", f)
	}
	if len(f.Headers) != 2 {
		t.Errorf("Headers = %v", f.Headers)
	}
	if f.OutDir != "evidencias" {
		t.Errorf("OutDir = %q", f.OutDir)
	}
	if f.ScreenshotDelay != 2*time.Second {
		t.Errorf("ScreenshotDelay = %v", f.ScreenshotDelay)
	}
}

func TestParseRequiresExactlyOneSource(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("no source: expected error")
	}
	if _, err := Parse([]string{"-u", "a", "-f", "b"}); err == nil {
		t.Error("both sources: expected error")
	}
}

func TestParseHeaders(t *testing.T) {
	h, warnings := ParseHeaders([]string{"Cookie: sess=abc", "bad-header", "  X-Test : v  "})
	if h["Cookie"] != "sess=abc" || h["X-Test"] != "v" {
		t.Errorf("headers = %v", h)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestMaskHeaderValue(t *testing.T) {
	if got := MaskHeaderValue("short"); got != "short" {
		t.Errorf("short value masked: %q", got)
	}
	long := strings.Repeat("a", 40)
	if got := MaskHeaderValue(long); len(got) != 30 || !strings.HasSuffix(got, "...") {
		t.Errorf("long value not masked: %q", got)
	}
}

func TestBannerSnapshotPlain(t *testing.T) {
	got := buildBanner(brandArt, toolArt, Description, false)
	bannerLines := map[string]bool{}
	for _, l := range strings.Split(got, "\n") {
		bannerLines[strings.TrimSpace(l)] = true
	}
	for _, art := range []string{brandArt, toolArt} {
		for _, l := range strings.Split(art, "\n") {
			if !bannerLines[strings.TrimSpace(l)] {
				t.Errorf("banner missing art line %q", l)
			}
		}
	}
	for _, want := range []string{Description, "By: Cr0wtl3r"} {
		if !strings.Contains(got, want) {
			t.Errorf("banner missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Error("plain banner contains ANSI escapes")
	}
}

func TestBannerColor(t *testing.T) {
	got := buildBanner(brandArt, toolArt, Description, true)
	if !strings.Contains(got, primary) || !strings.Contains(got, accent) {
		t.Error("colored banner missing identity palette codes")
	}
}

func TestPrinterStatusColors(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Color: true}
	p.Status("CONFIRMED_FRAMEABLE")
	if !strings.Contains(buf.String(), ansiRed) {
		t.Errorf("confirmed status not red: %q", buf.String())
	}
}

func TestPrinterSummaryCounts(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Color: false}
	p.Summary(1, 1, "url_with_clickjacking.txt")
	out := buf.String()
	if !strings.Contains(out, "Found 1 confirmed frameable application(s)") {
		t.Errorf("summary missing confirmed count: %q", out)
	}
	if !strings.Contains(out, "Found 1 potentially frameable application(s)") {
		t.Errorf("summary missing potential count: %q", out)
	}
	buf.Reset()
	p.Summary(1, 0, "url_with_clickjacking.txt")
	if strings.Contains(buf.String(), "potentially frameable") {
		t.Errorf("confirmed-only summary mentions potential: %q", buf.String())
	}
	buf.Reset()
	p.Summary(0, 0, "url_with_clickjacking.txt")
	if !strings.Contains(buf.String(), "No frameable applications found.") {
		t.Errorf("empty summary = %q", buf.String())
	}
}

func TestPrinterHeaderLines(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Color: false}
	p.Progress(1, 1, "https://target.example")
	p.HeaderMissing("X-Frame-Options")
	p.HeaderPresent("Content-Security-Policy", "frame-ancestors 'none'")
	out := buf.String()
	for _, want := range []string{
		"[*] [1/1] Analyzing headers of https://target.example",
		"[!] Security header missing: X-Frame-Options",
		"[*] Header Content-Security-Policy is present! (Value: frame-ancestors 'none')",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %q", want, out)
		}
	}
}

func TestPrinterEvidenceHighlight(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{W: &buf, Color: true}
	p.Evidence("CONFIRMED_FRAMEABLE", "cross-origin framing observed")
	out := buf.String()
	if !strings.Contains(out, ansiBold+ansiRed) || !strings.Contains(out, "[!]") {
		t.Errorf("confirmed evidence not highlighted: %q", out)
	}
	buf.Reset()
	p.Evidence("POTENTIALLY_VULNERABLE", "no X-Frame-Options")
	if !strings.Contains(buf.String(), ansiBold+ansiYellow) {
		t.Errorf("potential evidence not yellow: %q", buf.String())
	}
}
