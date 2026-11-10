package detect

import (
	"net/http"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   Status
	}{
		{"xfo deny", hdr("X-Frame-Options", "DENY"), Protected},
		{"xfo sameorigin", hdr("X-Frame-Options", "SAMEORIGIN"), Protected},
		{"xfo lowercase with spaces", hdr("X-Frame-Options", "  deny  "), Protected},
		{"xfo allow-from obsolete", hdr("X-Frame-Options", "ALLOW-FROM https://evil.example"), PotentiallyVulnerable},
		{"xfo invalid value", hdr("X-Frame-Options", "GARBAGE"), PotentiallyVulnerable},
		{"csp frame-ancestors none", hdr("Content-Security-Policy", "frame-ancestors 'none'"), Protected},
		{"csp frame-ancestors self", hdr("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"), Protected},
		{"csp frame-ancestors hosts", hdr("Content-Security-Policy", "frame-ancestors trusted.example"), Protected},
		{"csp frame-ancestors wildcard is permissive", hdr("Content-Security-Policy", "frame-ancestors *"), PotentiallyVulnerable},
		{"csp wildcard with xfo deny: csp governs", hdr("Content-Security-Policy", "frame-ancestors *", "X-Frame-Options", "DENY"), PotentiallyVulnerable},
		{"csp restrictive with xfo deny", hdr("Content-Security-Policy", "frame-ancestors 'none'", "X-Frame-Options", "DENY"), Protected},
		{"report-only only is not protection", hdr("Content-Security-Policy-Report-Only", "frame-ancestors 'none'"), PotentiallyVulnerable},
		{"no headers", hdr(), PotentiallyVulnerable},
		{"bare frame-ancestors is invalid", hdr("Content-Security-Policy", "frame-ancestors"), PotentiallyVulnerable},
		{"multiple policies any-block wins", hdr("Content-Security-Policy", "frame-ancestors *, frame-ancestors 'none'"), Protected},
		{"policy without frame-ancestors ignored", hdr("Content-Security-Policy", "default-src 'self'"), PotentiallyVulnerable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.header)
			if got.Status != tt.want {
				t.Errorf("Classify() = %q, want %q (notes: %v)", got.Status, tt.want, got.Notes)
			}
		})
	}
}

func TestClassifyNotesEvidence(t *testing.T) {
	got := Classify(hdr("X-Frame-Options", "ALLOW-FROM https://x", "Content-Security-Policy-Report-Only", "frame-ancestors 'none'"))
	joined := strings.Join(got.Notes, "\n")
	for _, want := range []string{"ALLOW-FROM is obsolete", "Report-Only"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes missing %q: %v", want, got.Notes)
		}
	}
	if got.XFO != "ALLOW-FROM https://x" {
		t.Errorf("XFO evidence = %q", got.XFO)
	}
}

func TestFrameAncestorsBlocks(t *testing.T) {
	src, present, blocks := frameAncestors([]string{"frame-ancestors 'self' https://a.example"})
	if !present || !blocks || src == "" {
		t.Errorf("frameAncestors() = (%q, %v, %v), want present+blocks", src, present, blocks)
	}
}
