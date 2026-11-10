package main

import (
	"testing"

	"github.com/Cr0wtl3r/cl1ck/internal/cli"
	"github.com/Cr0wtl3r/cl1ck/internal/detect"
)

func TestIsRedundantMissingNote(t *testing.T) {
	const note = "no X-Frame-Options and no enforced CSP frame-ancestors"
	if !isRedundantMissingNote(note, cli.Result{}) {
		t.Error("note should be redundant when both headers are missing")
	}
	if isRedundantMissingNote(note, cli.Result{CSP: "default-src 'self'"}) {
		t.Error("note should not be redundant when a CSP is present")
	}
}

func TestCountFindingsUsesFinalClassification(t *testing.T) {
	results := []cli.Result{
		{Classification: string(detect.ConfirmedFrameable)},
		{Classification: string(detect.PotentiallyVulnerable)},
		{Classification: string(detect.Protected)},
		{Classification: string(detect.Inconclusive)},
	}
	confirmed, potential := countFindings(results)
	if confirmed != 1 || potential != 1 {
		t.Errorf("countFindings() = (%d, %d), want (1, 1)", confirmed, potential)
	}
}
