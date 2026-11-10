package detect

import (
	"net/http"
	"strings"
)

type Status string

const (
	Protected             Status = "PROTECTED"
	PotentiallyVulnerable Status = "POTENTIALLY_VULNERABLE"
	ConfirmedFrameable    Status = "CONFIRMED_FRAMEABLE"
	Inconclusive          Status = "INCONCLUSIVE"
)

type Result struct {
	Status Status   `json:"status"`
	XFO    string   `json:"x_frame_options,omitempty"`
	CSP    string   `json:"content_security_policy,omitempty"`
	Notes  []string `json:"notes,omitempty"`
}

func Classify(h http.Header) Result {
	res := Result{Status: PotentiallyVulnerable}
	xfo := strings.TrimSpace(h.Get("X-Frame-Options"))
	csp := strings.TrimSpace(h.Get("Content-Security-Policy"))
	ro := strings.TrimSpace(h.Get("Content-Security-Policy-Report-Only"))
	res.XFO = xfo
	res.CSP = csp

	if ro != "" {
		res.Notes = append(res.Notes, "Content-Security-Policy-Report-Only present (informational, not enforced)")
	}

	src, present, blocks := frameAncestors(h.Values("Content-Security-Policy"))
	if present {
		if blocks {
			res.Status = Protected
			res.Notes = append(res.Notes, "CSP frame-ancestors blocks cross-origin framing: "+src)
			if xfo != "" {
				res.Notes = append(res.Notes, "X-Frame-Options ignored where frame-ancestors is enforced: "+xfo)
			}
			return res
		}
		res.Notes = append(res.Notes, "CSP frame-ancestors is permissive: "+src)
		if xfo != "" {
			res.Notes = append(res.Notes, "X-Frame-Options overridden by frame-ancestors in modern browsers (would apply only to legacy browsers): "+xfo)
		}
		return res
	}

	switch v := normalizeXFO(xfo); v {
	case "deny", "sameorigin":
		res.Status = Protected
		res.Notes = append(res.Notes, "X-Frame-Options: "+v+" blocks cross-origin framing")
	case "":
		res.Notes = append(res.Notes, "no X-Frame-Options and no enforced CSP frame-ancestors")
	default:
		if strings.HasPrefix(v, "allow-from") {
			res.Notes = append(res.Notes, "X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers: "+xfo)
		} else {
			res.Notes = append(res.Notes, "X-Frame-Options has unrecognized value: "+xfo)
		}
	}
	return res
}

func frameAncestors(values []string) (src string, present bool, blocks bool) {
	permissive := false
	for _, value := range values {
		for _, policy := range splitPolicies(value) {
			for _, directive := range strings.Split(policy, ";") {
				fields := strings.Fields(directive)
				if len(fields) == 0 || !strings.EqualFold(fields[0], "frame-ancestors") {
					continue
				}
				sources := fields[1:]
				if len(sources) == 0 {
					continue
				}
				present = true
				src = strings.TrimSpace(directive)
				if blocks {
					continue
				}
				if isPermissive(sources) {
					permissive = true
				} else {
					blocks = true
				}
			}
		}
	}
	if !blocks && permissive {
		blocks = false
	}
	return src, present, blocks
}

func splitPolicies(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isPermissive(sources []string) bool {
	for _, s := range sources {
		if s == "*" {
			return true
		}
	}
	return false
}

func normalizeXFO(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexAny(v, ";,"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return strings.Join(strings.Fields(v), " ")
}
