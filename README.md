# cl1ck

**Clickjacking Layer Inspection & Confirmation Kit** — by Cr0wtl3r.

CLI that scans targets for clickjacking exposure, classifies them honestly
(`PROTECTED` / `POTENTIALLY_VULNERABLE` / `CONFIRMED_FRAMEABLE` /
`INCONCLUSIVE`), generates a self-contained HTML PoC and validates cross-origin
framing in a real browser, saving screenshot evidence.

## Build

```sh
make build        # produces ./cl1ck
make check        # go vet + go test
make test-browser # browser integration tests (needs Chromium/Chrome)
```

Requires Go 1.27+. A Chromium/Chrome binary is needed only for screenshot
evidence (`CLICK_BROWSER_PATH` overrides browser discovery); without one the
scan continues and skips screenshots with a warning.

## Usage

```sh
cl1ck -u https://example.com
cl1ck -f urls.txt -H "Cookie: sess=abc123"
cl1ck -u https://example.com --save --json
```

| Flag                       | Meaning                                                           |
| -------------------------- | ----------------------------------------------------------------- |
| `-u <url>`                 | single target (mutually exclusive with `-f`)                      |
| `-f <file>`                | target list, one URL per line                                     |
| `-H, --header "K: V"`      | custom HTTP header (repeatable; applied to fetch **and** browser) |
| `--no-screenshot`          | skip browser stage; persists the PoC HTML only                    |
| `--save`                   | also persist the PoC HTML file                                    |
| `--json`                   | JSON report for all targets on stdout (progress goes to stderr)   |
| `--out <dir>`              | evidence directory (default `evidencias`)                         |
| `--timeout <dur>`          | per-request timeout (default 10s)                                 |
| `--screenshot-delay <dur>` | delay before screenshot so the framed app can load (default 2s)   |

## Output

- `evidencias/{domain}_{timestamp}.png` — screenshot of the PoC, kept only when browser validation confirms cross-origin framing (graceful degradation without a browser)
- `evidencias/{domain}_{timestamp}.html` — PoC page (`--save` or `--no-screenshot`)
- `url_with_clickjacking.txt` — append-only list of frameable URLs (in the CWD)

## Classification model

Absence of anti-framing headers is **never** reported as confirmed exploitation.
Only a real browser rendering the target cross-origin promotes a finding to
`CONFIRMED FRAMEABLE`. `frame-ancestors *` and obsolete `X-Frame-Options:
ALLOW-FROM` are treated as no effective protection; enforced CSP
`frame-ancestors` governs over `X-Frame-Options` (modern browser semantics).
