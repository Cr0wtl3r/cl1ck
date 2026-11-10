package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	primary = "\x1b[38;2;185;28;28m"   // #B91C1C
	accent  = "\x1b[38;2;239;68;68m"   // #EF4444
	text    = "\x1b[38;2;229;231;235m" // #E5E7EB
	dim     = "\x1b[38;2;69;10;10m"    // #450A0A
	reset   = "\x1b[0m"
)

const Description = "Clickjacking Layer Inspection & Confirmation Kit"

const brandArt = `  ██████╗██████╗  ██████╗ ██╗    ██╗████████╗██╗     ██████╗ ██████╗
 ██╔════╝██╔══██╗██╔═████╗██║    ██║╚══██╔══╝██║     ╚════██╗██╔══██╗
 ██║     ██████╔╝██║██╔██║██║ █╗ ██║   ██║   ██║      █████╔╝██████╔╝
 ██║     ██╔══██╗████╔╝██║██║███╗██║   ██║   ██║      ╚═══██╗██╔══██╗
 ╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝   ██║   ███████╗██████╔╝██║  ██║
  ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝    ╚═╝   ╚══════╝╚═════╝ ╚═╝  ╚═╝`

const toolArt = ` ██████╗██╗      ██╗ ██████╗██╗  ██╗
██╔════╝██║     ████╗██╔════╝██║ ██╔╝
██║     ██║       ██║██║     █████╔╝
██║     ██║       ██║██║     ██╔═██╗
╚██████╗█████████╗  ██║╚██████╗██║  ██╗
 ╚═════╝╚══════╝  ╚═╝ ╚═════╝╚═╝  ╚═╝`

func ColorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func Banner() string {
	return buildBanner(brandArt, toolArt, Description, ColorEnabled())
}

func charWidth(s string) int { return utf8.RuneCountInString(s) }

func maxWidth(arts ...string) int {
	width := 0
	for _, art := range arts {
		for _, line := range strings.Split(art, "\n") {
			if w := charWidth(line); w > width {
				width = w
			}
		}
	}
	return width
}

func center(s string, width int) string {
	gap := (width - charWidth(s)) / 2
	if gap < 0 {
		gap = 0
	}
	return strings.Repeat(" ", gap) + s
}

func paint(s, color string, enabled bool) string {
	if !enabled {
		return s
	}
	return color + s + reset
}

func buildBanner(brand, tool, description string, useColor bool) string {
	width := maxWidth(brand, tool)
	lines := make([]string, 0, 20)
	for _, line := range strings.Split(brand, "\n") {
		lines = append(lines, paint(center(line, width), primary, useColor))
	}
	lines = append(lines, "")
	for _, line := range strings.Split(tool, "\n") {
		lines = append(lines, paint(center(line, width), accent, useColor))
	}
	lines = append(lines, "")
	lines = append(lines, paint(center(description, width), text, useColor))
	lines = append(lines, paint(fmt.Sprintf("%*s", width, "By: Cr0wtl3r"), text, useColor))
	lines = append(lines, paint(strings.Repeat("━", width), dim, useColor))
	return strings.Join(lines, "\n") + "\n"
}

func PrintBanner(w io.Writer) {
	io.WriteString(w, "\n"+Banner())
}
