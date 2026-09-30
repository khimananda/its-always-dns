// Package render prints a case as a detective story, a serious report, or JSON.
package render

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/khimananda/its-always-dns/internal/checks"
	"github.com/khimananda/its-always-dns/internal/detective"
)

// Options for rendering.
type Options struct {
	Version  string
	NoTiming bool // hide durations, for reproducible output
}

var (
	bold   = lipgloss.NewStyle().Bold(true)
	dim    = lipgloss.NewStyle().Faint(true)
	red    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	yellow = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	green  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	title  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
)

const checkCol = 21

// Narrative is the default output.
func Narrative(c detective.Case, o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n", title.Render(fmt.Sprintf("CASE #%d: %s", c.Number, c.Title)))
	fmt.Fprintf(&b, "  %s\n", dim.Render(fmt.Sprintf("Target %s   Investigator its-always-dns %s", hostPort(c.Target), o.Version)))
	for i, s := range c.Suspects {
		fmt.Fprintf(&b, "\n  %s\n", bold.Render(fmt.Sprintf("Suspect %d: %s", i+1, s.Title)))
		for _, f := range s.Findings {
			check := f.Check
			if len(check) > checkCol-1 {
				check = check[:checkCol-2] + "…"
			}
			line := fmt.Sprintf("    %-*s %s", checkCol, check, f.Detail)
			if t := timing(f.Duration, o); t != "" {
				line += dim.Render("  " + t)
			}
			fmt.Fprintln(&b, colorBy(f.Severity, line))
		}
		fmt.Fprintf(&b, "    %s %s\n", bold.Render("Verdict:"), verdictStyle(s.Verdict).Render(s.VerdictLine))
	}
	b.WriteString("\n  " + strings.Repeat("─", 44) + "\n")
	fmt.Fprintf(&b, "  %s\n\n", red.Render(c.Conclusion))
	if c.Alibi != "" {
		fmt.Fprintf(&b, "  %s\n\n", c.Alibi)
	}
	switch {
	case c.Alibi != "" && len(c.Evidence) == 1:
		// The alibi already names the evidence.
	case len(c.Evidence) == 1:
		fmt.Fprintf(&b, "  Evidence: %s\n", c.Evidence[0])
	default:
		b.WriteString("  Evidence:\n")
		for _, e := range c.Evidence {
			fmt.Fprintf(&b, "    - %s\n", e)
		}
	}
	fmt.Fprintf(&b, "  %s\n\n", dim.Render("Exit code 53. Use --serious for a boring report."))
	return b.String()
}

// Serious is a plain report for scripts and managers.
func Serious(c detective.Case, o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "its-always-dns %s report for %s\n\n", o.Version, hostPort(c.Target))
	for _, s := range c.Suspects {
		for _, f := range s.Findings {
			line := fmt.Sprintf("%-5s %-5s %-*s %s", strings.ToUpper(string(f.Suspect)), f.Severity, checkCol, f.Check, f.Detail)
			if t := timing(f.Duration, o); t != "" {
				line += " (" + t + ")"
			}
			b.WriteString(strings.TrimRight(line, " ") + "\n")
		}
	}
	fmt.Fprintf(&b, "\nResult: %d failures, %d warnings.", c.Failures, c.Warnings)
	switch {
	case c.Culprit != "":
		fmt.Fprintf(&b, " Most likely cause: %s: %s.\n", strings.ToUpper(string(c.Culprit)), c.Evidence[0])
	case c.Warnings > 0:
		fmt.Fprintf(&b, " Worth a look: %s.\n", c.Evidence[0])
	default:
		b.WriteString(" Everything checked out.\n")
	}
	return b.String()
}

type jsonFinding struct {
	checks.Finding
	DurationMS *float64 `json:"duration_ms,omitempty"`
}

// JSON renders the case with durations in milliseconds.
func JSON(c detective.Case, o Options) (string, error) {
	type suspect struct {
		detective.Suspect
		Findings []jsonFinding `json:"findings"`
	}
	type out struct {
		detective.Case
		Suspects []suspect `json:"suspects"`
		Version  string    `json:"version"`
	}
	v := out{Case: c, Version: o.Version}
	for _, s := range c.Suspects {
		js := suspect{Suspect: s}
		for _, f := range s.Findings {
			jf := jsonFinding{Finding: f}
			if f.Duration > 0 && !o.NoTiming {
				ms := float64(f.Duration.Microseconds()) / 1000
				jf.DurationMS = &ms
			}
			jf.Finding.Duration = 0
			js.Findings = append(js.Findings, jf)
		}
		v.Suspects = append(v.Suspects, js)
	}
	buf, err := json.MarshalIndent(v, "", "  ")
	return string(buf) + "\n", err
}

func timing(d time.Duration, o Options) string {
	if o.NoTiming || d <= 0 {
		return ""
	}
	if d < time.Millisecond {
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}

func hostPort(t checks.Target) string {
	if strings.Contains(t.Host, ":") {
		return fmt.Sprintf("[%s]:%d", t.Host, t.Port)
	}
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

func colorBy(s checks.Severity, line string) string {
	switch s {
	case checks.Fail:
		return red.Render(line)
	case checks.Warn:
		return yellow.Render(line)
	}
	return line
}

func verdictStyle(v detective.Verdict) lipgloss.Style {
	switch v {
	case detective.Guilty:
		return red
	case detective.Suspicious:
		return yellow
	case detective.Cleared:
		return green
	}
	return dim
}
