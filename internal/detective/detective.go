// Package detective turns findings into a case. It always concludes that
// it was DNS, and it always tells you what actually happened.
package detective

import (
	"fmt"
	"strings"

	"github.com/khimananda/its-always-dns/internal/checks"
	"github.com/khimananda/its-always-dns/internal/phrases"
)

// Verdict for one suspect.
type Verdict string

const (
	Cleared       Verdict = "cleared"
	Suspicious    Verdict = "suspicious"
	Guilty        Verdict = "guilty"
	NotQuestioned Verdict = "not questioned"
)

// Titles for each suspect, in interrogation order.
var Titles = map[checks.Suspect]string{
	checks.DNS:  "The Resolver",
	checks.TCP:  "The Network",
	checks.TLS:  "The Certificate",
	checks.HTTP: "The Application",
}

var order = []checks.Suspect{checks.DNS, checks.TCP, checks.TLS, checks.HTTP}

// Suspect is one layer and what was found about it.
type Suspect struct {
	Suspect     checks.Suspect   `json:"suspect"`
	Title       string           `json:"title"`
	Findings    []checks.Finding `json:"findings"`
	Verdict     Verdict          `json:"verdict"`
	VerdictLine string           `json:"verdict_line"`
}

// Case is the finished investigation.
type Case struct {
	Number     int            `json:"case_number"`
	Title      string         `json:"title"`
	Target     checks.Target  `json:"target"`
	Suspects   []Suspect      `json:"suspects"`
	Conclusion string         `json:"conclusion"`
	Evidence   []string       `json:"evidence"`
	Alibi      string         `json:"alibi,omitempty"`
	Culprit    checks.Suspect `json:"actual_culprit,omitempty"`
	Failures   int            `json:"failures"`
	Warnings   int            `json:"warnings"`
}

// Investigate builds the case. seed picks the case number and title.
func Investigate(r checks.Result, seed uint32) Case {
	titles := phrases.Titles()
	c := Case{
		Number:     1000 + int(seed%9000),
		Title:      phrases.Pick(titles, seed/9000),
		Target:     r.Target,
		Conclusion: "It was DNS.",
	}
	by := map[checks.Suspect][]checks.Finding{}
	for _, f := range r.Findings {
		by[f.Suspect] = append(by[f.Suspect], f)
		switch f.Severity {
		case checks.Fail:
			c.Failures++
		case checks.Warn:
			c.Warnings++
		}
	}
	for _, s := range order {
		fs := by[s]
		if len(fs) == 0 {
			continue
		}
		sp := Suspect{Suspect: s, Title: Titles[s], Findings: fs, Verdict: verdict(fs)}
		sp.VerdictLine = verdictLine(s, sp.Verdict)
		c.Suspects = append(c.Suspects, sp)
		if sp.Verdict == Guilty && c.Culprit == "" {
			c.Culprit = s
		}
	}

	switch {
	case c.Culprit == checks.DNS:
		c.Evidence = details(by[checks.DNS], checks.Fail)
	case c.Culprit != "":
		real := details(by[c.Culprit], checks.Fail)
		c.Alibi = fmt.Sprintf("The DNS would like you to know it has an alibi. %s did it: %s.", Titles[c.Culprit], real[0])
		c.Evidence = real
	case c.Warnings > 0:
		for _, s := range order {
			c.Evidence = append(c.Evidence, details(by[s], checks.Warn)...)
		}
	default:
		c.Evidence = []string{"none whatsoever. It was DNS anyway."}
	}
	return c
}

func verdict(fs []checks.Finding) Verdict {
	v, questioned := Cleared, false
	for _, f := range fs {
		if f.Check != "skipped" {
			questioned = true
		}
		switch f.Severity {
		case checks.Fail:
			return Guilty
		case checks.Warn:
			v = Suspicious
		}
	}
	if !questioned {
		return NotQuestioned
	}
	return v
}

func verdictLine(s checks.Suspect, v Verdict) string {
	switch {
	case s == checks.DNS && v == Cleared:
		return "Cleared. Allegedly."
	case s == checks.DNS && v == Guilty:
		return "Guilty. Obviously."
	case v == Cleared:
		return "Cleared."
	case v == Suspicious:
		return "Suspicious."
	case v == Guilty:
		return "Guilty."
	}
	return "Not questioned."
}

func details(fs []checks.Finding, sev checks.Severity) []string {
	var out []string
	for _, f := range fs {
		if f.Severity == sev {
			d := f.Detail
			if f.Check != "" && f.Check != "skipped" && f.Check != "handshake" {
				d = f.Check + ": " + d
			}
			out = append(out, strings.TrimSuffix(d, "."))
		}
	}
	return out
}
