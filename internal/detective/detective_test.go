package detective

import (
	"strings"
	"testing"

	c "github.com/khimananda/its-always-dns/internal/checks"
)

func result(fs ...c.Finding) c.Result {
	return c.Result{Target: c.Target{Host: "api.example.com", Port: 443, Scheme: "https"}, Findings: fs}
}

func f(s c.Suspect, check, detail string, sev c.Severity) c.Finding {
	return c.Finding{Suspect: s, Check: check, Detail: detail, Severity: sev}
}

func TestAllClearStillBlamesDNS(t *testing.T) {
	cs := Investigate(result(f(c.DNS, "system lookup", "ok", c.OK), f(c.TCP, "connect", "ok", c.OK)), 42)
	if cs.Conclusion != "It was DNS." || cs.Culprit != "" {
		t.Errorf("%+v", cs)
	}
	if cs.Suspects[0].VerdictLine != "Cleared. Allegedly." {
		t.Errorf("DNS is never simply cleared: %q", cs.Suspects[0].VerdictLine)
	}
	if !strings.Contains(cs.Evidence[0], "It was DNS anyway") {
		t.Errorf("evidence %v", cs.Evidence)
	}
}

func TestRealCulpritGetsAnAlibi(t *testing.T) {
	cs := Investigate(result(
		f(c.DNS, "system lookup", "ok", c.OK),
		f(c.TCP, "connect", "ok", c.OK),
		f(c.TLS, "handshake", "certificate expired 3 days ago", c.Fail),
		f(c.HTTP, "skipped", "not questioned: the TLS handshake failed first", c.Info),
	), 1)
	if cs.Culprit != c.TLS || cs.Conclusion != "It was DNS." {
		t.Errorf("%+v", cs)
	}
	want := "The DNS would like you to know it has an alibi. The Certificate did it: certificate expired 3 days ago."
	if cs.Alibi != want {
		t.Errorf("alibi %q", cs.Alibi)
	}
	if cs.Suspects[3].Verdict != NotQuestioned {
		t.Errorf("skipped HTTP should be not questioned, got %s", cs.Suspects[3].Verdict)
	}
}

func TestDNSGuilty(t *testing.T) {
	cs := Investigate(result(f(c.DNS, "system lookup", "api.example.com does not exist", c.Fail)), 1)
	if cs.Culprit != c.DNS || cs.Alibi != "" || cs.Suspects[0].VerdictLine != "Guilty. Obviously." {
		t.Errorf("%+v", cs)
	}
	if cs.Evidence[0] != "system lookup: api.example.com does not exist" {
		t.Errorf("evidence %v", cs.Evidence)
	}
}

func TestWarningsBecomeEvidence(t *testing.T) {
	cs := Investigate(result(f(c.DNS, "ndots", "ndots:5 hurts", c.Warn), f(c.TLS, "handshake", "expires in 5 days", c.Warn)), 1)
	if cs.Culprit != "" || len(cs.Evidence) != 2 || cs.Warnings != 2 {
		t.Errorf("%+v", cs)
	}
}

func TestSeedIsStable(t *testing.T) {
	a, b := Investigate(result(), 7), Investigate(result(), 7)
	if a.Number != b.Number || a.Title != b.Title || a.Number < 1000 || a.Number > 9999 {
		t.Errorf("%d %q vs %d %q", a.Number, a.Title, b.Number, b.Title)
	}
}
