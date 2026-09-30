package render

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	c "github.com/khimananda/its-always-dns/internal/checks"
	"github.com/khimananda/its-always-dns/internal/detective"
)

var update = flag.Bool("update", false, "rewrite golden files")

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func cases() map[string]detective.Case {
	tg := c.Target{Host: "api.example.com", Port: 443, Scheme: "https", URL: "https://api.example.com/"}
	dnsOK := []c.Finding{
		{Suspect: c.DNS, Check: "resolv.conf", Detail: "nameserver 10.96.0.10, search svc.cluster.local cluster.local, ndots:5", Severity: c.OK},
		{Suspect: c.DNS, Check: "ndots", Detail: "ndots:5 with 2 search domains: api.example.com tries 2 wrong names before the real one. Add a trailing dot or lower ndots", Severity: c.Warn},
		{Suspect: c.DNS, Check: "system lookup", Detail: "api.example.com -> 203.0.113.10", Severity: c.OK, Duration: ms(412)},
		{Suspect: c.DNS, Check: "1.1.1.1", Detail: "203.0.113.10 (TTL 300)", Severity: c.OK, Duration: ms(9)},
		{Suspect: c.DNS, Check: "authoritative", Detail: "203.0.113.10 (TTL 300) from ns1.example.com", Severity: c.OK, Duration: ms(31)},
	}
	tcpOK := c.Finding{Suspect: c.TCP, Check: "connect", Detail: "203.0.113.10:443 connected", Severity: c.OK, Duration: ms(18)}
	expired := detective.Investigate(c.Result{Target: tg, Findings: append(append([]c.Finding{}, dnsOK...), tcpOK,
		c.Finding{Suspect: c.TLS, Check: "handshake", Detail: "certificate expired 3 days ago (2026-09-27)", Severity: c.Fail, Duration: ms(40)},
		c.Finding{Suspect: c.HTTP, Check: "skipped", Detail: "not questioned: the TLS handshake failed first", Severity: c.Info},
	)}, 4173)
	nx := detective.Investigate(c.Result{Target: tg, Findings: []c.Finding{
		{Suspect: c.DNS, Check: "system lookup", Detail: "api.example.com does not exist (NXDOMAIN or no records)", Severity: c.Fail, Duration: ms(22)},
		{Suspect: c.DNS, Check: "1.1.1.1", Detail: "NXDOMAIN: this resolver says the name does not exist", Severity: c.Fail, Duration: ms(8)},
		{Suspect: c.TCP, Check: "skipped", Detail: "not questioned: DNS gave us no address to call", Severity: c.Info},
	}}, 99)
	clean := detective.Investigate(c.Result{Target: tg, Findings: []c.Finding{
		{Suspect: c.DNS, Check: "system lookup", Detail: "api.example.com -> 203.0.113.10", Severity: c.OK, Duration: ms(3)},
		tcpOK,
		{Suspect: c.TLS, Check: "handshake", Detail: "CN api.example.com, issued by Let's Encrypt, expires in 41 days, TLS 1.3", Severity: c.OK, Duration: ms(35)},
		{Suspect: c.HTTP, Check: "GET /", Detail: "200 OK, server nginx", Severity: c.OK, Duration: ms(96)},
	}}, 7)
	return map[string]detective.Case{"expired": expired, "nxdomain": nx, "clean": clean}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("missing golden file, run go test ./... -update: %v", err)
	}
	if got != string(want) {
		t.Errorf("%s differs.\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestGolden(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	o := Options{Version: "1.0.0"}
	for name, cs := range cases() {
		t.Run(name, func(t *testing.T) {
			golden(t, name+".txt", Narrative(cs, o))
			golden(t, name+".serious.txt", Serious(cs, o))
			js, err := JSON(cs, o)
			if err != nil {
				t.Fatal(err)
			}
			var back map[string]any
			if err := json.Unmarshal([]byte(js), &back); err != nil {
				t.Fatal(err)
			}
			golden(t, name+".json", js)
		})
	}
}

func TestNoTimingHidesDurations(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	out := Narrative(cases()["clean"], Options{NoTiming: true})
	for _, s := range []string{" ms", "<1 ms"} {
		if contains(out, s) {
			t.Errorf("--no-timing output contains %q", s)
		}
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
