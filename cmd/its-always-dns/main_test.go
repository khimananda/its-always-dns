package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/khimananda/its-always-dns/internal/checks"
)

// A target given as an IP skips DNS, so these tests need no resolver.
func server(t *testing.T) (string, defaultsFunc) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	defaults := func(timeout time.Duration, _ []string) checks.Options {
		return checks.Options{Timeout: timeout, RootCAs: pool, NoAuth: true}
	}
	return "https://" + s.Listener.Addr().String() + "/", defaults
}

func run(t *testing.T, d defaultsFunc, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := newRoot(&out, d)
	cmd.SetArgs(args)
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	return out.String(), err
}

func code(err error) int {
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if err != nil {
		return 1
	}
	return 0
}

func TestNarrativeAlwaysExits53(t *testing.T) {
	url, d := server(t)
	out, err := run(t, d, url, "--no-color")
	if code(err) != 53 || !strings.Contains(out, "It was DNS.") {
		t.Errorf("exit %d, output:\n%s", code(err), out)
	}
}

func TestSeriousExitCodes(t *testing.T) {
	url, d := server(t)
	if out, err := run(t, d, url, "--serious"); code(err) != 0 || !strings.Contains(out, "Everything checked out") {
		t.Errorf("healthy target: exit %d\n%s", code(err), out)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	out, err := run(t, d, "127.0.0.1:"+strconv.Itoa(port), "--serious", "--timeout", "1s")
	if code(err) != 1 || !strings.Contains(out, "Most likely cause: TCP") {
		t.Errorf("closed port: exit %d\n%s", code(err), out)
	}
}

func TestJSON(t *testing.T) {
	url, d := server(t)
	out, err := run(t, d, url, "--json", "--serious")
	if code(err) != 0 {
		t.Fatalf("exit %d", code(err))
	}
	var v struct {
		Conclusion string `json:"conclusion"`
		Suspects   []struct {
			Suspect string `json:"suspect"`
		} `json:"suspects"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.Conclusion != "It was DNS." || len(v.Suspects) != 4 {
		t.Errorf("err %v, %+v\n%s", err, v, out)
	}
}

func TestSubcommands(t *testing.T) {
	if out, _ := run(t, nil, "haiku"); !strings.HasSuffix(strings.TrimSpace(out), "It was DNS.") {
		t.Errorf("haiku: %q", out)
	}
	if out, _ := run(t, nil, "why", "--all"); !strings.Contains(out, "ndots:5") || !strings.Contains(out, "Negative caching") {
		t.Errorf("why --all: %q", out)
	}
}

func TestBadInput(t *testing.T) {
	if _, err := run(t, nil, "ftp://example.com"); err == nil || code(err) == 53 {
		t.Errorf("unsupported scheme should be a plain error, got %v", err)
	}
}
