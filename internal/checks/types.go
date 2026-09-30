// Package checks runs the real network diagnostics. Each check returns
// findings; the detective package turns them into a story.
package checks

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Severity of a finding.
type Severity int

const (
	OK Severity = iota
	Info
	Warn
	Fail
)

func (s Severity) String() string {
	return [...]string{"ok", "info", "warn", "fail"}[s]
}

// MarshalText makes severities readable in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Suspect names the layer a finding belongs to.
type Suspect string

const (
	DNS  Suspect = "dns"
	TCP  Suspect = "tcp"
	TLS  Suspect = "tls"
	HTTP Suspect = "http"
)

// Finding is one observed fact.
type Finding struct {
	Suspect  Suspect       `json:"suspect"`
	Check    string        `json:"check"`
	Detail   string        `json:"detail"`
	Severity Severity      `json:"severity"`
	Duration time.Duration `json:"duration_ns,omitempty"`
}

// Target is what the user asked about.
type Target struct {
	Raw    string `json:"raw"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme,omitempty"` // https, http, or empty for plain TCP
	URL    string `json:"url,omitempty"`
	IsIP   bool   `json:"is_ip"`
}

// ParseTarget accepts a host, host:port, or URL. port overrides when > 0.
func ParseTarget(raw string, port int) (Target, error) {
	t := Target{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		return t, fmt.Errorf("no target given")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return t, fmt.Errorf("%q is not a valid URL", raw)
		}
		t.Scheme = strings.ToLower(u.Scheme)
		if t.Scheme != "http" && t.Scheme != "https" {
			return t, fmt.Errorf("unsupported scheme %q: use http or https", u.Scheme)
		}
		t.Host = u.Hostname()
		t.Port = map[string]int{"http": 80, "https": 443}[t.Scheme]
		if p := u.Port(); p != "" {
			t.Port, _ = strconv.Atoi(p)
		}
	} else {
		t.Host, t.Port = s, 443
		if h, p, err := net.SplitHostPort(s); err == nil {
			t.Host = h
			if t.Port, err = strconv.Atoi(p); err != nil {
				return t, fmt.Errorf("invalid port in %q", raw)
			}
		}
	}
	if port > 0 {
		t.Port = port
	}
	if t.Port < 1 || t.Port > 65535 {
		return t, fmt.Errorf("port %d is out of range", t.Port)
	}
	if t.Scheme == "" {
		switch t.Port {
		case 443, 8443:
			t.Scheme = "https"
		case 80, 8080:
			t.Scheme = "http"
		}
	}
	t.Host = strings.TrimSuffix(strings.Trim(t.Host, "[]"), ".")
	t.IsIP = net.ParseIP(t.Host) != nil
	if t.Scheme != "" {
		hostPort := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
		if (t.Scheme == "https" && t.Port == 443) || (t.Scheme == "http" && t.Port == 80) {
			hostPort = t.Host
			if strings.Contains(t.Host, ":") {
				hostPort = "[" + t.Host + "]"
			}
		}
		path := "/"
		if u, err := url.Parse(s); err == nil && strings.Contains(s, "://") && u.RequestURI() != "" {
			path = u.RequestURI()
		}
		t.URL = t.Scheme + "://" + hostPort + path
	}
	return t, nil
}
