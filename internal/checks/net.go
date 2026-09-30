package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SlowHTTP is when the application starts to look suspicious.
const SlowHTTP = 2 * time.Second

// ExpiringSoon is when a certificate earns a warning.
const ExpiringSoon = 14 * 24 * time.Hour

func skipped(s Suspect, why string) []Finding {
	return []Finding{{Suspect: s, Check: "skipped", Detail: why, Severity: Info}}
}

// CheckTCP connects to the first address that works. It returns that
// address as host:port, or "" when nothing connected.
func CheckTCP(ctx context.Context, t Target, ips []string, o Options) (string, []Finding) {
	if len(ips) == 0 {
		return "", skipped(TCP, "not questioned: DNS gave us no address to call")
	}
	var fs []Finding
	for i, ip := range ips {
		if i == 2 {
			break // two attempts is enough for a story
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(t.Port))
		dial := addr
		if o.DialAddress != "" {
			dial = o.DialAddress
		}
		start := time.Now()
		d := net.Dialer{Timeout: o.Timeout}
		conn, err := d.DialContext(ctx, "tcp", dial)
		took := time.Since(start)
		if err == nil {
			conn.Close()
			fs = append(fs, Finding{Suspect: TCP, Check: "connect", Detail: addr + " connected", Severity: OK, Duration: took})
			return dial, fs
		}
		fs = append(fs, Finding{Suspect: TCP, Check: "connect", Detail: addr + " " + shortNetErr(err), Severity: Fail, Duration: took})
	}
	return "", fs
}

// CheckTLS performs a handshake and inspects the certificate.
func CheckTLS(ctx context.Context, t Target, addr string, o Options, now time.Time) (bool, []Finding) {
	if t.Scheme != "https" {
		return false, nil
	}
	if addr == "" {
		return false, skipped(TLS, "not questioned: nothing to shake hands with")
	}
	cfg := &tls.Config{ServerName: t.Host, RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: o.Timeout}, Config: cfg}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	took := time.Since(start)
	if err == nil {
		defer conn.Close()
		st := conn.(*tls.Conn).ConnectionState()
		leaf := st.PeerCertificates[0]
		left := leaf.NotAfter.Sub(now)
		sev := OK
		if left < ExpiringSoon {
			sev = Warn
		}
		detail := fmt.Sprintf("%s, issued by %s, expires in %d days, %s",
			certName(leaf), issuer(leaf), int(left.Hours()/24), tls.VersionName(st.Version))
		return true, []Finding{{Suspect: TLS, Check: "handshake", Detail: detail, Severity: sev, Duration: took}}
	}
	return false, []Finding{{Suspect: TLS, Check: "handshake", Detail: describeTLSErr(ctx, err, t, addr, o, now), Severity: Fail, Duration: took}}
}

func describeTLSErr(ctx context.Context, err error, t Target, addr string, o Options, now time.Time) string {
	var inv x509.CertificateInvalidError
	var host x509.HostnameError
	var unk x509.UnknownAuthorityError
	var verr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		// Look again without verification to say how long ago.
		if leaf := peek(ctx, t, addr, o); leaf != nil {
			return fmt.Sprintf("certificate expired %d days ago (%s)", int(now.Sub(leaf.NotAfter).Hours()/24), leaf.NotAfter.Format("2006-01-02"))
		}
		return "certificate expired"
	case errors.As(err, &host):
		return fmt.Sprintf("certificate is for %s, not %s", strings.Join(certNames(host.Certificate), ", "), t.Host)
	case errors.As(err, &unk):
		return "certificate is signed by an authority nobody trusts (self-signed or missing intermediate)"
	case errors.As(err, &verr):
		return "certificate rejected: " + verr.Err.Error()
	}
	return "handshake failed: " + shortNetErr(err)
}

func peek(ctx context.Context, t Target, addr string, o Options) *x509.Certificate {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: o.Timeout},
		Config: &tls.Config{ServerName: t.Host, InsecureSkipVerify: true}} // #nosec G402 -- only to describe a cert that already failed verification
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

// CheckHTTP sends one GET to the address TCP connected to. Redirects are
// reported, not followed.
func CheckHTTP(ctx context.Context, t Target, addr string, tlsOK bool, o Options) []Finding {
	if t.Scheme == "" {
		return nil
	}
	switch {
	case addr == "":
		return skipped(HTTP, "not questioned: could not reach the server")
	case t.Scheme == "https" && !tlsOK:
		return skipped(HTTP, "not questioned: the TLS handshake failed first")
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: o.Timeout}).DialContext(ctx, network, addr)
		},
		TLSClientConfig:   &tls.Config{ServerName: t.Host, RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: o.Timeout * 2,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return []Finding{{Suspect: HTTP, Check: "GET", Detail: err.Error(), Severity: Fail}}
	}
	req.Header.Set("User-Agent", "its-always-dns (+https://github.com/khimananda/its-always-dns)")
	start := time.Now()
	resp, err := client.Do(req)
	took := time.Since(start)
	if err != nil {
		return []Finding{{Suspect: HTTP, Check: "GET " + reqPath(t.URL), Detail: shortNetErr(err), Severity: Fail, Duration: took}}
	}
	resp.Body.Close()
	detail := resp.Status
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		detail += " -> " + loc
	}
	if s := resp.Header.Get("Server"); s != "" {
		detail += ", server " + s
	}
	sev := OK
	switch {
	case resp.StatusCode >= 500:
		sev = Fail
	case resp.StatusCode >= 400:
		sev = Info // a 404 or 401 is still an answer
	case took > SlowHTTP:
		sev = Warn
	}
	return []Finding{{Suspect: HTTP, Check: "GET " + reqPath(t.URL), Detail: detail, Severity: sev, Duration: took}}
}

func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return "CN " + c.Subject.CommonName
	}
	if len(c.DNSNames) > 0 {
		return "SAN " + c.DNSNames[0]
	}
	return "unnamed certificate"
}

func certNames(c *x509.Certificate) []string {
	if c == nil {
		return []string{"another name"}
	}
	names := c.DNSNames
	if len(names) == 0 && c.Subject.CommonName != "" {
		names = []string{c.Subject.CommonName}
	}
	if len(names) > 3 {
		names = append(names[:3], fmt.Sprintf("and %d more", len(names)-3))
	}
	return names
}

func issuer(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return "an unnamed issuer"
}

func reqPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.Index(u[i+3:], "/"); j >= 0 {
			return u[i+3+j:]
		}
	}
	return "/"
}
