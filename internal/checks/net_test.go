package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var now = time.Now()

func tlsServer(t *testing.T, status int) (*httptest.Server, *x509.CertPool, int) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "fake/1.0")
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return s, pool, port
}

// httptest certificates are valid for example.com and 127.0.0.1.
func httpsTarget(port int) Target {
	t, _ := ParseTarget("https://example.com:"+strconv.Itoa(port)+"/health", 0)
	return t
}

func TestHealthyHTTPS(t *testing.T) {
	_, pool, port := tlsServer(t, 200)
	o := Options{Timeout: 2 * time.Second, RootCAs: pool}
	tg := httpsTarget(port)
	addr, fs := CheckTCP(context.Background(), tg, []string{"127.0.0.1"}, o)
	if addr == "" || fs[0].Severity != OK {
		t.Fatalf("tcp %+v", fs)
	}
	ok, fs := CheckTLS(context.Background(), tg, addr, o, now)
	if !ok || !strings.Contains(fs[0].Detail, "expires in") {
		t.Fatalf("tls %+v", fs)
	}
	fs = CheckHTTP(context.Background(), tg, addr, ok, o)
	if fs[0].Severity != OK || fs[0].Check != "GET /health" || !strings.Contains(fs[0].Detail, "200 OK, server fake/1.0") {
		t.Errorf("http %+v", fs)
	}
}

func TestHTTP503IsGuilty(t *testing.T) {
	_, pool, port := tlsServer(t, 503)
	o := Options{Timeout: 2 * time.Second, RootCAs: pool}
	fs := CheckHTTP(context.Background(), httpsTarget(port), "127.0.0.1:"+strconv.Itoa(port), true, o)
	if fs[0].Severity != Fail || !strings.Contains(fs[0].Detail, "503") {
		t.Errorf("http %+v", fs)
	}
}

func TestUntrustedCertificate(t *testing.T) {
	_, _, port := tlsServer(t, 200)
	o := Options{Timeout: 2 * time.Second, RootCAs: x509.NewCertPool()}
	ok, fs := CheckTLS(context.Background(), httpsTarget(port), "127.0.0.1:"+strconv.Itoa(port), o, now)
	if ok || fs[0].Severity != Fail || !strings.Contains(fs[0].Detail, "nobody trusts") {
		t.Errorf("tls %+v", fs)
	}
	if fs := CheckHTTP(context.Background(), httpsTarget(port), "x", false, o); fs[0].Check != "skipped" {
		t.Errorf("HTTP must be skipped after a TLS failure: %+v", fs)
	}
}

func TestWrongHostCertificate(t *testing.T) {
	_, pool, port := tlsServer(t, 200)
	tg, _ := ParseTarget("https://wrong.example.org:"+strconv.Itoa(port), 0)
	o := Options{Timeout: 2 * time.Second, RootCAs: pool}
	_, fs := CheckTLS(context.Background(), tg, "127.0.0.1:"+strconv.Itoa(port), o, now)
	if !strings.Contains(fs[0].Detail, "not wrong.example.org") {
		t.Errorf("tls %+v", fs)
	}
}

func TestExpiredCertificate(t *testing.T) {
	cert, pool := expiredCert(t)
	s := httptest.NewUnstartedServer(http.NotFoundHandler())
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	defer s.Close()
	tg, _ := ParseTarget("https://expired.test"+s.Listener.Addr().String()[len("127.0.0.1"):], 0)
	o := Options{Timeout: 2 * time.Second, RootCAs: pool}
	_, fs := CheckTLS(context.Background(), tg, s.Listener.Addr().String(), o, now)
	if fs[0].Severity != Fail || !strings.Contains(fs[0].Detail, "expired 3 days ago") {
		t.Errorf("tls %+v", fs)
	}
}

func TestConnectionRefused(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // nothing listens here now
	tg, _ := ParseTarget("127.0.0.1:"+strconv.Itoa(port), 0)
	addr, fs := CheckTCP(context.Background(), tg, []string{"127.0.0.1"}, Options{Timeout: time.Second})
	if addr != "" || fs[0].Severity != Fail || !strings.Contains(fs[0].Detail, "refused") {
		t.Errorf("tcp %q %+v", addr, fs)
	}
}

func TestNoAddressSkipsEverything(t *testing.T) {
	tg := httpsTarget(443)
	addr, fs := CheckTCP(context.Background(), tg, nil, Options{})
	if addr != "" || fs[0].Check != "skipped" {
		t.Errorf("tcp %+v", fs)
	}
	if _, fs := CheckTLS(context.Background(), tg, "", Options{}, now); fs[0].Check != "skipped" {
		t.Errorf("tls %+v", fs)
	}
}

func expiredCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired.test"},
		DNSNames:              []string{"expired.test"},
		NotBefore:             now.AddDate(0, 0, -90),
		NotAfter:              now.AddDate(0, 0, -3).Add(-time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
