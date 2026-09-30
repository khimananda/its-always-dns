package checks

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// zone maps a lower-case FQDN to its A record; "" means NXDOMAIN.
type zone map[string]string

// fakeDNS starts a UDP DNS server on 127.0.0.1 answering from z.
// The zone apex "zone.test." has NS ns1.zone.test. which points back at 127.0.0.1.
func fakeDNS(t *testing.T, z zone, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if delay > 0 {
			time.Sleep(delay)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = !r.RecursionDesired
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		switch {
		case q.Qtype == dns.TypeNS && name == "zone.test.":
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1.zone.test."})
		case name == "ns1.zone.test." && q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.ParseIP("127.0.0.1")})
		case q.Qtype == dns.TypeA && z[name] != "":
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(z[name])})
		case q.Qtype == dns.TypeAAAA && z[name] != "":
			// NODATA for AAAA
		case q.Qtype == dns.TypeNS:
			// no NS here: the walker moves to the parent
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// systemVia returns a Go resolver that sends every query to addr.
func systemVia(addr string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", addr)
	}}
}

func testOptions(system string, public ...string) Options {
	_, port, _ := net.SplitHostPort(system)
	o := Options{Timeout: time.Second, System: systemVia(system), AuthPort: port,
		Resolvers: []Resolver{{Name: "system " + system, Addr: system}}}
	for i, p := range public {
		o.Resolvers = append(o.Resolvers, Resolver{Name: []string{"public-a", "public-b"}[i], Addr: p})
	}
	return o
}

func find(fs []Finding, check string) *Finding {
	for i := range fs {
		if fs[i].Check == check {
			return &fs[i]
		}
	}
	return nil
}
