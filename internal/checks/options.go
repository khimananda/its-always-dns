package checks

import (
	"crypto/x509"
	"net"
	"time"

	"github.com/khimananda/its-always-dns/internal/resolvconf"
)

// Resolver is a DNS server queried directly.
type Resolver struct {
	Name string // shown to the user
	Addr string // host:port
}

// Options configure a run. Zero values are filled by Defaults.
type Options struct {
	Timeout     time.Duration
	Resolvers   []Resolver
	System      *net.Resolver // nil means net.DefaultResolver
	ResolvConf  *resolvconf.Config
	AuthPort    string // port for authoritative queries, "53" in real life
	NoAuth      bool   // skip the authoritative lookup
	RootCAs     *x509.CertPool
	DialAddress string // tests only: dial this instead of the resolved address
}

// PublicResolvers are queried by default.
var PublicResolvers = []Resolver{
	{Name: "1.1.1.1", Addr: "1.1.1.1:53"},
	{Name: "8.8.8.8", Addr: "8.8.8.8:53"},
}

// Defaults returns options for a real run: the system resolver from
// resolv.conf, public resolvers, and any extra ones.
func Defaults(timeout time.Duration, extra []string) Options {
	o := Options{Timeout: timeout, AuthPort: "53"}
	if rc, ok := resolvconf.Load(); ok {
		o.ResolvConf = &rc
		if len(rc.Nameservers) > 0 {
			ns := rc.Nameservers[0]
			o.Resolvers = append(o.Resolvers, Resolver{Name: "system " + ns, Addr: net.JoinHostPort(ns, "53")})
		}
	}
	all := append([]Resolver{}, PublicResolvers...)
	for _, e := range extra {
		addr := e
		if _, _, err := net.SplitHostPort(e); err != nil {
			addr = net.JoinHostPort(e, "53")
		}
		all = append(all, Resolver{Name: e, Addr: addr})
	}
	o.Resolvers = dedupe(append(o.Resolvers, all...))
	return o
}

func (o Options) system() *net.Resolver {
	if o.System != nil {
		return o.System
	}
	return net.DefaultResolver
}

// dedupe keeps the first resolver for each address, so the system
// resolver is not asked twice when it is also a public one.
func dedupe(rs []Resolver) []Resolver {
	seen := map[string]bool{}
	var out []Resolver
	for _, r := range rs {
		if !seen[r.Addr] {
			seen[r.Addr] = true
			out = append(out, r)
		}
	}
	return out
}
