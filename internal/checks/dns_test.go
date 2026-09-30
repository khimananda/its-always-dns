package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/khimananda/its-always-dns/internal/resolvconf"
)

func TestDNSHappyPath(t *testing.T) {
	z := zone{"api.zone.test.": "192.0.2.10"}
	sys := fakeDNS(t, z, 0)
	pub := fakeDNS(t, z, 0)
	o := testOptions(sys, pub)
	o.ResolvConf = &resolvconf.Config{Nameservers: []string{"127.0.0.1"}, Ndots: 1}

	ips, fs := CheckDNS(context.Background(), Target{Host: "api.zone.test"}, o)
	if len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("ips %v, findings %+v", ips, fs)
	}
	for _, f := range fs {
		if f.Severity >= Warn {
			t.Errorf("unexpected %s finding: %+v", f.Severity, f)
		}
	}
	auth := find(fs, "authoritative")
	if auth == nil || !strings.Contains(auth.Detail, "192.0.2.10") || !strings.Contains(auth.Detail, "ns1.zone.test") {
		t.Errorf("authoritative finding %+v", auth)
	}
}

func TestDNSNXDOMAIN(t *testing.T) {
	sys := fakeDNS(t, zone{}, 0)
	ips, fs := CheckDNS(context.Background(), Target{Host: "missing.zone.test"}, testOptions(sys))
	if len(ips) != 0 {
		t.Fatalf("ips %v", ips)
	}
	f := find(fs, "system lookup")
	if f == nil || f.Severity != Fail || !strings.Contains(f.Detail, "does not exist") {
		t.Errorf("system lookup %+v", f)
	}
}

func TestDNSSplitHorizon(t *testing.T) {
	inside := fakeDNS(t, zone{"intranet.zone.test.": "10.0.0.5"}, 0)
	outside := fakeDNS(t, zone{}, 0)
	_, fs := CheckDNS(context.Background(), Target{Host: "intranet.zone.test"}, testOptions(inside, outside))
	f := find(fs, "agreement")
	if f == nil || f.Severity != Warn || !strings.Contains(f.Detail, "split horizon") {
		t.Errorf("agreement %+v", f)
	}
}

func TestDNSSlowLookup(t *testing.T) {
	sys := fakeDNS(t, zone{"slow.zone.test.": "192.0.2.1"}, Slow+50*time.Millisecond)
	o := testOptions(sys)
	o.NoAuth = true
	o.Timeout = 3 * time.Second // the fake server answers A and AAAA one after the other
	_, fs := CheckDNS(context.Background(), Target{Host: "slow.zone.test"}, o)
	if f := find(fs, "system lookup"); f == nil || f.Severity != Warn {
		t.Errorf("a slow lookup should warn: %+v", f)
	}
}

func TestDNSBlockedPublicResolverIsInfo(t *testing.T) {
	sys := fakeDNS(t, zone{"api.zone.test.": "192.0.2.10"}, 0)
	o := testOptions(sys)
	o.Resolvers = append(o.Resolvers, Resolver{Name: "blocked", Addr: "127.0.0.1:9"})
	o.Timeout = 300 * time.Millisecond
	o.NoAuth = true
	_, fs := CheckDNS(context.Background(), Target{Host: "api.zone.test"}, o)
	if f := find(fs, "blocked"); f == nil || f.Severity != Info {
		t.Errorf("a blocked public resolver is information, not failure: %+v", f)
	}
}

func TestDNSNdotsWarning(t *testing.T) {
	sys := fakeDNS(t, zone{"api.zone.test.": "192.0.2.10"}, 0)
	o := testOptions(sys)
	o.NoAuth = true
	o.ResolvConf = &resolvconf.Config{Search: []string{"default.svc.cluster.local", "svc.cluster.local", "cluster.local"}, Ndots: 5}
	_, fs := CheckDNS(context.Background(), Target{Host: "api.zone.test"}, o)
	f := find(fs, "ndots")
	if f == nil || f.Severity != Warn || !strings.Contains(f.Detail, "tries 3 wrong names") {
		t.Errorf("ndots finding %+v", f)
	}
}

func TestDNSSkippedForIP(t *testing.T) {
	ips, fs := CheckDNS(context.Background(), Target{Host: "192.0.2.7", IsIP: true}, Options{})
	if len(ips) != 1 || len(fs) != 1 || fs[0].Severity != Info {
		t.Errorf("ips %v findings %+v", ips, fs)
	}
}
