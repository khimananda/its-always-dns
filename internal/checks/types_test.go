package checks

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in     string
		port   int
		host   string
		wantP  int
		scheme string
		url    string
		ip     bool
	}{
		{"example.com", 0, "example.com", 443, "https", "https://example.com/", false},
		{"example.com:80", 0, "example.com", 80, "http", "http://example.com/", false},
		{"db.internal:5432", 0, "db.internal", 5432, "", "", false},
		{"https://example.com/health?x=1", 0, "example.com", 443, "https", "https://example.com/health?x=1", false},
		{"http://example.com:8080/", 0, "example.com", 8080, "http", "http://example.com:8080/", false},
		{"example.com", 8443, "example.com", 8443, "https", "https://example.com:8443/", false},
		{"10.0.0.1:22", 0, "10.0.0.1", 22, "", "", true},
		{"[2001:db8::1]:443", 0, "2001:db8::1", 443, "https", "https://[2001:db8::1]/", true},
		{"example.com.", 0, "example.com", 443, "https", "https://example.com/", false},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in, c.port)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if got.Host != c.host || got.Port != c.wantP || got.Scheme != c.scheme || got.URL != c.url || got.IsIP != c.ip {
			t.Errorf("%s: got %+v", c.in, got)
		}
	}
	for _, bad := range []string{"", "ftp://example.com", "example.com:notaport", "example.com:70000"} {
		if _, err := ParseTarget(bad, 0); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestDedupeResolvers(t *testing.T) {
	got := dedupe([]Resolver{{"system 8.8.8.8", "8.8.8.8:53"}, {"1.1.1.1", "1.1.1.1:53"}, {"8.8.8.8", "8.8.8.8:53"}})
	if len(got) != 2 || got[0].Name != "system 8.8.8.8" {
		t.Errorf("%+v", got)
	}
}
