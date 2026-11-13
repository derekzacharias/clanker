package pkgurl

import "testing"

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		ecosystem, name, version, want string
	}{
		{"Debian:12", "openssl", "3.0.11-1~deb12u2", "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12"},
		{"Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.5", "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?distro=ubuntu-24.04"},
		{"PyPI", "Requests", "2.31.0", "pkg:pypi/Requests@2.31.0"},
		{"npm", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"},
		{"npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"Go", "github.com/gin-gonic/gin", "1.9.1", "pkg:golang/github.com/gin-gonic/gin@1.9.1"},
		{"crates.io", "openssl-src", "300.1.5+3.1.3", "pkg:cargo/openssl-src@300.1.5+3.1.3"},
		{"Maven", "org.apache.logging.log4j/log4j-core", "2.17.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"},
		{"RubyGems", "rails", "7.0.4", "pkg:gem/rails@7.0.4"},
		{"unknown-ecosystem", "weird", "1.0", ""},
	}
	for _, c := range cases {
		if got := BuildPURL(c.ecosystem, c.name, c.version); got != c.want {
			t.Errorf("BuildPURL(%q,%q,%q) = %q, want %q", c.ecosystem, c.name, c.version, got, c.want)
		}
	}
}

func TestParsePURLRoundTrip(t *testing.T) {
	raw := "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?distro=ubuntu-24.04"
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Type != "deb" || p.Namespace != "ubuntu" || p.Name != "openssl" || p.Version != "3.0.13-0ubuntu3.5" {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.Qualifiers["distro"] != "ubuntu-24.04" {
		t.Fatalf("qualifier lost: %+v", p.Qualifiers)
	}
	if got := p.String(); got != raw {
		t.Fatalf("round trip mismatch: %q", got)
	}

	if _, err := Parse("not-a-purl"); err == nil {
		t.Fatal("expected error for non-purl input")
	}
	if _, err := Parse("pkg:npm"); err == nil {
		t.Fatal("expected error for purl without name")
	}
}

func TestParseCPE(t *testing.T) {
	c, err := ParseCPE("cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("parse cpe: %v", err)
	}
	if c.Part != "a" || c.Vendor != "openbsd" || c.Product != "openssh" || c.Version != "9.3p1" {
		t.Fatalf("unexpected cpe: %+v", c)
	}
	if got := c.String(); got != "cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*" {
		t.Fatalf("cpe round trip = %q", got)
	}
	// escaped colon must survive
	esc, err := ParseCPE(`cpe:2.3:a:vendor:prod\:name:1.0:*:*:*:*:*:*:*`)
	if err != nil {
		t.Fatalf("parse escaped cpe: %v", err)
	}
	if esc.Product != "prod:name" {
		t.Fatalf("escaping not handled: %q", esc.Product)
	}
	if _, err := ParseCPE("cpe:/a:openbsd:openssh:9.3p1"); err == nil {
		t.Fatal("CPE 2.2 URI binding should be rejected by ParseCPE")
	}
}

func TestNormalizeName(t *testing.T) {
	cases := [][3]string{
		{"PyPI", "Flask_SQLAlchemy", "flask-sqlalchemy"},
		{"PyPI", "zope.interface", "zope-interface"},
		{"npm", "React", "react"},
		{"Debian:12", "OpenSSL", "openssl"},
		{"Go", "github.com/Gin-Gonic/Gin", "github.com/Gin-Gonic/Gin"},
	}
	for _, c := range cases {
		if got := NormalizeName(c[0], c[1]); got != c[2] {
			t.Errorf("NormalizeName(%q,%q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}
