package sbom

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func parseFixture(t *testing.T, name string) Document {
	t.Helper()
	doc, err := ParseFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func byName(pkgs []model.Package, name string) (model.Package, bool) {
	for _, p := range pkgs {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return model.Package{}, false
}

func TestParseCycloneDX(t *testing.T) {
	doc := parseFixture(t, "cyclonedx.json")
	if doc.Format != FormatCycloneDX || doc.Subject != "payments-api" {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if len(doc.Packages) != 4 {
		t.Fatalf("expected 4 versioned packages, got %d: %+v", len(doc.Packages), doc.Packages)
	}
	if len(doc.Warnings) == 0 {
		t.Fatal("the component without a version should be reported as a warning")
	}

	requests, ok := byName(doc.Packages, "requests")
	if !ok || requests.Ecosystem != string(model.EcosystemPyPI) || requests.Version != "2.31.0" {
		t.Fatalf("PyPI component wrong: %+v", requests)
	}
	log4j, ok := byName(doc.Packages, "log4j-core")
	if !ok || log4j.Ecosystem != string(model.EcosystemMaven) {
		t.Fatalf("Maven component wrong: %+v", log4j)
	}
	// A distro purl must resolve to the distro ecosystem so vendor data applies.
	openssl, ok := byName(doc.Packages, "openssl")
	if !ok || openssl.Ecosystem != "Debian:12" {
		t.Fatalf("deb purl should map to Debian:12, got %+v", openssl)
	}
}

func TestParseSPDX(t *testing.T) {
	doc := parseFixture(t, "spdx.json")
	if doc.Format != FormatSPDX || len(doc.Packages) != 2 {
		t.Fatalf("unexpected SPDX parse: %+v", doc)
	}
	flask, _ := byName(doc.Packages, "flask")
	if flask.Ecosystem != string(model.EcosystemPyPI) {
		t.Fatalf("purl should drive the ecosystem: %+v", flask)
	}
}

func TestParseNpmLock(t *testing.T) {
	doc := parseFixture(t, "package-lock.json")
	if doc.Format != FormatNpmLock {
		t.Fatalf("wrong format: %s", doc.Format)
	}
	if _, ok := byName(doc.Packages, "@angular/core"); !ok {
		t.Fatalf("scoped package missing: %+v", doc.Packages)
	}
	leftpad, ok := byName(doc.Packages, "left-pad")
	if !ok || leftpad.Version != "1.3.0" {
		t.Fatalf("nested dependency missing: %+v", doc.Packages)
	}
	if _, ok := byName(doc.Packages, "demo"); ok {
		t.Fatal("the root project itself must not be reported as a dependency")
	}
}

func TestParseRequirements(t *testing.T) {
	doc := parseFixture(t, "requirements.txt")
	if doc.Format != FormatRequirements {
		t.Fatalf("wrong format: %s", doc.Format)
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("expected 3 pinned packages, got %d: %+v", len(doc.Packages), doc.Packages)
	}
	sqlalchemy, ok := byName(doc.Packages, "flask_sqlalchemy")
	if !ok {
		t.Fatalf("marker line should still parse: %+v", doc.Packages)
	}
	if sqlalchemy.Version != "3.1.1" {
		t.Fatalf("version parse wrong: %+v", sqlalchemy)
	}
	if len(doc.Warnings) == 0 {
		t.Fatal("unpinned requirement should be reported as a warning")
	}
}

func TestParseCargoLock(t *testing.T) {
	doc := parseFixture(t, "Cargo.lock")
	if len(doc.Packages) != 2 {
		t.Fatalf("expected 2 crates, got %+v", doc.Packages)
	}
	openssl, ok := byName(doc.Packages, "openssl-src")
	if !ok || openssl.Version != "300.1.5+3.1.3" || openssl.Ecosystem != string(model.EcosystemCargo) {
		t.Fatalf("cargo parse wrong: %+v", openssl)
	}
}

func TestUnsupportedDocumentIsRejected(t *testing.T) {
	_, err := Parse([]byte(`{"hello":"world"}`), "unknown.json")
	if err == nil || !strings.Contains(err.Error(), "not a supported SBOM") {
		t.Fatalf("expected a clear rejection, got %v", err)
	}
	_, err = Parse([]byte("just some text"), "notes.txt")
	if err == nil {
		t.Fatal("unrecognised text must be rejected")
	}
}

func TestExportCycloneDXIsDeterministic(t *testing.T) {
	pkgs := []model.Package{
		{Name: "requests", Version: "2.31.0", Ecosystem: string(model.EcosystemPyPI)},
		{Name: "lodash", Version: "4.17.21", Ecosystem: string(model.EcosystemNPM), PURL: "pkg:npm/lodash@4.17.21"},
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	a, err := ExportCycloneDX(pkgs, model.Asset{Hostname: "host1", OSVersion: "24.04"}, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ExportCycloneDX(pkgs, model.Asset{Hostname: "host1", OSVersion: "24.04"}, "test", now)
	if !bytes.Equal(a, b) {
		t.Fatal("the same inventory must produce the same document")
	}
	var doc cdxDocument
	if err := jsonUnmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || len(doc.Components) != 2 {
		t.Fatalf("unexpected export: %+v", doc)
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Fatalf("serial number missing: %q", doc.SerialNumber)
	}
	if doc.Components[0].Name != "lodash" {
		t.Fatalf("components should be sorted: %+v", doc.Components)
	}
	if doc.Components[0].PURL == "" || doc.Components[1].PURL == "" {
		t.Fatal("purls should be derived when missing")
	}
}

// imageTar builds a minimal docker-save style archive with a dpkg database.
func imageTar(t *testing.T, osRelease, dpkgStatus string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name, content string) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	add("abc123/layer.tar", "")
	add("blobs/rootfs/etc/os-release", osRelease)
	add("blobs/rootfs/var/lib/dpkg/status", dpkgStatus)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScanImageFromArchiveStream(t *testing.T) {
	osRelease := "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n"
	dpkgStatus := "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\n" +
		"\nPackage: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.15-2\n"
	archive := imageTar(t, osRelease, dpkgStatus)

	res, err := ScanImage(context.Background(), "demo:1.0", ImageOptions{
		DockerSave: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(archive)), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OS != "Debian:12" {
		t.Fatalf("os-release should drive the ecosystem, got %q", res.OS)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %+v", res.Packages)
	}
	openssl, ok := byName(res.Packages, "openssl")
	if !ok || openssl.Vendor != "Debian" || openssl.Version != "3.0.11-1~deb12u2" {
		t.Fatalf("dpkg parse wrong: %+v", openssl)
	}
}

func TestScanImageReportsEmptyInventory(t *testing.T) {
	archive := imageTar(t, "ID=alpine\nVERSION_ID=\"3.19\"\n", "")
	res, err := ScanImage(context.Background(), "scratch:latest", ImageOptions{
		DockerSave: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(archive)), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("an image without a package database must be reported as a gap")
	}
}

func TestScanImageHonoursContextCancellation(t *testing.T) {
	archive := imageTar(t, "ID=debian\nVERSION_ID=\"12\"\n", "Package: bash\nStatus: install ok installed\nVersion: 5.2-1\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanImage(ctx, "demo", ImageOptions{
		DockerSave: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(archive)), nil
		},
	}); err == nil {
		t.Fatal("cancelled image scan must fail")
	}
}

func TestParseFileRejectsDirectories(t *testing.T) {
	if _, err := ParseFile(t.TempDir()); err == nil {
		t.Fatal("directories must be rejected")
	}
	if _, err := ParseFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing files must be rejected")
	}
	_ = os.ErrNotExist
}

// gzipBytes compresses a tar layer the way docker/OCI stores it.
func gzipTarLayer(t *testing.T, path string, content string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	if err := tw.WriteHeader(&tar.Header{Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	return out.Bytes()
}

// TestScanImageNestedOCIBlobs is the regression test for the live-image defect:
// docker save stores gzipped layer blobs, so scanning the outer archive alone
// reported zero components for a real image.
func TestScanImageNestedOCIBlobs(t *testing.T) {
	osLayer := gzipTarLayer(t, "etc/os-release", "ID=alpine\nVERSION_ID=\"3.19\"\nPRETTY_NAME=\"Alpine Linux v3.19\"\n")
	apkLayer := gzipTarLayer(t, "lib/apk/db/installed", "C:Q1abc=\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nC:Q1def=\nP:openssl\nV:3.1.4-r0\nA:x86_64\no:openssl\n")

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, layer := range [][]byte{osLayer, apkLayer} {
		name := "blobs/sha256/" + strings.Repeat(string(rune('a'+i)), 64)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(layer)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(layer); err != nil {
			t.Fatal(err)
		}
	}
	// A config blob that is not a layer must be ignored quietly.
	cfg := []byte(`{"architecture":"amd64","os":"linux"}`)
	_ = tw.WriteHeader(&tar.Header{Name: "blobs/sha256/" + strings.Repeat("f", 64), Mode: 0o644, Size: int64(len(cfg)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(cfg)
	_ = tw.Close()

	res, err := ScanImage(context.Background(), "alpine:3.19", ImageOptions{
		DockerSave: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OS != "Alpine:v3.19" {
		t.Fatalf("os-release inside a gzipped layer was not read: %q", res.OS)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("expected apk packages from the nested layer, got %+v (warnings %v)", res.Packages, res.Warnings)
	}
	openssl, ok := byName(res.Packages, "openssl")
	if !ok || openssl.Version != "3.1.4-r0" || openssl.Vendor != "Alpine" {
		t.Fatalf("apk entry wrong: %+v", openssl)
	}
}
