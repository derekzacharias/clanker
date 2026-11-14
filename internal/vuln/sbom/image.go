package sbom

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// ImageOptions bounds container image scanning.
type ImageOptions struct {
	// DockerPath is the docker CLI to use (default "docker").
	DockerPath string
	// MaxImageBytes refuses images whose reported size exceeds this.
	MaxImageBytes int64
	// MaxTarBytes caps how much of the exported layer stream is read.
	MaxTarBytes int64
	// DockerSave is injectable for tests; it must return the `docker save` tar.
	DockerSave func(ctx context.Context, ref string) (io.ReadCloser, error)
	// Now is injectable for tests.
	Now func() time.Time
}

func (o *ImageOptions) normalize() {
	if o.DockerPath == "" {
		o.DockerPath = "docker"
	}
	if o.MaxImageBytes <= 0 {
		o.MaxImageBytes = 4 << 30 // 4 GiB
	}
	if o.MaxTarBytes <= 0 {
		o.MaxTarBytes = 8 << 30
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.DockerSave == nil {
		o.DockerSave = func(ctx context.Context, ref string) (io.ReadCloser, error) {
			cmd := exec.CommandContext(ctx, o.DockerPath, "save", ref)
			// Keep docker's stderr out of the stream; surface it on failure.
			var stderr strings.Builder
			cmd.Stderr = &stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return nil, err
			}
			if err := cmd.Start(); err != nil {
				return nil, fmt.Errorf("docker save: %w", err)
			}
			return &cmdReader{ReadCloser: stdout, cmd: cmd, stderr: &stderr}, nil
		}
	}
}

type cmdReader struct {
	io.ReadCloser
	cmd    *exec.Cmd
	stderr *strings.Builder
}

func (c *cmdReader) Close() error {
	err := c.ReadCloser.Close()
	if waitErr := c.cmd.Wait(); waitErr != nil && err == nil {
		msg := strings.TrimSpace(c.stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		err = fmt.Errorf("docker save failed: %s", msg)
	}
	return err
}

// ImageResult is the outcome of scanning a container image.
type ImageResult struct {
	Reference string          `json:"reference"`
	OS        string          `json:"os,omitempty"`
	Packages  []model.Package `json:"packages"`
	Warnings  []string        `json:"warnings,omitempty"`
}

// ScanImage inventories packages from a container image reference.
//
// It reads the image filesystem (via `docker save`) rather than running it: a
// scanned image must never be executed. Docker saves either a legacy archive
// (manifest.json + <layer>/layer.tar) or an OCI archive (blobs/sha256/<digest>);
// layers may be gzipped, so each layer is opened and scanned for distribution
// package databases. Only those files are parsed, with byte limits.
func ScanImage(ctx context.Context, ref string, opts ImageOptions) (ImageResult, error) {
	opts.normalize()
	if strings.TrimSpace(ref) == "" {
		return ImageResult{}, fmt.Errorf("container image reference is required")
	}
	res := ImageResult{Reference: ref}

	stream, err := opts.DockerSave(ctx, ref)
	if err != nil {
		return res, err
	}
	defer stream.Close()

	var limits = &scanLimits{maxLayerBytes: 512 << 20, layersScanned: 0}
	tr := tar.NewReader(io.LimitReader(stream, opts.MaxTarBytes))
	for {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, fmt.Errorf("read image archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))

		// Some archives store the filesystem flat; handle a direct match first.
		if isInventoryFile(clean) {
			scanInventoryEntries(tr, clean, &res)
			continue
		}
		// Otherwise this entry may be a layer/blob: try to read it as a tar,
		// transparently decompressing gzip layers.
		if !looksLikeLayer(clean) {
			continue
		}
		if err := scanLayer(tr, &res, limits, opts); err != nil {
			// A blob that is not a layer (config JSON, manifest) is expected.
			continue
		}
	}

	if len(res.Packages) == 0 {
		res.Warnings = append(res.Warnings,
			"no distribution package database was found in the image layers (import a generated SBOM instead)")
	}
	if len(res.Packages) > 0 && res.OS == "" {
		res.Warnings = append(res.Warnings,
			"distro could not be identified from os-release; advisories may be less precise")
	}
	return res, nil
}

// scanLimits bounds the work done inside nested layers.
type scanLimits struct {
	maxLayerBytes int64
	layersScanned int
}

// looksLikeLayer reports whether a tar entry could be an image layer blob.
func looksLikeLayer(name string) bool {
	base := path.Base(name)
	if base == "layer.tar" {
		return true
	}
	// OCI blobs are content-addressed hex names.
	if strings.HasPrefix(name, "blobs/") && len(base) >= 32 && isHex(base) {
		return true
	}
	return false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// isInventoryFile matches the files we actually parse inside a layer.
func isInventoryFile(clean string) bool {
	switch {
	case strings.HasSuffix(clean, "var/lib/dpkg/status"):
		return true
	case strings.HasSuffix(clean, "lib/apk/db/installed"):
		return true
	case path.Base(clean) == "os-release" &&
		(strings.Contains(clean, "etc/") || strings.Contains(clean, "usr/lib/")):
		// /etc/os-release is usually a symlink to /usr/lib/os-release, so the
		// regular file lives under usr/lib in the layer.
		return true
	}
	return false
}

// scanLayer walks one nested layer archive.
func scanLayer(r io.Reader, res *ImageResult, limits *scanLimits, opts ImageOptions) error {
	if limits.layersScanned > 256 {
		return fmt.Errorf("layer limit reached")
	}
	buffered := bufio.NewReader(io.LimitReader(r, limits.maxLayerBytes))
	magic, err := buffered.Peek(2)
	if err != nil {
		return err
	}
	var layer io.Reader = buffered
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return err
		}
		defer gz.Close()
		layer = gz
	}
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		clean := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if !isInventoryFile(clean) {
			continue
		}
		scanInventoryEntries(tr, clean, res)
		limits.layersScanned++
	}
}

// scanInventoryEntries parses one recognised file into the result.
func scanInventoryEntries(r io.Reader, clean string, res *ImageResult) {
	switch {
	case strings.HasSuffix(clean, "var/lib/dpkg/status"):
		pkgs, err := inventory.ParseDpkgReader(io.LimitReader(r, 256<<20), res.OS, vendorOf(res.OS))
		if err != nil {
			res.Warnings = append(res.Warnings, "dpkg database could not be parsed: "+err.Error())
			return
		}
		res.Packages = append(res.Packages, pkgs...)
	case strings.HasSuffix(clean, "lib/apk/db/installed"):
		pkgs, err := inventory.ParseAPKReader(io.LimitReader(r, 64<<20), res.OS, vendorOf(res.OS))
		if err != nil {
			res.Warnings = append(res.Warnings, "APK database could not be parsed: "+err.Error())
			return
		}
		res.Packages = append(res.Packages, pkgs...)
	case path.Base(clean) == "os-release":
		fields, err := inventory.ParseOSReleaseFields(io.LimitReader(r, 64<<10))
		if err != nil {
			return
		}
		if eco := inventory.EcosystemFromFields(fields); eco != "" {
			res.OS = eco
			// Re-derive vendor for packages parsed before os-release was seen.
			for i := range res.Packages {
				if res.Packages[i].Vendor == "" {
					res.Packages[i].Vendor = vendorOf(eco)
				}
				if res.Packages[i].Ecosystem == "" || res.Packages[i].Ecosystem == string(model.EcosystemUnknown) {
					res.Packages[i].Ecosystem = eco
				}
			}
		}
	}
}

func vendorOf(ecosystem string) string {
	switch {
	case strings.HasPrefix(ecosystem, "Ubuntu"):
		return "Ubuntu"
	case strings.HasPrefix(ecosystem, "Debian"):
		return "Debian"
	case strings.HasPrefix(ecosystem, "Alpine"):
		return "Alpine"
	case strings.HasPrefix(ecosystem, "Red Hat"):
		return "Red Hat"
	}
	return ""
}

// ImageInspectSize returns the reported image size, used to refuse large exports
// before streaming gigabytes.
func ImageInspectSize(ctx context.Context, dockerPath, ref string) (int64, error) {
	if dockerPath == "" {
		dockerPath = "docker"
	}
	out, err := exec.CommandContext(ctx, dockerPath, "image", "inspect", "--format", "{{.Size}}", ref).Output()
	if err != nil {
		return 0, fmt.Errorf("docker image inspect %s: %w", ref, err)
	}
	var size int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &size); err != nil {
		return 0, fmt.Errorf("unexpected docker inspect output %q", strings.TrimSpace(string(out)))
	}
	return size, nil
}

// MarshalSummary is used by the CLI to print a parsed document or image result.
func MarshalSummary(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
