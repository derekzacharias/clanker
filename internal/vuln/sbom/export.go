package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/pkgurl"
)

// CycloneDX 1.5 output. Only fields that are actually known are emitted; an
// unknown version is not invented.
type cdxDocument struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Group   string `json:"group,omitempty"`
}

// ExportCycloneDX renders an inventory as a CycloneDX 1.5 document.
//
// The serial number is derived from the content, so exporting the same inventory
// twice produces the same document (useful for diffing).
func ExportCycloneDX(pkgs []model.Package, asset model.Asset, toolVersion string, now time.Time) ([]byte, error) {
	components := make([]cdxComponent, 0, len(pkgs))
	for _, p := range pkgs {
		purl := p.PURL
		if purl == "" {
			purl = pkgurl.BuildPURL(p.Ecosystem, p.Name, p.Version)
		}
		ref := purl
		if ref == "" {
			ref = p.Ecosystem + "/" + p.Name + "@" + p.Version
		}
		components = append(components, cdxComponent{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
			PURL:    purl,
			BOMRef:  ref,
		})
	}
	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		return components[i].Version < components[j].Version
	})

	host := asset.Hostname
	if host == "" {
		host = "endpoint"
	}
	seed := host + "|"
	for _, c := range components {
		seed += c.BOMRef + ","
	}
	sum := sha256.Sum256([]byte(seed))
	serial := "urn:uuid:" + hex.EncodeToString(sum[:16])

	doc := cdxDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: serial,
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "clanker", Name: "clanker-guard", Version: toolVersion}},
			Component: &cdxComponent{
				Type: "device", Name: host,
				Version: asset.OSVersion,
			},
		},
		Components: components,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// Summary describes a document for reports and the CLI.
func Summary(doc Document) string {
	return fmt.Sprintf("%s (%s): %d packages", doc.Path, doc.Format, len(doc.Packages))
}
