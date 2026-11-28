package apps

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/nvd"
)

// seedBenchStore builds a synthetic NVD store: cvesPerProduct CVEs per product,
// each with an OR configuration of an affected range and a fixed version.
// products counts distinct products.
func seedBenchStore(b *testing.B, products, cvesPerProduct int) *sql.DB {
	b.Helper()
	db, err := sql.Open("sqlite", "file:"+b.TempDir()+"/bench.db?_pragma=journal_mode(WAL)")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })
	if err := nvd.EnsureSchema(db); err != nil {
		b.Fatal(err)
	}
	ns := nvd.NewStore(db)
	now := time.Now().UTC()
	records := make([]nvd.Record, 0, products*cvesPerProduct)
	for p := 0; p < products; p++ {
		for c := 0; c < cvesPerProduct; c++ {
			records = append(records, nvd.Record{
				ID:          fmt.Sprintf("CVE-2024-%04d", p*cvesPerProduct+c),
				Status:      "Analyzed",
				Description: "benchmark record",
				Metrics:     []nvd.CVSSMetric{{Version: "3.1", Score: 7.5, Severity: "high"}},
				Configs: []cpe.Node{{Operator: "OR", Matches: []cpe.Match{
					{
						Criteria:        fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", p, p),
						Vulnerable:      true,
						Range:           cpe.Range{StartIncluding: "1.0.0", EndExcluding: fmt.Sprintf("%d.0.0", c+2)},
						MatchCriteriaID: fmt.Sprintf("mc-%d-%d", p, c),
					},
				}}},
			})
		}
	}
	if _, _, err := ns.SaveCVEs(context.Background(), records, now); err != nil {
		b.Fatal(err)
	}
	// The dictionary table is what identity resolution reads; seed it too.
	var entries []nvd.DictEntry
	for p := 0; p < products; p++ {
		entries = append(entries, nvd.DictEntry{
			CPE23:   fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", p, p),
			Vendor:  fmt.Sprintf("vendor%d", p),
			Product: fmt.Sprintf("product%d", p),
			Version: "*",
		})
	}
	if _, _, err := ns.SaveDictionary(context.Background(), entries); err != nil {
		b.Fatal(err)
	}
	seq, _ := ns.RecordSyncStart(context.Background(), "cves", "full", time.Time{}, time.Time{}, now)
	_ = ns.RecordSyncFinish(context.Background(), seq, "ok", len(records), len(records), 0, 0, "", now)
	return db
}

// benchInventory builds the application inventory for the synthetic store:
// one installed application per product.
func benchInventory(products int) model.Inventory {
	var pkgs []model.Package
	for p := 0; p < products; p++ {
		pkgs = append(pkgs, model.Package{
			// The display name is exactly the dictionary product name, so the
			// dictionary identity path resolves it (one vendor per product).
			Name:      fmt.Sprintf("product%d", p),
			Version:   fmt.Sprintf("1.5.%d", p),
			Ecosystem: model.EcosystemWindows,
			Source:    model.OriginManifest,
			Vendor:    fmt.Sprintf("Vendor%d", p),
		})
	}
	return model.Inventory{
		Asset:    model.Asset{Hostname: "bench", OS: "Windows", OSVersion: "11"},
		Windows:  &model.WindowsState{Product: "Windows 11", Build: "10.0.22631.0"},
		Packages: pkgs,
	}
}

// Baseline documented in docs/APPLICATIONS.md. Re-run with:
//
//	go test ./internal/vuln/apps/ -bench Correlate -benchmem
func BenchmarkCorrelate10Apps100CVEs(b *testing.B) {
	db := seedBenchStore(b, 10, 100)
	a := &Assessor{DB: db, Concurrency: 8, Now: time.Now}
	inv := benchInventory(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := a.Assess(context.Background(), inv)
		if err != nil {
			b.Fatal(err)
		}
		if res.Coverage.Evaluated == 0 {
			b.Fatal("nothing was evaluated")
		}
	}
}

func BenchmarkCorrelate50Apps200CVEs(b *testing.B) {
	db := seedBenchStore(b, 50, 200)
	a := &Assessor{DB: db, Concurrency: 8, Now: time.Now}
	inv := benchInventory(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := a.Assess(context.Background(), inv)
		if err != nil {
			b.Fatal(err)
		}
		if res.Coverage.Evaluated == 0 {
			b.Fatal("nothing was evaluated")
		}
	}
}

func BenchmarkConfigTreeEvaluation(b *testing.B) {
	cfg := []cpe.Node{{
		Operator: "OR",
		Matches: []cpe.Match{{
			Criteria:        "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
			Vulnerable:      true,
			Range:           cpe.Range{StartIncluding: "119.0.0.0", EndExcluding: "120.0.6099.224"},
			MatchCriteriaID: "mc-1",
		}},
	}}
	targets := cpe.Targets{
		App: cpe.NewTarget("google", "chrome", "120.0.6099.109", "", "", "x64"),
		OS:  []cpe.CPE{{Part: cpe.PartOS, Vendor: "microsoft", Product: "windows", Version: cpe.Any}},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := cpe.EvaluateConfigs(cfg, targets, nil)
		if !res.Vulnerable {
			b.Fatal("expected vulnerable")
		}
	}
}
