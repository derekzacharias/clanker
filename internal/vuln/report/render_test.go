package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// SARIF is consumed by other tools, not by people: a missing field is a silent ingestion
// failure in someone else's pipeline. This pins the parts of the 2.1.0 contract that matter
// for a scanner, including the requirement that every result has a location.
func TestSARIFSatisfiesTheContractConsumersRelyOn(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, fixtureReport(), "sarif"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	raw := buf.Bytes()
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name           string `json:"name"`
					InformationURI string `json:"informationUri"`
					Rules          []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if !strings.Contains(doc.Schema, "sarif") || doc.Version != "2.1.0" {
		t.Fatalf("schema/version = %q/%q", doc.Schema, doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name == "" || run.Tool.Driver.InformationURI == "" {
		t.Fatalf("tool driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) == 0 {
		t.Fatal("no results were emitted")
	}
	rules := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		rules[r.ID] = true
	}
	for _, res := range run.Results {
		if res.RuleID == "" || !rules[res.RuleID] {
			t.Fatalf("result references an undeclared rule: %q", res.RuleID)
		}
		switch res.Level {
		case "error", "warning", "note", "none":
		default:
			t.Fatalf("level %q is not a SARIF level", res.Level)
		}
		if strings.TrimSpace(res.Message.Text) == "" {
			t.Fatal("result has no message text")
		}
		// Every result must point somewhere, or GitHub code scanning drops it.
		if len(res.Locations) == 0 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Fatalf("result %q has no location", res.RuleID)
		}
	}
}
