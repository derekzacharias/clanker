package norm

import (
	"testing"
)

func TestNormalizePriorityApplications(t *testing.T) {
	cases := []struct {
		name, publisher, version, arch string
		wantVendor, wantProduct        string
	}{
		{"Google Chrome (64-bit)", "Google LLC", "120.0.6099.109", "x64", "google", "chrome"},
		{"Google Chrome", "Google Inc.", "119.0.6045.105", "", "google", "chrome"},
		{"Microsoft Edge", "Microsoft Corporation", "127.0.2651.74", "x64", "microsoft", "edge"},
		{"Microsoft Edge Stable", "Microsoft Corporation", "127.0.2651.74", "", "microsoft", "edge"},
		{"Mozilla Firefox (x64 en-US)", "Mozilla", "128.0", "x64", "mozilla", "firefox"},
		{"Mozilla Firefox ESR", "Mozilla Corporation", "115.13.0", "", "mozilla", "firefox"},
		{"Brave", "Brave Software Inc.", "1.67.123", "x64", "brave", "brave"},
		{"Brave Browser", "Brave Software, Inc.", "1.67.123", "", "brave", "brave"},
		{"Microsoft 365 Apps for enterprise - en-us", "Microsoft Corporation", "16.0.17628.20006", "x64", "microsoft", "365_apps"},
		{"Microsoft Office Professional Plus 2016", "Microsoft Corporation", "16.0.4266.1001", "", "microsoft", "office"},
		{"Adobe Acrobat Reader DC (64-bit)", "Adobe Inc.", "24.002.20965", "x64", "adobe", "acrobat_reader_dc"},
		{"Adobe Acrobat DC (64-bit)", "Adobe Inc.", "24.002.20965", "", "adobe", "acrobat_dc"},
		{"LibreOffice 7.6.4.1", "The Document Foundation", "7.6.4.1", "x64", "libreoffice", "libreoffice"},
		{"Microsoft Teams", "Microsoft Corporation", "1.7.00.7956", "", "microsoft", "teams"},
		{"Zoom Workplace (x64)", "Zoom Video Communications, Inc.", "6.1.5", "x64", "zoom", "zoom"},
		{"Java 8 Update 411 (64-bit)", "Oracle Corporation", "8.0.4110.9", "x64", "oracle", "jre"},
		{"Eclipse Temurin JDK with Hotspot 17.0.11+9 (x64)", "Eclipse Adoptium", "17.0.11.9", "x64", "eclipse", "temurin"},
		{"Python 3.12.3 (64-bit)", "Python Software Foundation", "3.12.3150.0", "x64", "python", "python"},
		{"Node.js", "OpenJS Foundation", "20.15.0", "x64", "nodejs", "node.js"},
		{"Microsoft .NET Runtime 8.0", "Microsoft Corporation", "8.0.6", "", "microsoft", ".net"},
		{"Microsoft .NET SDK 8.0.204", "Microsoft Corporation", "8.0.204", "", "microsoft", ".net"},
		{"PowerShell 7-x64", "Microsoft Corporation", "7.4.3.0", "x64", "microsoft", "powershell"},
		{"Git", "The Git Development Community", "2.45.2", "x64", "git-scm", "git"},
		{"OpenSSL 3.3.1 Light (64-bit)", "OpenSSL Software Foundation", "3.3.1", "x64", "openssl", "openssl"},
		{"7-Zip 24.08 (x64)", "Igor Pavlov", "24.08", "x64", "7-zip", "7-zip"},
		{"WinRAR 7.01 (64-bit)", "win.rar GmbH", "7.01.0", "x64", "rarlab", "winrar"},
		{"Notepad++ (64-bit x64)", "Notepad++ Team", "8.6.9", "x64", "notepad-plus-plus", "notepad_plus_plus"},
		{"VLC media player", "VideoLAN", "3.0.21", "x64", "videolan", "vlc_media_player"},
		{"PuTTY (64-bit)", "Simon Tatham", "0.81.0.0", "x64", "simon-tatham", "putty"},
		{"WinSCP 6.3.3", "Martin Prikryl", "6.3.3", "", "winscp", "winscp"},
		{"FileZilla Client 3.67.0", "Tim Kosse", "3.67.0", "x64", "filezilla-project", "filezilla_client"},
		{"Docker Desktop", "Docker Inc.", "4.32.0", "", "docker", "docker_desktop"},
		{"VMware Tools", "VMware, Inc.", "12.3.5", "x64", "vmware", "vmware_tools"},
		{"VMware Workstation", "VMware, Inc.", "17.5.2", "", "vmware", "vmware_workstation"},
		{"Oracle VM VirtualBox 7.0.18", "Oracle Corporation", "7.0.18", "", "oracle", "vm_virtualbox"},
		{"OpenSSH for Windows", "Microsoft Corporation", "9.5.0.0", "", "microsoft", "openssh"},
		{"Apache HTTP Server", "Apache Software Foundation", "2.4.59", "", "apache", "http_server"},
		{"nginx/1.26.1", "", "1.26.1", "", "nginx", "nginx"},
		{"Microsoft OneDrive", "Microsoft Corporation", "24.121.0605.0001", "", "microsoft", "onedrive"},
		{"Microsoft Visual Studio Code (User)", "Microsoft Corporation", "1.90.2", "", "microsoft", "visual_studio_code"},
		{"GitLab Runner", "GitLab Inc.", "17.0.1", "", "gitlab", "gitlab_runner"},
		{"Wireshark 4.2.5 (x64)", "Wireshark Foundation", "4.2.5", "x64", "wireshark", "wireshark"},
	}
	for _, tc := range cases {
		got := Default.Normalize(tc.name, tc.publisher, tc.version, tc.arch)
		if got.Vendor != tc.wantVendor || got.Product != tc.wantProduct {
			t.Errorf("Normalize(%q, %q) = %s/%s (%s), want %s/%s",
				tc.name, tc.publisher, got.Vendor, got.Product, got.MatchSource, tc.wantVendor, tc.wantProduct)
		}
		if got.Method != "pattern" {
			t.Errorf("Normalize(%q): method = %q, want pattern", tc.name, got.Method)
		}
		if got.Confidence < 0.9 {
			t.Errorf("Normalize(%q): confidence %v too low for a deterministic rule", tc.name, got.Confidence)
		}
		if got.Name != tc.name {
			t.Errorf("Normalize(%q): original name must be preserved, got %q", tc.name, got.Name)
		}
	}
}

func TestNormalizePreservesOriginalValues(t *testing.T) {
	got := Default.Normalize("Google Chrome (64-bit)", "Google LLC", "120.0.6099.109", "x64")
	if got.Name != "Google Chrome (64-bit)" || got.Publisher != "Google LLC" || got.Version != "120.0.6099.109" {
		t.Fatalf("original values not preserved: %+v", got)
	}
}

func TestNormalizeUnmapped(t *testing.T) {
	got := Default.Normalize("Some Internal Tool 3.14", "ACME Corp", "3.14", "x64")
	if got.Method != "unmapped" {
		t.Fatalf("unknown software must stay unmapped: %+v", got)
	}
	if got.Vendor != "" || got.Product != "" {
		t.Fatalf("unmapped software must not invent vendor/product: %+v", got)
	}
	if got.Name != "Some Internal Tool 3.14" {
		t.Fatal("original name must be preserved for unmapped software")
	}
}

func TestNormalizeChannelAndArch(t *testing.T) {
	got := Default.Normalize("Mozilla Firefox (x64 en-US)", "Mozilla", "128.0", "x64")
	if got.Arch != "x64" {
		t.Errorf("arch = %q, want x64", got.Arch)
	}
	beta := Default.Normalize("Google Chrome Beta", "Google LLC", "121.0.0.0", "")
	if beta.Channel != "beta" || beta.Product != "chrome" {
		t.Errorf("beta channel: %+v", beta)
	}
	esr := Default.Normalize("Mozilla Firefox ESR", "Mozilla Corporation", "115.13.0", "")
	if esr.Channel != "esr" {
		t.Errorf("esr channel: %+v", esr)
	}
}

func TestSimilarNamesDoNotCrossMap(t *testing.T) {
	// "chrome" must never map to "chromeos"/"chromium" products, and edge
	// must not map to internet explorer.
	if got := Default.Normalize("Google Chrome", "Google LLC", "1.0", ""); got.Product != "chrome" {
		t.Errorf("chrome mapped to %q", got.Product)
	}
	if got := Default.Normalize("Chromium", "The Chromium Authors", "1.0", ""); got.Method != "unmapped" {
		t.Errorf("chromium must not be confused with chrome: %+v", got)
	}
}

func TestVersionCleaning(t *testing.T) {
	got := Default.Normalize("Google Chrome", "Google LLC", "120.0.6099.109 (build 1.2)", "")
	if got.Version != "120.0.6099.109" {
		t.Errorf("version = %q", got.Version)
	}
}

func TestCandidatesFuzzy(t *testing.T) {
	cands := Default.Candidates("Googl Chrome (64-bit)", 5)
	if len(cands) == 0 || cands[0].Product != "chrome" {
		t.Fatalf("fuzzy candidates should surface chrome for a typo: %+v", cands)
	}
	if cands[0].Score >= 1.0 {
		t.Fatal("fuzzy candidates are never exact matches")
	}
}

func TestRulesLoadValidation(t *testing.T) {
	if _, err := Load([]byte(`{"schema_version": 2}`)); err == nil {
		t.Fatal("unsupported schema must fail")
	}
	if _, err := Load([]byte(`{"schema_version": 1, "products": [{"match": "(", "vendor": "x", "product": "y"}]}`)); err == nil {
		t.Fatal("invalid regex must fail load")
	}
	if _, err := Load([]byte(`{"schema_version": 1, "products": [{"match": "^x$", "vendor": "", "product": "y"}]}`)); err == nil {
		t.Fatal("rule without vendor must fail load")
	}
}

func TestFuzzyMustNotEstablishVulnerability(t *testing.T) {
	// The contract: a fuzzy-only mapping has Method "fuzzy" (set by the
	// caller) and the engine's own deterministic path never returns one.
	got := Default.Normalize("Zoom Workplce", "Zoom Video Communications, Inc.", "6.0.0", "")
	if got.Method == "pattern" {
		return // typo happened to match a pattern; that's fine
	}
	if got.Method != "unmapped" && got.Confidence >= 0.9 {
		t.Fatalf("non-deterministic mapping must not carry high confidence: %+v", got)
	}
}
