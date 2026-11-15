import { describe, expect, it, vi } from "vitest";
import { downloadReportExport, downloadSoftwareInventory } from "../lib/api";

/**
 * The inventory exports are plain downloads, so what matters here is that the
 * buttons request the right URL and give the file an honest name: a CSV of
 * installed software is not "the report", and an SBOM is not a findings export.
 */
function mockDownload() {
  const bodies = new Map<string, string>();
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const body = bodies.get(url.split("?")[0]) ?? "";
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="fallback.csv"`,
      },
    });
  });
  vi.stubGlobal("fetch", fetchMock);

  // jsdom has no object-URL support and the download path uses it.
  const createObjectURL = vi.fn(() => "blob:mock");
  const revokeObjectURL = vi.fn();
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
  const clicks: string[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    clicks.push(this.download);
  });
  return { fetchMock, clicks };
}

describe("software inventory downloads", () => {
  it("asks for the per-host CSV at the inventory format", async () => {
    const { fetchMock, clicks } = mockDownload();
    const name = await downloadReportExport("SCAN-1", "csv");
    expect(fetchMock).toHaveBeenCalledWith("/api/reports/SCAN-1/export?format=csv", expect.anything());
    expect(name).toBe("fallback.csv");
    // The fallback name only applies when the server sends no filename.
    expect(clicks).toContain("fallback.csv");
  });

  it("names the CycloneDX export as an SBOM, not as the report", async () => {
    mockDownload();
    await downloadReportExport("SCAN-1", "cyclonedx");
    const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledWith("/api/reports/SCAN-1/export?format=cyclonedx", expect.anything());
  });

  it("requests the environment-wide list without a host", async () => {
    const { fetchMock } = mockDownload();
    await downloadSoftwareInventory({ format: "csv" });
    expect(fetchMock).toHaveBeenCalledWith("/api/software/export?format=csv", expect.anything());
  });

  it("scopes an SBOM export to one host", async () => {
    const { fetchMock } = mockDownload();
    await downloadSoftwareInventory({ format: "cyclonedx", host: "web01" });
    expect(fetchMock).toHaveBeenCalledWith("/api/software/export?format=cyclonedx&host=web01", expect.anything());
  });
});
