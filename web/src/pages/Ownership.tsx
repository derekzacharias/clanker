import { useMemo, useState } from "react";
import { useAsync } from "../lib/useApi";
import { api, type AssetOwnershipRow } from "../lib/api";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Field, Input, Select } from "../components/ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";
import { Modal } from "../components/ui/Dialog";
import { Terminal } from "lucide-react";
import { relativeTime } from "../lib/format";

/**
 * Ownership inventory.
 *
 * Routing never guesses: a finding whose asset has no owner and whose ecosystem cannot
 * be classified waits in triage. That makes "who is responsible for this machine" the
 * one input the queue cannot fill in for itself, so this page exists to record it —
 * one asset or many at a time.
 *
 * The rows come from work, not from a CMDB: an asset appears once an assessment reports
 * findings for it. A record with no findings is kept and shown, because a host that has
 * been fixed is still somebody's host.
 */
const TEAMS = ["Infrastructure", "Development", "DevOps", "Platform Engineering", "Cloud Engineering", "Security"];

type Filter = "all" | "triage" | "overdue";

const FILTER_LABEL: Record<Filter, string> = {
  all: "All assets",
  triage: "Needs an owner",
  overdue: "Overdue",
};

export default function Ownership() {
  const { data, error, loading, reload } = useAsync(() => api.ownershipOverview());
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [bulkTeam, setBulkTeam] = useState("");
  const [bulkOwner, setBulkOwner] = useState("");
  // Access editor: how a developer reaches the host, so the ticket can say it.
  const [editing, setEditing] = useState<AssetOwnershipRow | null>(null);
  const [sshUser, setSSHUser] = useState("");
  const [sshHost, setSSHHost] = useState("");
  const [sshPort, setSSHPort] = useState("");
  const [sshJump, setSSHJump] = useState("");
  const [runbook, setRunbook] = useState("");
  const [saving, setSaving] = useState(false);
  const { push } = useToast();

  const rows = data?.items ?? [];

  const teams = useMemo(() => {
    const known = new Set(TEAMS);
    rows.forEach((r) => {
      if (r.team) known.add(r.team);
    });
    return [...known].sort();
  }, [rows]);

  const visible = rows.filter((r) => {
    if (filter === "triage" && !r.triaged) return false;
    if (filter === "overdue" && r.overdue === 0) return false;
    if (query && !r.asset.toLowerCase().includes(query.toLowerCase())) return false;
    return true;
  });

  const counts = {
    assets: rows.length,
    triage: rows.filter((r) => r.triaged).length,
    overdue: rows.reduce((n, r) => n + r.overdue, 0),
    unownedItems: rows.filter((r) => r.triaged).reduce((n, r) => n + r.open, 0),
  };

  async function save(asset: string, patch: Partial<AssetOwnershipRow>) {
    const row = rows.find((r) => r.asset === asset);
    if (!row) return;
    try {
      await api.saveOwnership(asset, {
        team: patch.team ?? row.team ?? "",
        owner: patch.owner ?? row.owner ?? "",
        exposure: patch.exposure ?? row.exposure ?? "",
        environment: patch.environment ?? row.environment ?? "",
        criticality: patch.criticality ?? row.criticality ?? "",
        contact: patch.contact ?? row.contact ?? "",
      });
      push(`${asset} → ${(patch.team ?? row.team) || "no team (triage)"}`);
      reload();
    } catch (err) {
      push(err instanceof Error ? err.message : `Could not save ${asset}`);
    }
  }

  function openAccess(row: AssetOwnershipRow) {
    setEditing(row);
    setSSHUser(row.ssh_user ?? "");
    setSSHHost(row.ssh_host ?? "");
    setSSHPort(row.ssh_port ? String(row.ssh_port) : "");
    setSSHJump(row.ssh_jump ?? "");
    setRunbook(row.runbook_url ?? "");
  }

  async function saveAccess() {
    if (!editing) return;
    const row = editing;
    try {
      await api.saveOwnership(row.asset, {
        team: row.team ?? "",
        owner: row.owner ?? "",
        exposure: row.exposure ?? "",
        ssh_user: sshUser.trim(),
        ssh_port: sshPort.trim() === "" ? 0 : Number(sshPort),
        ssh_host: sshHost.trim(),
        ssh_jump: sshJump.trim(),
        runbook_url: runbook.trim(),
      });
      push(`Access details saved for ${row.asset}`);
      setEditing(null);
      reload();
    } catch (err) {
      push(err instanceof Error ? err.message : `Could not save access for ${row.asset}`);
    }
  }

  async function assignSelected() {
    if (!bulkTeam) {
      push("Choose a team first — unowned work belongs in triage.");
      return;
    }
    setSaving(true);
    try {
      const res = await api.bulkOwnership({ assets: selected, team: bulkTeam, owner: bulkOwner });
      const failed = Object.keys(res.failed ?? {});
      push(
        failed.length === 0
          ? `${res.total} asset${res.total === 1 ? "" : "s"} assigned to ${bulkTeam}`
          : `${res.total} assigned, ${failed.length} failed: ${failed.join(", ")}`,
      );
      setSelected([]);
      setBulkOwner("");
      reload();
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not assign these assets");
    } finally {
      setSaving(false);
    }
  }

  function toggle(asset: string) {
    setSelected((prev) => (prev.includes(asset) ? prev.filter((a) => a !== asset) : [...prev, asset]));
  }

  if (loading && !data) return <LoadingBlock label="Loading ownership" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Ownership"
        description="Who is responsible for each asset. Findings route to that team; anything without an owner waits in triage instead of being assigned to a guess."
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: "Assets", value: counts.assets, hint: "with findings or an owner" },
          { label: "Needs an owner", value: counts.triage, hint: "routing will wait" },
          { label: "Unrouted work", value: counts.unownedItems, hint: "items in triage" },
          { label: "Overdue work", value: counts.overdue, hint: "past the SLA" },
        ].map((c) => (
          <Card key={c.label} className="p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted">{c.label}</p>
            <p className="num mt-1 text-2xl font-semibold">{c.value}</p>
            <p className="mt-0.5 text-xs text-subtle">{c.hint}</p>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader
          title="Asset inventory"
          description="Select several assets to give them the same team, or set them one at a time."
        />
        <CardBody className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            {(Object.keys(FILTER_LABEL) as Filter[]).map((f) => (
              <Button key={f} size="sm" variant={filter === f ? "primary" : "secondary"} onClick={() => setFilter(f)}>
                {FILTER_LABEL[f]}
                <span className="ml-1 text-xs opacity-70">
                  {f === "all" ? counts.assets : f === "triage" ? counts.triage : counts.overdue}
                </span>
              </Button>
            ))}
            <div className="ml-auto w-full sm:w-56">
              <label htmlFor="owner-filter" className="sr-only">
                Filter assets by name
              </label>
              <Input
                id="owner-filter"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by asset…"
              />
            </div>
          </div>

          {selected.length > 0 ? (
            <div className="flex flex-wrap items-end gap-2 rounded-md border border-accent/40 bg-accent-soft p-2.5">
              <p className="text-sm font-medium">
                {selected.length} selected
              </p>
              <label className="text-xs text-muted">
                <span className="mb-1 block">Team</span>
                <Select value={bulkTeam} onChange={(e) => setBulkTeam(e.target.value)} aria-label="Team for selected assets">
                  <option value="">Choose a team…</option>
                  {teams.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              </label>
              <label className="text-xs text-muted">
                <span className="mb-1 block">Engineer (optional)</span>
                <Input
                  value={bulkOwner}
                  onChange={(e) => setBulkOwner(e.target.value)}
                  placeholder="e.g. dana"
                  aria-label="Engineer for selected assets"
                />
              </label>
              <Button variant="primary" onClick={assignSelected} disabled={saving || !bulkTeam}>
                {saving ? "Assigning…" : `Assign ${selected.length}`}
              </Button>
              <Button variant="ghost" onClick={() => setSelected([])}>
                Clear
              </Button>
            </div>
          ) : null}

          {visible.length === 0 ? (
            <EmptyState
              title={rows.length === 0 ? "No assets yet" : "Nothing matches this filter"}
              description={
                rows.length === 0
                  ? "Assets appear here once an assessment reports findings for them. Run a scan, or install the agent on an endpoint."
                  : filter === "triage"
                    ? "Every asset has an owner. New assets will appear here when they start reporting."
                    : "Clear the filter to see every asset."
              }
            />
          ) : (
            <TableWrap>
              <Table caption="Assets and their owners">
                <thead>
                  <tr>
                    <Th className="w-8">
                      <input
                        type="checkbox"
                        className="h-4 w-4"
                        aria-label="Select all assets shown"
                        checked={visible.length > 0 && visible.every((r) => selected.includes(r.asset))}
                        onChange={(e) =>
                          setSelected(e.target.checked ? visible.map((r) => r.asset) : [])
                        }
                      />
                    </Th>
                    <Th>Asset</Th>
                    <Th>Work</Th>
                    <Th>Team</Th>
                    <Th>Engineer</Th>
                    <Th>Exposure</Th>
                    <Th>Access</Th>
                    <Th>Updated</Th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((row) => (
                    <Tr key={row.asset} className={row.triaged ? "bg-high-soft/40" : undefined}>
                      <Td>
                        <input
                          type="checkbox"
                          className="h-4 w-4"
                          checked={selected.includes(row.asset)}
                          onChange={() => toggle(row.asset)}
                          aria-label={`Select ${row.asset}`}
                        />
                      </Td>
                      <Td>
                        <span className="mono text-xs">{row.asset}</span>
                        {row.triaged ? (
                          <Badge className="ml-2 border-high/30 bg-high-soft text-high">needs an owner</Badge>
                        ) : null}
                        {row.environment ? <span className="block text-xs text-subtle">{row.environment}</span> : null}
                      </Td>
                      <Td className="whitespace-nowrap text-xs">
                        <span className="num font-medium">{row.open}</span>
                        <span className="text-subtle"> open</span>
                        {row.items !== row.open ? <span className="text-subtle"> of {row.items}</span> : null}
                        <div className="mt-1 flex flex-wrap gap-1">
                          {row.critical > 0 ? (
                            <Badge className="border-critical/30 bg-critical-soft text-critical">{row.critical} critical</Badge>
                          ) : null}
                          {row.overdue > 0 ? (
                            <Badge className="border-critical/40 bg-critical-soft text-critical">{row.overdue} overdue</Badge>
                          ) : null}
                        </div>
                      </Td>
                      <Td>
                        <Select
                          className="min-w-[10.5rem]"
                          value={row.team ?? ""}
                          onChange={(e) => save(row.asset, { team: e.target.value })}
                          aria-label={`Team for ${row.asset}`}
                        >
                          <option value="">No owner recorded</option>
                          {teams.map((t) => (
                            <option key={t} value={t}>
                              {t}
                            </option>
                          ))}
                        </Select>
                        {/* Routing is not ownership: the mapping can send work to a team
                            while nobody has accepted responsibility for the machine. */}
                        {(row.routed_teams ?? []).length > 0 && !row.team ? (
                          <span className="mt-1 block text-xs text-subtle">
                            work maps to {(row.routed_teams ?? []).join(", ")}
                          </span>
                        ) : null}
                      </Td>
                      <Td>
                        <Input
                          className="min-w-[8rem]"
                          key={`${row.asset}-${row.owner ?? ""}`}
                          defaultValue={row.owner ?? ""}
                          placeholder="unassigned"
                          aria-label={`Engineer for ${row.asset}`}
                          onBlur={(e) => {
                            const next = e.target.value.trim();
                            if (next !== (row.owner ?? "")) save(row.asset, { owner: next });
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") e.currentTarget.blur();
                          }}
                        />
                      </Td>
                      <Td>
                        <Select
                          className="min-w-[7.5rem]"
                          value={row.exposure ?? ""}
                          onChange={(e) => save(row.asset, { exposure: e.target.value })}
                          aria-label={`Exposure for ${row.asset}`}
                        >
                          <option value="">unknown</option>
                          <option value="internal">internal</option>
                          <option value="internet">internet</option>
                        </Select>
                      </Td>
                      <Td>
                        <Button size="sm" variant="ghost" onClick={() => openAccess(row)}>
                          <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
                          Access
                        </Button>
                        <span className="block max-w-[12rem] truncate text-xs text-subtle">
                          {row.ssh_user
                            ? `ssh ${row.ssh_user}@${row.ssh_host || row.asset}${row.ssh_jump ? ` via ${row.ssh_jump}` : ""}${
                                row.ssh_port && row.ssh_port !== 22 ? ` :${row.ssh_port}` : ""
                              }`
                            : "not recorded"}
                        </span>
                      </Td>
                      <Td className="whitespace-nowrap text-xs text-muted">
                        {row.status && row.updated_at ? (
                          relativeTime(row.updated_at)
                        ) : (
                          <span className="text-subtle">never recorded</span>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </CardBody>
      </Card>

      <Modal
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
        title={editing ? `Access for ${editing.asset}` : "Access"}
        description="How a person reaches this host. These are references, never credentials, and they are printed into remediation tickets so the owner does not have to ask."
      >
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="SSH user" htmlFor="acc-user" hint="e.g. deploy">
              <Input id="acc-user" value={sshUser} onChange={(e) => setSSHUser(e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Host override" htmlFor="acc-host" hint="Leave empty to use the asset name.">
              <Input id="acc-host" value={sshHost} onChange={(e) => setSSHHost(e.target.value)} autoComplete="off" />
            </Field>
            <Field label="SSH port" htmlFor="acc-port" hint="Leave empty for 22.">
              <Input id="acc-port" inputMode="numeric" value={sshPort} onChange={(e) => setSSHPort(e.target.value)} />
            </Field>
            <Field label="Jump host" htmlFor="acc-jump" hint="Bastion, if the host is not directly reachable.">
              <Input id="acc-jump" value={sshJump} onChange={(e) => setSSHJump(e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Runbook URL" htmlFor="acc-runbook" hint="Your team's procedure for this kind of host.">
              <Input id="acc-runbook" value={runbook} onChange={(e) => setRunbook(e.target.value)} autoComplete="off" />
            </Field>
          </div>
          <div className="rounded-md border border-border bg-surface-2 p-2 text-xs">
            <span className="text-muted">Ticket will show: </span>
            <code className="mono">
              {sshUser.trim()
                ? `ssh${sshPort.trim() && sshPort.trim() !== "22" ? ` -p ${sshPort.trim()}` : ""}${
                    sshJump.trim() ? ` -J ${sshJump.trim()}` : ""
                  } ${sshUser.trim()}@${sshHost.trim() || editing?.asset || ""}`
                : "no connection line (no user recorded)"}
            </code>
          </div>
          <p className="text-xs text-muted">
            Never store a password or key here. The field goes into a ticket body, which is readable by anyone with
            access to the project.
          </p>
          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={saveAccess}>
              Save access
            </Button>
            <Button variant="ghost" onClick={() => setEditing(null)}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>

      <p className="text-xs text-subtle">
        Assigning an asset routes its unowned work to that team and starts its SLA clock. Exposure{" "}
        <span className="mono">internet</span> raises the effective severity by one step, so the deadline is shorter.
      </p>
    </div>
  );
}
