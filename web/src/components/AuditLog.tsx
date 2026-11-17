import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { EmptyState, ErrorState, LoadingBlock } from "./ui/Feedback";
import { Select } from "./ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "./ui/Table";
import { formatDate } from "../lib/format";

/**
 * Settings → Audit log.
 *
 * The answer to "who changed this, and when". Ownership, workflow state, verification,
 * tickets and configuration all land here, because log lines rotate away and those
 * questions get asked months later.
 */
export function AuditLog() {
  const [action, setAction] = useState("");
  const { data, error, loading, reload } = useAsync(() => api.audit({ limit: 200, action: action || undefined }), [action]);

  if (loading && !data) return <LoadingBlock label="Loading audit log" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;

  const items = data?.items ?? [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-muted">
          <span className="mb-1 block">Action</span>
          <Select value={action} onChange={(e) => setAction(e.target.value)} aria-label="Filter by action">
            <option value="">All actions</option>
            {(data?.actions ?? []).map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
        </label>
        <p className="ml-auto text-xs text-subtle">{items.length} entries, newest first · 200 shown at most</p>
      </div>

      {items.length === 0 ? (
        <EmptyState
          title="Nothing recorded yet"
          description="Assignments, workflow changes, verifications, tickets and configuration changes appear here."
        />
      ) : (
        <TableWrap>
          <Table caption="Audit log">
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Who</Th>
                <Th>Action</Th>
                <Th>Target</Th>
                <Th>Detail</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <Tr key={e.seq}>
                  <Td className="whitespace-nowrap text-xs">{formatDate(e.at)}</Td>
                  <Td className="text-xs">{e.actor}</Td>
                  <Td>
                    <span className="mono text-xs">{e.action}</span>
                  </Td>
                  <Td className="mono text-xs">{e.target || "—"}</Td>
                  <Td className="text-xs text-muted">{e.detail || "—"}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </div>
  );
}
