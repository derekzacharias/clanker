import { useState } from "react";
import { KeyRound, Loader2, ShieldCheck, Trash2, UserPlus } from "lucide-react";
import { api, type Account } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Banner } from "./ui/Feedback";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Field, Input, Select } from "./ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "./ui/Table";
import { useToast } from "./ui/Toast";
import { formatDate } from "../lib/format";

/**
 * Settings → Access.
 *
 * Three roles, and the differences are the point: a viewer reads, an operator does the
 * work, an administrator also manages people and configuration. The server enforces it —
 * this screen only explains it and refuses the changes that would lock the organisation out
 * (no last-admin demotion, no self-delete, no self-promotion).
 */
const ROLE_HELP: Record<string, string> = {
  viewer: "Read everything, change nothing.",
  operator: "Assign, accept risk, verify, ticket and scan. No account or configuration changes.",
  admin: "Everything, including accounts and integrations.",
};

export function AccessPanel() {
  const me = useAsync(() => api.accessMe());
  const users = useAsync(() => api.users());
  const { push } = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("operator");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [resetFor, setResetFor] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState("");

  const isAdmin = Boolean(me.data?.permissions.admin);

  async function create() {
    setBusy("create");
    setError(null);
    try {
      await api.createUser({ username: username.trim(), password, role });
      push(`Account ${username.trim()} created with role ${role}`);
      setUsername("");
      setPassword("");
      users.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the account");
    } finally {
      setBusy(null);
    }
  }

  async function change(account: Account, patch: { role?: string; disabled?: boolean }) {
    setBusy(account.username);
    setError(null);
    try {
      await api.updateUser(account.username, patch);
      users.reload();
      me.reload();
      push(`${account.username} updated`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update the account");
    } finally {
      setBusy(null);
    }
  }

  async function resetPassword(account: Account) {
    setBusy(account.username);
    setError(null);
    try {
      await api.updateUser(account.username, { password: newPassword });
      push(`Password reset for ${account.username}; their other sessions were signed out.`);
      setResetFor(null);
      setNewPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset the password");
    } finally {
      setBusy(null);
    }
  }

  async function remove(account: Account) {
    setBusy(account.username);
    setError(null);
    try {
      await api.deleteUser(account.username);
      push(`${account.username} deleted`);
      users.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the account");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-border bg-surface-2 p-3">
        <p className="flex items-center gap-2 text-sm">
          <ShieldCheck className="h-4 w-4 text-accent" aria-hidden="true" />
          You are signed in as <span className="font-medium">{me.data?.username || "—"}</span>
          {me.data?.role ? (
            <Badge className="border-accent/40 bg-accent-soft text-accent">{me.data.role}</Badge>
          ) : null}
        </p>
        <p className="mt-1 text-xs text-muted">
          Roles are checked by the server on every request, so a change applies immediately rather than when a session
          expires. The shared deployment token (<span className="mono">X-Guard-Token</span>) always acts as an
          administrator.
        </p>
      </div>

      {!isAdmin ? (
        <Banner tone="info" title="Managing accounts needs the administrator role">
          Work, tickets and settings are still available to you; creating or changing accounts is not.
        </Banner>
      ) : null}

      {error ? (
        <Banner tone="danger" title="Access change refused">
          {error}
        </Banner>
      ) : null}

      <div>
        {users.data && users.data.items.length > 0 ? (
          <TableWrap>
            <Table caption="Dashboard accounts">
              <thead>
                <tr>
                  <Th>Account</Th>
                  <Th>Role</Th>
                  <Th>State</Th>
                  <Th>Actions</Th>
                </tr>
              </thead>
              <tbody>
                {users.data.items.map((u) => (
                  <Tr key={u.username}>
                    <Td>
                      <span className="font-medium">{u.username}</span>
                      {u.username === me.data?.username ? (
                        <span className="ml-2 text-xs text-subtle">(you)</span>
                      ) : null}
                      <span className="mono block text-xs text-subtle">since {formatDate(u.created_at)}</span>
                    </Td>
                    <Td>
                      <Select
                        value={u.role}
                        disabled={!isAdmin || busy === u.username}
                        onChange={(e) => change(u, { role: e.target.value })}
                        aria-label={`Role for ${u.username}`}
                      >
                        <option value="viewer">viewer</option>
                        <option value="operator">operator</option>
                        <option value="admin">admin</option>
                      </Select>
                    </Td>
                    <Td>
                      {u.disabled ? (
                        <Badge className="border-critical/30 bg-critical-soft text-critical">disabled</Badge>
                      ) : (
                        <Badge className="border-low/30 bg-low-soft text-low">active</Badge>
                      )}
                    </Td>
                    <Td>
                      <div className="flex flex-wrap items-center gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={!isAdmin || busy === u.username}
                          onClick={() => change(u, { disabled: !u.disabled })}
                        >
                          {u.disabled ? "Enable" : "Disable"}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={!isAdmin || busy === u.username}
                          onClick={() => {
                            setResetFor(u.username);
                            setNewPassword("");
                          }}
                        >
                          <KeyRound className="h-3.5 w-3.5" aria-hidden="true" />
                          Reset password
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={!isAdmin || busy === u.username || u.username === me.data?.username}
                          onClick={() => remove(u)}
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                          Delete
                        </Button>
                      </div>
                      {resetFor === u.username ? (
                        <div className="mt-2 flex flex-wrap items-end gap-2">
                          <Field label="New password" htmlFor={`reset-${u.username}`}>
                            <Input
                              id={`reset-${u.username}`}
                              type="password"
                              value={newPassword}
                              onChange={(e) => setNewPassword(e.target.value)}
                              autoComplete="new-password"
                            />
                          </Field>
                          <Button size="sm" variant="primary" onClick={() => resetPassword(u)} disabled={newPassword.length < 10}>
                            Set password
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => setResetFor(null)}>
                            Cancel
                          </Button>
                        </div>
                      ) : null}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        ) : null}
      </div>

      {isAdmin ? (
        <div className="rounded-md border border-border p-3">
          <p className="flex items-center gap-2 text-sm font-medium">
            <UserPlus className="h-4 w-4" aria-hidden="true" />
            Add an account
          </p>
          <div className="mt-2 grid gap-3 sm:grid-cols-3">
            <Field label="Username" htmlFor="new-username">
              <Input id="new-username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
            </Field>
            <Field label="Password" htmlFor="new-password" hint="At least 10 characters.">
              <Input
                id="new-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
            </Field>
            <Field label="Role" htmlFor="new-role" hint={ROLE_HELP[role]}>
              <Select id="new-role" value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="viewer">viewer</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </Select>
            </Field>
          </div>
          <div className="mt-2">
            <Button
              variant="primary"
              onClick={create}
              disabled={busy === "create" || !username.trim() || password.length < 10}
            >
              {busy === "create" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <UserPlus className="h-4 w-4" aria-hidden="true" />}
              Create account
            </Button>
          </div>
        </div>
      ) : null}

      <dl className="grid gap-2 border-t border-border pt-3 text-xs text-muted sm:grid-cols-3">
        <div>
          <dt className="text-subtle">viewer</dt>
          <dd>{ROLE_HELP.viewer}</dd>
        </div>
        <div>
          <dt className="text-subtle">operator</dt>
          <dd>{ROLE_HELP.operator}</dd>
        </div>
        <div>
          <dt className="text-subtle">admin</dt>
          <dd>{ROLE_HELP.admin}</dd>
        </div>
      </dl>
    </div>
  );
}
