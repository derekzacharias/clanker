import { KeyRound, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { getToken, setToken } from "../lib/api";
import { Modal } from "./ui/Dialog";
import { Button } from "./ui/Button";
import { Input } from "./ui/Field";

/**
 * Shown when the server requires an API token (any non-loopback bind) and the
 * browser has not supplied one. The token is stored locally in this browser and
 * sent as X-Guard-Token; it is never sent anywhere else.
 */
export function AuthGate({
  reason = "required",
  onAuthenticated,
  onClose,
}: {
  reason?: "required" | "rejected" | "manual";
  onAuthenticated: () => void;
  onClose?: () => void;
}) {
  const [value, setValue] = useState(() => getToken());
  const [error, setError] = useState<string | null>(null);

  function save() {
    const trimmed = value.trim();
    if (!trimmed) {
      setError("Enter the token printed by `clanker vuln serve`.");
      return;
    }
    setToken(trimmed);
    setError(null);
    onAuthenticated();
  }

  return (
    <Modal
      open
      onOpenChange={(open) => {
        if (!open) onClose?.();
      }}
      title={
        <span className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-high" aria-hidden="true" /> This server requires an API token
        </span>
      }
      description={
        reason === "rejected"
          ? "The stored token was rejected by the server and has been cleared. Paste the current token to continue."
          : "It is listening beyond localhost, so control of scans requires authentication."
      }
      footer={
        <>
          <Button variant="ghost" onClick={() => window.location.assign("/")}>
            Reload
          </Button>
          <Button variant="primary" onClick={save}>
            <KeyRound className="h-4 w-4" aria-hidden="true" /> Unlock
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div>
          <label htmlFor="auth-token" className="block text-xs font-medium text-muted">
            API token
          </label>
          <Input
            id="auth-token"
            type="password"
            autoComplete="off"
            autoFocus
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") save();
            }}
            placeholder="CLANKER_GUARD_TOKEN value"
            aria-describedby="auth-hint"
          />
          <p id="auth-hint" className="mt-1 text-xs text-muted">
            Printed when the server starts, or set via <span className="mono">CLANKER_GUARD_TOKEN</span>. Stored in this
            browser only.
          </p>
        </div>
        {error ? (
          <p role="alert" className="text-sm text-critical">
            {error}
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
