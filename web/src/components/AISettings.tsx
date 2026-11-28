import { Check, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError, type AIModel, type AIState, type AIProvider } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { relativeTime } from "../lib/format";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader } from "./ui/Card";
import { Collapsible } from "./ui/Collapsible";
import { Banner, LoadingBlock } from "./ui/Feedback";
import { Field, Input, Select } from "./ui/Field";
import { Switch } from "./ui/Switch";
import { useToast } from "./ui/Toast";

/**
 * Settings → AI & Models.
 *
 * The page is ordered the way a person configures it: provider, credential, model. Model
 * lists come from the provider's own API, so the dropdown cannot go stale in the way a
 * hardcoded list would — and when discovery fails, the last good list is shown with a
 * visible warning instead of pretending to be current.
 */
export function AISettings() {
  const toast = useToast();
  const state = useAsync(() => api.aiSettings(), []);
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [settings, setSettings] = useState<AIState["settings"] | null>(null);
  const [credential, setCredential] = useState<AIState["credential"] | null>(null);
  const [catalog, setCatalog] = useState<AIState["catalog"] | null>(null);

  const [apiKey, setApiKey] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [apiVersion, setApiVersion] = useState("");
  const [model, setModel] = useState("");
  const [allowPreview, setAllowPreview] = useState(false);
  const [modelFilter, setModelFilter] = useState("");

  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    if (!state.data) return;
    setProviders(state.data.providers);
    setSettings(state.data.settings);
    setCredential(state.data.credential);
    setCatalog(state.data.catalog);
    setModel(state.data.settings.model ?? "");
    setEndpoint(state.data.settings.endpoint ?? "");
    setApiVersion(state.data.settings.api_version ?? "");
    setAllowPreview(Boolean(state.data.settings.allow_preview));
  }, [state.data]);

  const provider = useMemo(
    () => providers.find((p) => p.id === settings?.provider) ?? null,
    [providers, settings?.provider],
  );

  const models: AIModel[] = catalog?.models ?? [];
  const filteredModels = useMemo(() => {
    const needle = modelFilter.trim().toLowerCase();
    if (!needle) return models;
    return models.filter(
      (m) => m.id.toLowerCase().includes(needle) || m.name.toLowerCase().includes(needle),
    );
  }, [models, modelFilter]);

  async function selectProvider(id: string) {
    const next = providers.find((p) => p.id === id);
    setSettings((s) => (s ? { ...s, provider: id, model: "" } : s));
    setModel("");
    setCatalog(null);
    setCredential(null);
    setEndpoint(next?.needs_endpoint ? endpoint : "");
    setApiKey("");
    try {
      const res = await api.saveAISettings({ provider: id });
      setSettings(res.settings);
      setCredential(res.credential);
      // A provider with no listing API still needs a model name to be useful.
      if (next?.needs_deployment) setModel(res.settings.model ?? "");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not switch provider", "error");
    }
  }

  async function saveCredential() {
    if (!settings?.provider) {
      toast.push("Choose a provider first", "error");
      return;
    }
    if (!apiKey.trim()) {
      toast.push("Paste an API key to save", "error");
      return;
    }
    const providerID = settings.provider;
    setSaving(true);
    try {
      const res = await api.saveAICredential(providerID, apiKey.trim());
      setCredential(res.credential);
      setApiKey("");
      toast.push("Credential saved (encrypted on the server)");
      // A saved key with an empty model list is not usable yet. Fetch the catalog now
      // so choosing a model is the next thing on the page, not a button to discover.
      await discoverModels(providerID, false);
      state.reload();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not save the credential", "error");
    } finally {
      setSaving(false);
    }
  }

  async function removeCredential() {
    if (!settings?.provider) return;
    setSaving(true);
    try {
      const res = await api.deleteAICredential(settings.provider);
      setCredential(res.credential);
      toast.push("Credential removed");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not remove the credential", "error");
    } finally {
      setSaving(false);
    }
  }

  async function saveSettings(next?: { model?: string; endpoint?: string; api_version?: string; allow_preview?: boolean }) {
    if (!settings?.provider) {
      toast.push("Choose a provider first", "error");
      return;
    }
    setSaving(true);
    try {
      const res = await api.saveAISettings({
        provider: settings.provider,
        model: next?.model ?? model,
        endpoint: next?.endpoint ?? endpoint,
        api_version: next?.api_version ?? apiVersion,
        allow_preview: next?.allow_preview ?? allowPreview,
      });
      setSettings(res.settings);
      setCredential(res.credential);
      toast.push("AI settings saved");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not save settings", "error");
    } finally {
      setSaving(false);
    }
  }

  async function testConnection() {
    setTesting(true);
    try {
      const res = await api.testAI();
      toast.push(res.detail || "Connected");
      state.reload();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Connection test failed";
      toast.push(message, "error");
      state.reload();
    } finally {
      setTesting(false);
    }
  }

  // discoverModels asks the provider for its list and stores whatever came back, stale or
  // live. Announce is false when another action already reported its own outcome.
  async function discoverModels(providerID: string, announce: boolean) {
    setRefreshing(true);
    try {
      const res = await api.aiModels(providerID, true);
      setCatalog({
        models: res.models,
        stale: res.stale,
        fetched_at: res.fetched_at,
        warning: res.warning,
        total: res.total,
      });
      if (announce) {
        toast.push(res.stale ? "Discovery failed; showing the last known list" : "Model list refreshed");
      }
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not load the model list", "error");
    } finally {
      setRefreshing(false);
    }
  }

  async function refreshModels() {
    if (!settings?.provider) return;
    await discoverModels(settings.provider, true);
  }

  if (state.loading) return <LoadingBlock label="Loading AI settings" />;
  if (state.error) {
    return (
      <Banner tone="danger" title="AI settings are unavailable">
        {state.error.message}
      </Banner>
    );
  }

  const connected = settings?.last_test_ok === true;
  const configured = Boolean(credential?.configured);

  return (
    <div className="grid gap-3">
      <Card>
        <CardHeader
          title="AI provider"
          description="Credentials are stored server-side, encrypted with a key that never leaves the host."
          actions={
            configured ? (
              <Badge className="border-low/40 bg-low-soft text-low">
                <Check size={12} /> {credential?.mask ?? "configured"}
              </Badge>
            ) : (
              <Badge className="border-border-strong text-muted">no credential</Badge>
            )
          }
        />
        <CardBody className="grid gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Provider" hint={provider?.notes}>
              <Select
                value={settings?.provider ?? ""}
                onChange={(e) => void selectProvider(e.target.value)}
                aria-label="AI provider"
              >
                <option value="">Select a provider…</option>
                {providers.map((p) => (
                  <option key={p.id} value={p.id} disabled={!p.implemented}>
                    {p.label}
                    {p.implemented ? "" : " — not supported yet"}
                  </option>
                ))}
              </Select>
            </Field>

            <Field
              label="API key"
              hint={
                configured
                  ? `Saved (${credential?.source === "environment" ? "injected by the environment" : "encrypted on disk"}). Paste a new value to rotate it.`
                  : provider?.key_hint
                    ? `Looks like: ${provider.key_hint}`
                    : "Paste the key from the provider's console."
              }
            >
              <div className="flex gap-2">
                <Input
                  type="password"
                  value={apiKey}
                  autoComplete="off"
                  placeholder={configured ? credential?.mask ?? "••••" : "paste key"}
                  onChange={(e) => setApiKey(e.target.value)}
                  aria-label="API key"
                />
                <Button onClick={() => void saveCredential()} disabled={saving || !apiKey.trim()}>
                  {saving ? <Loader2 size={14} className="animate-spin" /> : "Save"}
                </Button>
                {configured && credential?.source !== "environment" && (
                  <Button variant="ghost" onClick={() => void removeCredential()} disabled={saving} aria-label="Remove credential">
                    <Trash2 size={14} />
                  </Button>
                )}
              </div>
            </Field>
          </div>

          {(provider?.needs_endpoint || provider?.needs_api_version) && (
            <div className="grid gap-3 sm:grid-cols-2">
              {provider?.needs_endpoint && (
                <Field label="Endpoint" hint="Base URL, for example http://127.0.0.1:11434">
                  <Input value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="http://" />
                </Field>
              )}
              {provider?.needs_api_version && (
                <Field label="API version" hint="Azure resource API version">
                  <Input value={apiVersion} onChange={(e) => setApiVersion(e.target.value)} placeholder="2024-10-21" />
                </Field>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" onClick={() => void testConnection()} disabled={testing || !configured}>
              {testing ? <Loader2 size={14} className="animate-spin" /> : "Test connection"}
            </Button>
            <Button variant="secondary" onClick={() => void refreshModels()} disabled={refreshing || !settings?.provider}>
              {refreshing ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />} Refresh models
            </Button>
            <Button onClick={() => void saveSettings()} disabled={saving}>
              Save settings
            </Button>
            {settings?.last_test_at && (
              <span className="text-xs text-muted">
                Last tested {relativeTime(settings.last_test_at)} — {settings.last_test_detail}
              </span>
            )}
          </div>

          {connected && (
            <Banner tone="success" title="Connected">
              {settings?.last_test_detail}
            </Banner>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="AI model"
          description="Model lists come from the provider's API. Retired models are never offered; preview models are opt-in."
          actions={
            catalog?.fetched_at ? (
              <span className="text-xs text-muted">refreshed {relativeTime(catalog.fetched_at)}</span>
            ) : null
          }
        />
        <CardBody className="grid gap-3">
          {catalog?.stale && (
            <Banner tone="warn" title="Showing a cached model list">
              {catalog.warning || "Discovery failed; this list may be out of date."}
            </Banner>
          )}
          <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
            <Field label="Search" hint={`${filteredModels.length} of ${catalog?.total ?? models.length} models`}>
              <Input
                value={modelFilter}
                onChange={(e) => setModelFilter(e.target.value)}
                placeholder="filter by name or id"
                aria-label="Filter models"
              />
            </Field>
          </div>
          <Field
            label="Model"
            hint={
              provider?.needs_deployment
                ? "Azure uses your deployment name as the model id."
                : "Production models are listed first."
            }
          >
            <Select value={model} onChange={(e) => setModel(e.target.value)} aria-label="AI model">
              <option value="">Select a model…</option>
              {filteredModels.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                  {m.name !== m.id ? ` (${m.id})` : ""}
                  {m.status === "preview" ? " — preview" : ""}
                  {m.pricing_hint ? ` · ${m.pricing_hint} cost` : ""}
                </option>
              ))}
              {provider?.needs_deployment && model && !filteredModels.some((m) => m.id === model) && (
                <option value={model}>{model}</option>
              )}
            </Select>
          </Field>

          {models.length === 0 && (
            <p className="text-xs text-muted">
              {configured
                ? `No models loaded yet. Press Refresh models to ask ${provider?.label ?? "the provider"} for its list.`
                : "Save an API key, then Refresh models fills this list."}
            </p>
          )}

          {models.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {models
                .filter((m) => m.id === model)
                .map((m) => (
                  <div key={m.id} className="flex flex-wrap gap-1.5 text-xs text-muted">
                    {m.context_window ? <Badge>{(m.context_window / 1000).toFixed(0)}k context</Badge> : null}
                    {m.supports_tools ? <Badge>tools</Badge> : null}
                    {m.supports_json ? <Badge>JSON output</Badge> : null}
                    {m.pricing_hint ? <Badge>{m.pricing_hint} cost</Badge> : null}
                    <Badge>{m.status}</Badge>
                  </div>
                ))}
            </div>
          )}

          <Collapsible title="Advanced" summary="Preview models, endpoint overrides">
            <div className="grid gap-3 pt-2">
              <label className="flex items-center justify-between gap-3 text-sm">
                <span>
                  Show preview and experimental models
                  <span className="block text-xs text-muted">
                    Preview models change without notice; only enable this if you are testing one.
                  </span>
                </span>
                <Switch
                  checked={allowPreview}
                  onCheckedChange={(v) => {
                    setAllowPreview(v);
                    void saveSettings({ allow_preview: v });
                  }}
                />
              </label>
              <p className="text-xs text-muted">
                Changing provider or model clears the “connected” state: it described the previous
                configuration, not this one.
              </p>
            </div>
          </Collapsible>
        </CardBody>
      </Card>
    </div>
  );
}

// Keeping the type import used in one place documents the shape the page relies on.
export type { AIProvider };
