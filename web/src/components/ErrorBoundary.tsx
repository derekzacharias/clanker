import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "./ui/Button";

/**
 * Catches render errors so a bad payload or a bug shows a recoverable card
 * instead of a blank, flickering page.
 */
export class ErrorBoundary extends Component<
  { children: ReactNode; resetKey?: string | number; onReset?: () => void },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Console is the only sink: no telemetry, no uploads.
    console.error("Clanker Guard: screen crashed", error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey?: string | number }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div role="alert" className="mx-auto max-w-2xl">
        <div className="card p-5">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 text-critical" aria-hidden="true" />
            <div className="min-w-0">
              <h2 className="text-sm font-semibold">This screen could not be displayed</h2>
              <p className="mt-1 text-sm text-muted">
                The rest of the interface still works. This usually means the server sent a payload this build did not
                expect.
              </p>
              <pre className="mono mt-3 max-h-40 overflow-auto rounded-md border border-border bg-surface-2 p-2 text-xs">
                {this.state.error.message}
              </pre>
              <div className="mt-3 flex gap-2">
                <Button
                  variant="primary"
                  onClick={() => {
                    this.setState({ error: null });
                    this.props.onReset?.();
                  }}
                >
                  <RefreshCw className="h-4 w-4" aria-hidden="true" /> Try this screen again
                </Button>
                <Button variant="ghost" onClick={() => window.location.assign("/")}>
                  Go to overview
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }
}
