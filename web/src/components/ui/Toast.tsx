import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { cn } from "../../lib/cn";

type Toast = { id: number; message: string; tone: "success" | "error" };

const ToastContext = createContext<{ push: (message: string, tone?: "success" | "error") => void }>({
  push: () => {},
});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((message: string, tone: "success" | "error" = "success") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message, tone }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);
  const value = useMemo(() => ({ push }), [push]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div aria-live="polite" aria-atomic="false" className="pointer-events-none fixed bottom-4 right-4 z-[70] space-y-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cn(
              "pointer-events-auto flex items-center gap-2 rounded-md border px-3 py-2 text-sm shadow-lg",
              t.tone === "success"
                ? "border-low/30 bg-low-soft text-fg"
                : "border-critical/30 bg-critical-soft text-fg",
            )}
          >
            {t.tone === "success" ? (
              <CheckCircle2 className="h-4 w-4 text-low" aria-hidden="true" />
            ) : (
              <XCircle className="h-4 w-4 text-critical" aria-hidden="true" />
            )}
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
