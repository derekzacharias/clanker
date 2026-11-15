import { useAsync } from "./useApi";
import { api } from "./api";

/**
 * The running build's version.
 *
 * It comes from the server's unauthenticated `/api/health`, not from a constant baked
 * into the bundle: the point is to show what is actually deployed, so a stale tab
 * reports the server it is talking to rather than the assets it loaded.
 */
export function useAppVersion(): string {
  const { data } = useAsync(() => api.health(), []);
  return data?.version && data.version !== "" ? data.version : "…";
}
