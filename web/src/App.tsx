import { AppShell } from "./components/AppShell";
import { ToastProvider } from "./components/ui/Toast";
import { matchRoute, usePathname } from "./lib/router";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import AssetDetail from "./pages/AssetDetail";
import Vulnerabilities from "./pages/Vulnerabilities";
import Scans from "./pages/Scans";
import NewScan from "./pages/NewScan";
import ReportView from "./pages/ReportView";
import Settings from "./pages/Settings";
import Remediation from "./pages/Remediation";

function Routes() {
  const pathname = usePathname();

  if (pathname === "/" || pathname === "") return <Overview />;
  if (pathname === "/assets") return <Assets />;
  const asset = matchRoute("/assets/:host", pathname);
  if (asset) return <AssetDetail host={asset.host} />;
  if (pathname === "/vulnerabilities") return <Vulnerabilities />;
  if (pathname === "/scans") return <Scans />;
  if (pathname === "/scans/new") return <NewScan />;
  if (pathname === "/remediation") return <Remediation />;
  // Old bookmarks keep working: ownership moved inside Remediation, reports inside Scans.
  if (pathname === "/ownership") return <Remediation initialTab="ownership" />;
  if (pathname === "/reports") return <Scans initialTab="reports" />;
  const report = matchRoute("/reports/:id", pathname);
  if (report) return <ReportView id={report.id} />;
  if (pathname === "/settings") return <Settings />;

  return (
    <div className="mx-auto max-w-lg py-16 text-center">
      <h1 className="text-lg font-semibold">Page not found</h1>
      <p className="mt-1 text-sm text-muted">The address {pathname} does not match any screen.</p>
      <a href="/" className="mt-4 inline-block text-sm text-accent underline underline-offset-2">
        Back to overview
      </a>
    </div>
  );
}

export default function App() {
  const pathname = usePathname();
  // The sign-in screen renders outside the shell: it has no navigation, and it
  // must be reachable before a session exists.
  if (pathname === "/login") {
    return (
      <ToastProvider>
        <Login />
      </ToastProvider>
    );
  }
  return (
    <ToastProvider>
      <AppShell>
        <Routes />
      </AppShell>
    </ToastProvider>
  );
}
