import { NavLink, Outlet, useLocation, Link } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Search,
  Bug,
  Award,
  Ban,
  FileText,
  Terminal,
  ArrowLeft,
  Blocks,
  Moon,
  Sun,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/lib/theme';
import { useDemoMode } from '@/lib/demo-mode';
import { DemoBanner } from './DemoBanner';

const NAV_ITEMS = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview', end: true, blurb: 'Fleet-wide security posture' },
  { to: '/dashboard/scans', icon: Search, label: 'Scans', blurb: 'Trigger and review scan sessions' },
  { to: '/dashboard/findings', icon: Bug, label: 'Findings', blurb: 'Every discovered vulnerability' },
  { to: '/dashboard/servers', icon: Blocks, label: 'Servers', blurb: 'Discovered MCP servers and tools' },
  { to: '/dashboard/attestation', icon: Award, label: 'Attestation', blurb: 'Signed, hash-chained trust ledger' },
  { to: '/dashboard/quarantine', icon: Ban, label: 'Quarantine', blurb: 'Tools banned pending review' },
  { to: '/dashboard/reports', icon: FileText, label: 'Reports', blurb: 'Governance report for the latest scan' },
  { to: '/dashboard/logs', icon: Terminal, label: 'Logs', blurb: 'Live output from the agent' },
];

function useActiveNavItem() {
  const { pathname } = useLocation();
  const sorted = [...NAV_ITEMS].sort((a, b) => b.to.length - a.to.length);
  return sorted.find((item) => (item.end ? pathname === item.to : pathname.startsWith(item.to))) ?? NAV_ITEMS[0];
}

function Topbar() {
  const active = useActiveNavItem();
  const { theme, toggleTheme } = useTheme();
  const demo = useDemoMode();

  return (
    <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center gap-4 border-b border-border bg-background/85 px-8 backdrop-blur-md">
      <div className="min-w-0">
        <h1 className="truncate text-sm font-semibold tracking-tight">{active.label}</h1>
        <p className="truncate text-xs text-muted-foreground">{active.blurb}</p>
      </div>

      <div className="ml-auto flex items-center gap-3">
        <span
          className={cn(
            'pulse-dot inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-medium uppercase tracking-wider',
            demo ? 'border-cyan/30 text-cyan' : 'border-safe/30 text-safe'
          )}
        >
          <span className={cn('size-1.5 rounded-full', demo ? 'bg-cyan' : 'bg-safe')} />
          {demo ? 'Demo data' : 'Live'}
        </span>
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
          className="grid size-9 place-items-center rounded-full border border-border text-muted-foreground transition-all duration-300 hover:border-cyan/40 hover:text-foreground active:scale-90"
        >
          {theme === 'light' ? <Moon className="size-4" /> : <Sun className="size-4" />}
        </button>
      </div>
    </header>
  );
}

export function DashboardLayout() {
  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-card">
        <Link to="/" className="flex h-16 items-center gap-2.5 border-b border-border px-6">
          <span className="bg-gradient-brand size-6 shrink-0 rounded-md shadow-[0_0_18px_-2px_var(--brand-violet)]" />
          <span className="font-semibold tracking-tight">Odezzy AI</span>
        </Link>

        <nav className="flex-1 overflow-y-auto p-3">
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      'group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200',
                      isActive
                        ? 'bg-primary/10 text-primary'
                        : 'text-muted-foreground hover:bg-elevated hover:text-foreground'
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <span
                        className={cn(
                          'absolute left-0 h-5 w-0.5 rounded-full bg-primary transition-opacity duration-200',
                          isActive ? 'opacity-100' : 'opacity-0'
                        )}
                      />
                      <item.icon className="size-4 shrink-0 transition-transform duration-200 group-hover:scale-110" />
                      {item.label}
                    </>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>

          <div className="mt-6 border-t border-border pt-4">
            <NavLink
              to="/trueforge"
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive ? 'bg-cyan/10 text-cyan' : 'text-muted-foreground hover:bg-elevated hover:text-foreground'
                )
              }
            >
              <Shield className="size-4 shrink-0" />
              TrueForge Dashboard
            </NavLink>
          </div>
        </nav>

        <div className="border-t border-border p-3">
          <Link
            to="/"
            className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft className="size-4" />
            Back to Landing Page
          </Link>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-7xl">
            <DemoBanner />
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
