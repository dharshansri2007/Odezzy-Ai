import { NavLink, Outlet } from 'react-router-dom';
import { Link } from 'react-router-dom';
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
} from 'lucide-react';
import { cn } from '@/lib/utils';

const NAV_ITEMS = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview', end: true },
  { to: '/dashboard/scans', icon: Search, label: 'Scans' },
  { to: '/dashboard/findings', icon: Bug, label: 'Findings' },
  { to: '/dashboard/servers', icon: Blocks, label: 'Servers' },
  { to: '/dashboard/attestation', icon: Award, label: 'Attestation' },
  { to: '/dashboard/quarantine', icon: Ban, label: 'Quarantine' },
  { to: '/dashboard/reports', icon: FileText, label: 'Reports' },
  { to: '/dashboard/logs', icon: Terminal, label: 'Logs' },
];

export function DashboardLayout() {
  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <aside className="flex w-64 flex-col border-r border-border bg-card">
        <div className="flex h-16 items-center gap-2.5 border-b border-border px-6">
          <span className="bg-gradient-brand size-6 rounded-md shadow-[0_0_18px_-2px_var(--brand-violet)]" />
          <span className="font-semibold tracking-tight">Odezzy AI</span>
        </div>

        <nav className="flex-1 overflow-y-auto p-3">
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-primary/10 text-primary'
                        : 'text-muted-foreground hover:bg-elevated hover:text-foreground'
                    )
                  }
                >
                  <item.icon className="size-4" />
                  {item.label}
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
                  isActive
                    ? 'bg-cyan/10 text-cyan'
                    : 'text-muted-foreground hover:bg-elevated hover:text-foreground'
                )
              }
            >
              <Shield className="size-4" />
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
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
