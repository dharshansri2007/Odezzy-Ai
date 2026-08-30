import { cn } from '@/lib/utils';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: 'up' | 'down' | 'neutral';
  variant?: 'default' | 'danger' | 'success' | 'warning';
}

const ICON_VARIANTS = {
  default: 'bg-primary/10 text-primary',
  danger: 'bg-danger/10 text-danger',
  success: 'bg-safe/10 text-safe',
  warning: 'bg-amber-500/10 text-amber-500',
};

export function StatCard({ title, value, subtitle, icon: Icon, variant = 'default' }: StatCardProps) {
  return (
    <div className="surface p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="mt-2 font-mono text-3xl font-semibold tabular-nums">{value}</p>
          {subtitle && (
            <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
          )}
        </div>
        <div className={cn('rounded-xl p-2.5', ICON_VARIANTS[variant])}>
          <Icon className="size-5" />
        </div>
      </div>
    </div>
  );
}
