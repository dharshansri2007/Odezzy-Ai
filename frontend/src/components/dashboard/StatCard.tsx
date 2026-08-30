import { cn } from '@/lib/utils';
import { CountUp } from '@/components/landing/count-up';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'default' | 'danger' | 'success' | 'warning';
  style?: React.CSSProperties;
}

const ICON_VARIANTS = {
  default: 'bg-primary/10 text-primary',
  danger: 'bg-danger/10 text-danger',
  success: 'bg-safe/10 text-safe',
  warning: 'bg-amber-500/10 text-amber-500',
};

const RING_VARIANTS = {
  default: 'hover:border-primary/30',
  danger: 'hover:border-danger/30',
  success: 'hover:border-safe/30',
  warning: 'hover:border-amber-500/30',
};

export function StatCard({ title, value, subtitle, icon: Icon, variant = 'default', style }: StatCardProps) {
  return (
    <div className={cn('surface lift group fade-up p-6', RING_VARIANTS[variant])} style={style}>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
          <p className="mt-2 font-mono text-3xl font-semibold tabular-nums">
            <CountUp to={value} duration={900} />
          </p>
          {subtitle && <p className="mt-1 truncate text-xs text-muted-foreground">{subtitle}</p>}
        </div>
        <div
          className={cn(
            'rounded-xl p-2.5 transition-transform duration-300 group-hover:scale-110',
            ICON_VARIANTS[variant]
          )}
        >
          <Icon className="size-5" />
        </div>
      </div>
    </div>
  );
}
