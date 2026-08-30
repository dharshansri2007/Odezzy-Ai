import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  variant: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'neutral';
  children: React.ReactNode;
  className?: string;
}

const VARIANTS: Record<StatusBadgeProps['variant'], string> = {
  critical: 'bg-danger/10 text-danger border-danger/30',
  high: 'bg-danger/10 text-danger border-danger/30',
  medium: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
  low: 'bg-cyan/10 text-cyan border-cyan/30',
  info: 'bg-muted text-muted-foreground border-border',
  success: 'bg-safe/10 text-safe border-safe/30',
  warning: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
  neutral: 'bg-muted text-muted-foreground border-border',
};

export function StatusBadge({ variant, children, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-1 font-mono text-[10px] font-medium tracking-wider uppercase',
        VARIANTS[variant],
        className
      )}
    >
      {children}
    </span>
  );
}

export function GradeBadge({ grade }: { grade: string }) {
  const variant =
    grade === 'A' || grade === 'B'
      ? 'success'
      : grade === 'C'
        ? 'warning'
        : 'critical';
  return (
    <span
      className={cn(
        'inline-flex size-10 items-center justify-center rounded-xl font-mono text-lg font-bold',
        VARIANTS[variant]
      )}
    >
      {grade}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const variant = severity as StatusBadgeProps['variant'];
  return <StatusBadge variant={VARIANTS[variant] ? variant : 'neutral'}>{severity}</StatusBadge>;
}
