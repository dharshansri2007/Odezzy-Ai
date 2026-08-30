import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  variant: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'neutral';
  children: React.ReactNode;
  className?: string;
}

const VARIANTS: Record<StatusBadgeProps['variant'], string> = {
  critical: 'bg-danger/10 text-danger border-danger/25',
  high: 'bg-danger/10 text-danger border-danger/25',
  medium: 'bg-amber-500/10 text-amber-500 border-amber-500/25',
  low: 'bg-cyan/10 text-cyan border-cyan/25',
  info: 'bg-muted text-muted-foreground border-border',
  success: 'bg-safe/10 text-safe border-safe/25',
  warning: 'bg-amber-500/10 text-amber-500 border-amber-500/25',
  neutral: 'bg-muted text-muted-foreground border-border',
};

export function StatusBadge({ variant, children, className }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 font-mono text-[10px] font-medium tracking-wider uppercase transition-colors',
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
    grade === 'A' || grade === 'B' ? 'success' : grade === 'C' ? 'warning' : 'critical';
  return (
    <span
      className={cn(
        'inline-flex size-10 shrink-0 items-center justify-center rounded-xl border font-mono text-lg font-bold',
        VARIANTS[variant]
      )}
    >
      {grade}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const variant = severity as StatusBadgeProps['variant'];
  return (
    <StatusBadge variant={VARIANTS[variant] ? variant : 'neutral'}>
      <span
        className={cn(
          'size-1.5 rounded-full',
          variant === 'critical' || variant === 'high'
            ? 'bg-danger'
            : variant === 'medium'
              ? 'bg-amber-500'
              : variant === 'low'
                ? 'bg-cyan'
                : 'bg-muted-foreground'
        )}
      />
      {severity}
    </StatusBadge>
  );
}
