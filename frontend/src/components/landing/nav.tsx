import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Github, Moon, Sun, LayoutDashboard } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useTheme } from '@/lib/theme';
import { GITHUB_URL } from './data';

const LINKS = [
  { href: '#problem', label: 'Problem' },
  { href: '#how-it-works', label: 'How it works' },
  { href: '#architecture', label: 'Architecture' },
  { href: '#the-math', label: 'The Math' },
  { href: '#attestation', label: 'Attestation' },
];

export function Nav({ scroller }: { scroller?: React.RefObject<HTMLDivElement | null> }) {
  const [scrolled, setScrolled] = useState(false);
  const { theme, toggleTheme } = useTheme();
  const light = theme === 'light';

  useEffect(() => {
    const el = scroller?.current;
    const target: HTMLElement | Window = el ?? window;
    const onScroll = () => {
      const y = el ? el.scrollTop : window.scrollY;
      setScrolled(y > 24);
    };
    target.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => target.removeEventListener('scroll', onScroll);
  }, [scroller]);

  return (
    <header
      className={cn(
        'sticky top-0 z-50 transition-all duration-500',
        scrolled
          ? 'border-b border-border bg-background/70 backdrop-blur-xl supports-[backdrop-filter]:bg-background/55'
          : 'border-b border-transparent'
      )}
    >
      <nav
        aria-label="Primary"
        className="mx-auto flex h-16 w-full max-w-7xl items-center gap-6 px-6"
      >
        <a href="#hero" className="flex items-center gap-2.5 font-semibold tracking-tight">
          <span className="bg-gradient-brand size-6 rounded-md shadow-[0_0_18px_-2px_var(--brand-violet)]" />
          <span>Odezzy AI</span>
        </a>

        <ul className="ml-auto hidden items-center gap-7 text-sm text-muted-foreground lg:flex">
          {LINKS.map((l) => (
            <li key={l.href}>
              <a href={l.href} className="transition-colors hover:text-foreground">
                {l.label}
              </a>
            </li>
          ))}
        </ul>

        <div className="ml-auto flex items-center gap-2 lg:ml-0">
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 rounded-full border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground hover:border-cyan/50"
          >
            <LayoutDashboard className="size-4" />
            Dashboard
          </Link>
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={light ? 'Switch to dark mode' : 'Switch to light mode'}
            className="grid size-9 place-items-center rounded-full border border-border text-muted-foreground transition-all duration-300 hover:border-cyan/40 hover:text-foreground active:scale-90"
          >
            {light ? <Moon className="size-4" /> : <Sun className="size-4" />}
          </button>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
            className="glow-hover bg-gradient-brand inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium text-primary-foreground"
          >
            <Github className="size-4" />
            GitHub
          </a>
        </div>
      </nav>
    </header>
  );
}
