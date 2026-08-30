import { useEffect, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Reveal, useInView } from './reveal';
import { PIPELINE } from './data';

export function Pipeline() {
  const { ref, inView } = useInView<HTMLDivElement>(0.2);
  const [lit, setLit] = useState(0);
  const [active, setActive] = useState<string>(PIPELINE[0].id);

  useEffect(() => {
    if (!inView) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setLit(PIPELINE.length);
      return;
    }
    const t = window.setInterval(() => {
      setLit((n) => {
        if (n >= PIPELINE.length) {
          window.clearInterval(t);
          return n;
        }
        return n + 1;
      });
    }, 260);
    return () => window.clearInterval(t);
  }, [inView]);

  const activeStage = PIPELINE.find((s) => s.id === active)!;

  return (
    <section id="how-it-works" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            How it works
          </p>
          <h2 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            Seven stages, one autonomous run.
          </h2>
        </Reveal>

        <div ref={ref} className="mt-16">
          <ol className="flex flex-col gap-3 lg:flex-row lg:items-stretch lg:gap-2">
            {PIPELINE.map((stage, i) => {
              const on = i < lit;
              const isActive = active === stage.id;
              return (
                <li key={stage.id} className="flex flex-1 items-center gap-2">
                  <button
                    type="button"
                    onMouseEnter={() => setActive(stage.id)}
                    onFocus={() => setActive(stage.id)}
                    onClick={() => setActive(stage.id)}
                    aria-pressed={isActive}
                    className={cn(
                      'surface w-full px-4 py-5 text-left transition-all duration-700 lg:text-center',
                      on ? 'opacity-100' : 'translate-y-2 opacity-30',
                      isActive && 'border-cyan/50 shadow-[var(--glow-brand)]'
                    )}
                  >
                    <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span
                      className={cn(
                        'mt-1 block text-sm font-medium',
                        isActive && 'text-gradient'
                      )}
                    >
                      {stage.name}
                    </span>
                    {'badge' in stage && stage.badge ? (
                      <span className="mt-1 block font-mono text-[10px] text-muted-foreground">
                        {stage.badge}
                      </span>
                    ) : null}
                  </button>
                  {i < PIPELINE.length - 1 && (
                    <ChevronRight
                      aria-hidden
                      className={cn(
                        'hidden size-4 shrink-0 text-muted-foreground transition-opacity duration-700 lg:block',
                        on ? 'opacity-70' : 'opacity-20'
                      )}
                    />
                  )}
                </li>
              );
            })}
          </ol>

          <div className="surface mt-6 min-h-[7rem] p-7">
            <p className="font-mono text-xs tracking-widest text-cyan uppercase">
              {activeStage.name}
            </p>
            <p className="mt-3 max-w-3xl text-base leading-relaxed text-pretty text-muted-foreground">
              {activeStage.desc}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

const LAYERS = [
  { n: '01', t: 'Static rules', d: 'Regex-driven detection over tool definitions and configs — catches hidden HTML comments (CWE-1427), role spoofing, and API key exposure (CWE-798).' },
  { n: '02', t: 'Declared schema', d: 'Schema diff inspection that detects tools accepting undeclared fields not in their inputSchema — the exact pattern used by MCPoison-style attacks.' },
  { n: '03', t: 'LLM semantic reading', d: 'Gemini 2.5 Flash via Vertex AI reads intent, not just syntax — identifies deceptive instructions targeting other LLMs embedded in tool descriptions.' },
  { n: '04', t: 'Embedding drift', d: 'Per-tool baseline embeddings (text-embedding-004) compared via cosine distance on every subsequent scan. Catches "rug-pull" behavior changes invisible to static analysis.' },
];

export function Architecture() {
  return (
    <section id="architecture" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            Architecture
          </p>
          <h2 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            Four independent analysis layers.
          </h2>
        </Reveal>
        <div className="mt-16 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {LAYERS.map((l, i) => (
            <Reveal key={l.n} delay={i * 110}>
              <article className="surface lift h-full p-7">
                <p className="font-mono text-xs text-muted-foreground tabular-nums">{l.n}</p>
                <h3 className="mt-4 text-lg font-medium">{l.t}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{l.d}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
