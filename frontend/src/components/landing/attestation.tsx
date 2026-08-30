import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';
import { Reveal, useInView } from './reveal';

const BLOCKS = [
  { id: 0, sig: 'ed25519:9f2c…a17b', tool: 'fs.read_file' },
  { id: 1, sig: 'ed25519:41de…08c3', tool: 'http.fetch' },
  { id: 2, sig: 'ed25519:b70a…5f92', tool: 'db.query' },
  { id: 3, sig: 'ed25519:c31f…7ee4', tool: 'shell.exec' },
  { id: 4, sig: 'ed25519:0a8b…d420', tool: 'vector.search' },
];

const REVOKED_INDEX = 3;

export function Attestation() {
  const { ref, inView } = useInView<HTMLDivElement>(0.35);
  const [revoked, setRevoked] = useState(false);

  useEffect(() => {
    if (!inView) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const t = window.setTimeout(() => setRevoked(true), reduced ? 0 : 1400);
    return () => window.clearTimeout(t);
  }, [inView]);

  return (
    <section id="attestation" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            Attestation
          </p>
          <h2 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            A hash-chained record of every tool you trusted.
          </h2>
        </Reveal>

        <div ref={ref} className="mt-16 overflow-x-auto pb-4">
          <ol className="flex min-w-max items-stretch gap-0">
            {BLOCKS.map((b, i) => {
              const isRevoked = revoked && i === REVOKED_INDEX;
              return (
                <li key={b.id} className="flex items-center">
                  <div
                    className={cn(
                      'surface relative w-56 p-5 transition-all duration-700',
                      isRevoked
                        ? 'border-danger/60 bg-danger/5 shadow-[0_0_40px_-14px_var(--danger)]'
                        : 'border-safe/40 shadow-[0_0_40px_-18px_var(--safe)]'
                    )}
                  >
                    <p className="font-mono text-[11px] text-muted-foreground tabular-nums">
                      block #{String(i).padStart(3, '0')}
                    </p>
                    <p className="mt-2 font-mono text-xs">{b.tool}</p>
                    <p
                      className={cn(
                        'mt-3 font-mono text-[11px] break-all transition-colors duration-500',
                        isRevoked ? 'text-danger line-through' : 'text-safe'
                      )}
                    >
                      {b.sig}
                    </p>
                    <p
                      className={cn(
                        'mt-4 inline-flex rounded-full border px-2.5 py-1 font-mono text-[10px] tracking-widest uppercase transition-all duration-500',
                        isRevoked
                          ? 'scale-105 rotate-[-4deg] border-danger/60 text-danger'
                          : 'border-safe/40 text-safe'
                      )}
                    >
                      {isRevoked ? 'Revoked' : 'Attested'}
                    </p>
                  </div>
                  {i < BLOCKS.length - 1 && (
                    <span
                      aria-hidden
                      className="h-px w-8 bg-gradient-to-r from-border to-border/30"
                    />
                  )}
                </li>
              );
            })}
          </ol>
        </div>

        <Reveal delay={120}>
          <p className="mt-8 max-w-3xl text-base leading-relaxed text-pretty text-muted-foreground">
            Independently verifiable by anyone holding the public key — you don&apos;t have to trust
            Odezzy&apos;s runtime output, only the math.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
