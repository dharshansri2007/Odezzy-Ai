import { Reveal } from './reveal';

function Code({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="surface relative overflow-hidden">
      <div className="flex items-center gap-2 border-b border-border px-5 py-3">
        <span className="size-2.5 rounded-full bg-danger/70" />
        <span className="size-2.5 rounded-full bg-muted-foreground/40" />
        <span className="size-2.5 rounded-full bg-safe/70" />
        <span className="ml-3 font-mono text-xs text-muted-foreground">{title}</span>
      </div>
      <div className="scanlines pointer-events-none absolute inset-0 opacity-40" aria-hidden />
      <pre className="relative overflow-x-auto px-5 py-6 font-mono text-[13px] leading-7 tabular-nums">
        {children}
      </pre>
    </div>
  );
}

export function MathSection() {
  return (
    <section id="the-math" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            The math
          </p>
          <h2 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            No hand-waving. These are the actual formulas.
          </h2>
        </Reveal>

        <div className="mt-16 grid gap-5 lg:grid-cols-2">
          <Reveal delay={80}>
            <Code title="risk-score.ts">
              <code>
                <span className="text-cyan">score</span> = Σ (severityWeight × confidence) for every
                finding on a tool/server{'\n\n'}
                <span className="text-cyan">severityWeight</span> ={' {'} critical: 10, high: 7,
                medium: 4, low: 2, info: 1 {'}'}
                {'\n\n'}
                <span className="text-cyan">normalizedScore</span> = min(round(score × 10), 100)
                {'\n\n'}
                <span className="text-muted-foreground">grade:</span>
                {'\n'} 0 → <span className="text-safe">A</span>
                {'\n'} 1–24 → <span className="text-safe">B</span>
                {'\n'} 25–49 → C{'\n'} 50–74 → <span className="text-danger">D</span>
                {'\n'} 75–100 → <span className="text-danger">F</span>
              </code>
            </Code>
          </Reveal>

          <Reveal delay={200}>
            <Code title="drift-detection.ts">
              <code>
                <span className="text-cyan">distance</span> = cosineDistance(baselineEmbedding,
                currentEmbedding){'\n\n'}
                distance &lt; 0.10 → <span className="text-safe">stable, no action</span>
                {'\n'}
                distance ≥ 0.10 → possible drift, flagged{'\n'}
                distance ≥ 0.25 →{' '}
                <span className="text-danger">
                  high-confidence drift, attestation automatically revoked
                </span>
                {'\n\n'}
                <span className="text-cyan">confidence</span> = min(0.6 + distance, 0.95)
              </code>
            </Code>
          </Reveal>
        </div>

        <Reveal delay={320}>
          <p className="mt-10 max-w-3xl text-base leading-relaxed text-pretty text-muted-foreground">
            Embeddings generated via Vertex AI text-embedding-004, compared against a stored
            per-tool baseline on every subsequent scan — this is what catches a tool that quietly
            changes meaning <em>after</em> a human already approved it, which static
            description-reading can never catch.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
