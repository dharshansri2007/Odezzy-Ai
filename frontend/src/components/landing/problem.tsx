import { CountUp } from './count-up';
import { Reveal } from './reveal';

export function Problem() {
  return (
    <section id="problem" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            The problem
          </p>
          <h2 className="mt-5 max-w-3xl text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            The MCP supply chain is already leaking.
          </h2>
        </Reveal>

        <div className="mt-16 grid gap-5 md:grid-cols-3">
          <Reveal delay={80}>
            <article className="surface lift h-full p-8">
              <p className="font-mono text-4xl font-semibold tabular-nums sm:text-5xl">
                <CountUp to={24008} />
              </p>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
                secrets found in public MCP config files —{' '}
                <span className="font-mono text-danger tabular-nums">
                  <CountUp to={2117} /> still valid
                </span>
              </p>
              <p className="mt-6 font-mono text-[11px] tracking-wider text-muted-foreground/70 uppercase">
                Source: GitGuardian, 2026
              </p>
            </article>
          </Reveal>

          <Reveal delay={200}>
            <article className="surface lift h-full p-8">
              <p className="font-mono text-4xl font-semibold tabular-nums sm:text-5xl">
                CVSS <CountUp to={7.2} decimals={1} />
              </p>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
                MCPoison (CVE-2025-54136) let attackers silently swap a trusted MCP config for a
                malicious one.
              </p>
              <p className="mt-6 font-mono text-[11px] tracking-wider text-danger/80 uppercase">
                Silent config substitution
              </p>
            </article>
          </Reveal>

          <Reveal delay={320}>
            <article className="surface lift h-full p-8">
              <p className="font-mono text-4xl font-semibold tabular-nums sm:text-5xl">
                <CountUp to={0} /> of the major scanners
              </p>
              <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
                checked (Cisco mcp-scanner, Snyk mcp-scan) actually call a tool to see what it does
                — all are static-only.
              </p>
              <p className="mt-6 font-mono text-[11px] tracking-wider text-muted-foreground/70 uppercase">
                Static analysis only
              </p>
            </article>
          </Reveal>
        </div>

        <Reveal delay={420}>
          <p className="mt-14 max-w-3xl text-base text-pretty text-muted-foreground sm:text-lg">
            Enterprise platforms (Astrix, Oasis, Aembit) solve this behind six- and seven-figure
            contracts. Nothing open does it at this depth.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
