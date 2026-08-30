import { Check, Github, X } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Reveal } from './reveal';
import { CountUp } from './count-up';
import { COMPARISON, GITHUB_URL, VULNERABILITY_CATEGORIES } from './data';

export function Comparison() {
  return (
    <section id="different" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-5xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            What makes it different
          </p>
          <h2 className="mt-5 text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            Static scanning stops where Odezzy starts.
          </h2>
        </Reveal>

        <Reveal delay={140}>
          <div className="surface mt-14 overflow-x-auto">
            <table className="w-full min-w-[42rem] border-collapse text-left text-sm">
              <caption className="sr-only">
                Capability comparison between static MCP scanners and Odezzy AI
              </caption>
              <thead>
                <tr className="border-b border-border">
                  <th scope="col" className="px-6 py-5 font-medium text-muted-foreground">
                    Capability
                  </th>
                  <th scope="col" className="px-6 py-5 font-medium text-muted-foreground">
                    Static scanners (Cisco, Snyk)
                  </th>
                  <th scope="col" className="px-6 py-5 font-medium">
                    <span className="text-gradient">Odezzy AI</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON.map((row) => (
                  <tr key={row.capability} className="border-b border-border last:border-0">
                    <th scope="row" className="px-6 py-5 font-normal text-muted-foreground">
                      {row.capability}
                    </th>
                    <td className="px-6 py-5">
                      <span className="inline-flex items-center gap-2 text-muted-foreground">
                        <X className="size-4 shrink-0 text-danger" aria-hidden />
                        {row.static}
                      </span>
                    </td>
                    <td className="px-6 py-5">
                      <span className="inline-flex items-center gap-2">
                        <Check className="size-4 shrink-0 text-safe" aria-hidden />
                        {row.odezzy}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

export function VulnerabilityTypes() {
  return (
    <section id="vulnerabilities" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            What we catch
          </p>
          <h2 className="mt-5 text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            Seven categories of MCP vulnerability.
          </h2>
        </Reveal>
        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {VULNERABILITY_CATEGORIES.map((cat, i) => (
            <Reveal key={cat.id} delay={i * 80}>
              <article className="surface lift h-full p-6">
                <span className="text-2xl">{cat.icon}</span>
                <h3 className="mt-3 text-sm font-medium">{cat.name}</h3>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{cat.desc}</p>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

const TRUEFORGE_POINTS = [
  'Session/turn-based human approval gating — TrueForge refuses to forward tool calls until a human clicks approve',
  'Live scan-phase narration streamed into TrueForge\'s chat session UI via createTurn API',
  'Registry cross-reference that catches "shadow" MCP servers not registered in TrueForge',
  'HumanApprovalToken tracks exactly who authorized each quarantine and how (TrueForge UI vs CLI)',
];

export function TrueForge() {
  return (
    <section id="trueforge" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-5xl">
        <Reveal>
          <div className="flex items-center gap-4">
            <span className="rounded-md border border-dashed border-cyan/40 bg-cyan/5 px-4 py-2.5 font-mono text-sm font-semibold tracking-widest text-cyan uppercase">
              TrueForge
            </span>
            <span className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
              Sponsor Integration
            </span>
          </div>
          <h2 className="mt-8 text-3xl font-semibold tracking-tight text-balance sm:text-5xl">
            Built on TrueForge.
          </h2>
          <p className="mt-4 max-w-2xl text-base text-muted-foreground">
            TrueForge isn&apos;t just a provider — it&apos;s the orchestration layer. Odezzy uses
            TrueForge as a Human-In-The-Loop gateway, LLM provider, and MCP registry all in one.
          </p>
        </Reveal>
        <ul className="mt-14 grid gap-4 md:grid-cols-2">
          {TRUEFORGE_POINTS.map((p, i) => (
            <Reveal key={p} delay={i * 120} as="li">
              <div className="surface lift h-full p-7 text-sm leading-relaxed text-muted-foreground">
                <span className="bg-gradient-brand mb-5 block size-1.5 rounded-full" />
                {p}
              </div>
            </Reveal>
          ))}
        </ul>
      </div>
    </section>
  );
}

export function Proof() {
  return (
    <section id="proven" className="snap-start scroll-mt-16 px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-5xl">
        <Reveal>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            Proven, not claimed
          </p>
        </Reveal>
        <div className="mt-12 grid gap-5 sm:grid-cols-3">
          <Reveal delay={80}>
            <div className="surface p-8">
              <p className="font-mono text-3xl font-semibold tabular-nums">
                <CountUp to={72} />/72
              </p>
              <p className="mt-3 text-sm text-muted-foreground">tests passing (vitest)</p>
            </div>
          </Reveal>
          <Reveal delay={200}>
            <div className="surface p-8">
              <p className="font-mono text-3xl font-semibold tabular-nums">
                <CountUp to={9} /> categories
              </p>
              <p className="mt-3 text-sm text-muted-foreground">
                OWASP MCP Top 10 mapped vulnerability types
              </p>
            </div>
          </Reveal>
          <Reveal delay={320}>
            <div className="surface p-8">
              <p className="font-mono text-3xl font-semibold tabular-nums">
                <CountUp to={0} /> API keys
              </p>
              <p className="mt-3 text-sm text-muted-foreground">
                Vertex AI via Application Default Credentials only
              </p>
            </div>
          </Reveal>
        </div>
        <Reveal delay={420}>
          <p className="mt-10 max-w-3xl text-base text-pretty text-muted-foreground">
            Every capability on this page was independently traced, executed, and verified against
            real runs — not just described. The canary server ships with seeded vulnerabilities
            (command injection, prompt poisoning, semantic drift) so you can verify detection yourself.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

export function ClosingCta() {
  return (
    <section
      id="cta"
      className="relative snap-start scroll-mt-16 overflow-hidden px-6 py-32 sm:py-44"
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 h-[30rem] bg-[radial-gradient(50%_60%_at_50%_100%,color-mix(in_oklab,var(--brand-cyan)_14%,transparent),transparent_70%)]"
      />
      <div className="relative mx-auto max-w-4xl text-center">
        <Reveal>
          <h2 className="text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
            Trust, but verify — <span className="text-gradient">automatically.</span>
          </h2>
        </Reveal>
        <Reveal delay={160}>
          <div className="mt-12 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              className="glow-hover bg-gradient-brand inline-flex items-center gap-2 rounded-full px-8 py-4 text-sm font-medium text-primary-foreground"
            >
              <Github className="size-4" />
              View on GitHub
            </a>
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 rounded-full border border-border px-8 py-4 text-sm font-medium text-foreground transition-colors hover:border-cyan/50 hover:bg-elevated"
            >
              Open Dashboard
            </Link>
          </div>
        </Reveal>
      </div>

      <footer className="relative mx-auto mt-28 flex max-w-5xl flex-col items-center gap-4 border-t border-border pt-10 text-center text-sm text-muted-foreground">
        <a
          href={GITHUB_URL}
          target="_blank"
          rel="noreferrer"
          className="font-mono text-xs break-all transition-colors hover:text-foreground"
        >
          {GITHUB_URL}
        </a>
        <p>Built for Agent Harness Hackathon — WeMakeDevs × TrueForge</p>
      </footer>
    </section>
  );
}
