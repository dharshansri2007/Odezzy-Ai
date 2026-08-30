import { ArrowDown, Github, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { NodeGraph } from './node-graph';
import { Reveal } from './reveal';
import { GITHUB_URL } from './data';

export function Hero() {
  return (
    <section
      id="hero"
      className="relative flex min-h-[calc(100svh-4rem)] snap-start items-center overflow-hidden"
    >
      <NodeGraph className="pointer-events-none absolute inset-0 size-full opacity-70" />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-1/2 -z-0 h-[42rem] -translate-y-1/2 bg-[radial-gradient(50%_50%_at_50%_50%,color-mix(in_oklab,var(--brand-violet)_16%,transparent),transparent_70%)]"
      />
      <div className="relative mx-auto w-full max-w-5xl px-6 py-24 text-center">
        <Reveal>
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card/50 px-4 py-1.5 text-xs font-medium text-muted-foreground backdrop-blur-sm mb-4">
            <Shield className="size-3.5 text-cyan" />
            Built for WeMakeDevs Agent Harness Hackathon
          </div>
          <p className="font-mono text-xs tracking-[0.28em] text-muted-foreground uppercase">
            Autonomous MCP security agent
          </p>
        </Reveal>
        <Reveal delay={120}>
          <h1 className="mt-7 text-4xl leading-[1.05] font-semibold tracking-tight text-balance sm:text-6xl lg:text-7xl">
            Your AI agents trust their tools.{' '}
            <span className="text-gradient">Nothing verifies that trust.</span>
          </h1>
        </Reveal>
        <Reveal delay={240}>
          <p className="mx-auto mt-8 max-w-2xl text-base leading-relaxed text-pretty text-muted-foreground sm:text-lg">
            Odezzy AI is an autonomous agent that discovers, probes, and cryptographically attests
            every MCP tool your agents can reach — and automatically revokes trust the moment a
            tool&apos;s behavior quietly changes. Powered by Vertex AI (Gemini 2.5 Flash + text-embedding-004)
            and TrueForge human-in-the-loop approval.
          </p>
        </Reveal>
        <Reveal delay={360}>
          <div className="mt-11 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              className="glow-hover bg-gradient-brand inline-flex items-center gap-2 rounded-full px-7 py-3.5 text-sm font-medium text-primary-foreground"
            >
              <Github className="size-4" />
              View on GitHub
            </a>
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 rounded-full border border-border px-7 py-3.5 text-sm font-medium text-foreground transition-colors hover:border-cyan/50 hover:bg-elevated"
            >
              Open Dashboard
              <ArrowDown className="size-4 rotate-[-90deg]" />
            </Link>
            <a
              href="#how-it-works"
              className="inline-flex items-center gap-2 rounded-full border border-border px-7 py-3.5 text-sm font-medium text-foreground transition-colors hover:border-cyan/50 hover:bg-elevated"
            >
              See it run
              <ArrowDown className="size-4" />
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
