import { useRef } from 'react';
import { Nav } from '@/components/landing/nav';
import { Hero } from '@/components/landing/hero';
import { Problem } from '@/components/landing/problem';
import { Pipeline, Architecture } from '@/components/landing/pipeline';
import { MathSection } from '@/components/landing/math-section';
import { Attestation } from '@/components/landing/attestation';
import { Comparison, VulnerabilityTypes, TrueForge, Proof, ClosingCta } from '@/components/landing/closing';

export default function Landing() {
  const scroller = useRef<HTMLDivElement>(null);

  return (
    <div
      ref={scroller}
      className="h-svh snap-y snap-proximity overflow-x-hidden overflow-y-auto scroll-smooth"
    >
      <Nav scroller={scroller} />
      <main>
        <Hero />
        <Problem />
        <Pipeline />
        <Architecture />
        <MathSection />
        <Attestation />
        <VulnerabilityTypes />
        <Comparison />
        <TrueForge />
        <Proof />
        <ClosingCta />
      </main>
    </div>
  );
}
