/**
 * Trust Engine — pluggable signal registry + weighted policy fusion.
 *
 * Architecture, not invention: this follows the pattern that OPA (input/data/policy
 * separation), SPIFFE/SPIRE (attestor plugins emit evidence, never a final verdict —
 * see spiffe/spire#6640, where SPIRE's own maintainers point composite multi-attestor
 * logic at an external policy layer instead of baking it into attestors), and NIST
 * SP 800-207 (PEP/PDP split, "hybrid trust algorithm": hard criteria gates for
 * non-negotiable checks + score-based fusion for graded signals) all converge on
 * independently: verifiers stay "dumb" (they only ever emit structured evidence,
 * never decide anything), and exactly one place owns combination policy.
 *
 * What this replaces: server.ts previously called sealValidator/rhythmManager/
 * agentClassifier/automationDetector/walletBinder independently, each with its own
 * ad-hoc threshold check inlined at the call site. None of those files changed —
 * they're the "attestors" here, already emitting real evidence (trustImpact,
 * trustScore, confidence, sybilDetected). This module only adds the fusion layer
 * that was missing: a single policy that treats forgeable/binary checks as hard
 * gates and blends the continuous ones instead of evaluating each in isolation.
 */

export interface TrustSignal {
  id: string;
  /** SPIRE-style mandatory selector: failing this alone denies regardless of
   *  every other signal's score. Reserved for checks that are effectively
   *  unforgeable or already independently proven adversarial (PQC session
   *  absent, entropy-seal replay/signature failure, WebDriver artifact). */
  hardFail: boolean;
  /** 0.0 (worst) – 1.0 (best). Ignored when hardFail is true and failing. */
  score: number;
  /** Relative weight in the soft-signal fusion. Ignored for hard-fail signals. */
  weight: number;
  reasons: string[];
}

export type TrustDecision = 'ALLOW' | 'SHADOW_LIMIT' | 'STEP_UP' | 'DENY';

export interface TrustAssessment {
  decision: TrustDecision;
  fusedScore: number;
  hardFailed: boolean;
  signals: TrustSignal[];
  reasons: string[];
  ts: number;
}

// Decision bands. STEP_UP maps to the existing ACTIVE_INTERROGATION_REQUIRED
// behavior at /api/enclave; SHADOW_LIMIT gives the previously-unmounted
// shadowFilter concept (src/middleware/shadowFilter.ts) a real decision to
// drive instead of sitting dead — see SILICON_DNA_LAYERS.md's "RPC Shadow
// Filter" entry for that history.
const BAND_ALLOW = 0.7;
const BAND_STEP_UP = 0.4;
const BAND_SHADOW_LIMIT = 0.2;

/**
 * Weighted fusion, then moderated by the weakest soft signal — not a plain
 * weighted mean. A single very-low-confidence signal (e.g. classifier says
 * MALICIOUS_BOT) should pull the fused score down materially even if every
 * other signal is strong; a plain sum lets strong signals fully paper over
 * one bad one, which is exactly the failure mode the 2025-2026 adaptive-auth
 * literature flags plain criteria/summed scoring for (see research note in
 * commit message). The 0.5 floor keeps one weak signal from being an
 * automatic hard deny on its own — that's what hardFail is for instead.
 */
function fuseSoftSignals(signals: TrustSignal[]): number {
  const soft = signals.filter(s => !s.hardFail);
  if (soft.length === 0) return 1.0;

  const totalWeight = soft.reduce((sum, s) => sum + s.weight, 0) || 1;
  const weightedAvg = soft.reduce((sum, s) => sum + s.score * s.weight, 0) / totalWeight;
  const weakest = Math.min(...soft.map(s => s.score));
  const moderation = 0.5 + 0.5 * weakest;

  return Math.max(0, Math.min(1, weightedAvg * moderation));
}

function bandFor(score: number): TrustDecision {
  if (score >= BAND_ALLOW) return 'ALLOW';
  if (score >= BAND_STEP_UP) return 'STEP_UP';
  if (score >= BAND_SHADOW_LIMIT) return 'SHADOW_LIMIT';
  return 'DENY';
}

/**
 * Policy Engine (NIST 800-207 terms) / decision endpoint (OPA terms). Callers
 * assemble TrustSignal[] from whichever verifiers are relevant to the request
 * — see src/trustSignals.ts for the adapters that do that assembly against
 * this repo's existing sealValidator/rhythmManager/agentClassifier/
 * automationDetector/walletBinder outputs.
 */
export function evaluateTrust(signals: TrustSignal[]): TrustAssessment {
  const failedHard = signals.find(s => s.hardFail && s.score <= 0);

  if (failedHard) {
    return {
      decision: 'DENY',
      fusedScore: 0,
      hardFailed: true,
      signals,
      reasons: [`hard_fail:${failedHard.id}`, ...failedHard.reasons],
      ts: Date.now(),
    };
  }

  const fusedScore = fuseSoftSignals(signals);
  const decision = bandFor(fusedScore);
  const reasons = signals.flatMap(s => s.reasons.map(r => `${s.id}:${r}`));

  return { decision, fusedScore, hardFailed: false, signals, reasons, ts: Date.now() };
}
