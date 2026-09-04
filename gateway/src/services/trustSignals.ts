/**
 * Trust signal adapters — turn this repo's existing verifiers into the
 * TrustSignal shape trustEngine.ts fuses. Each adapter wraps one existing
 * check unmodified; none of sealValidator.ts / rhythmManager.ts /
 * agentClassifier.ts / automationDetector.ts / walletBinder.ts changed to
 * support this. That's deliberate — per trustEngine.ts's header, verifiers
 * stay "dumb" (evidence producers), only this module and trustEngine.ts know
 * about fusion policy.
 */
import type { TrustSignal } from './trustEngine';
import type { AgentClass } from './agentClassifier';

export function pqcSessionSignal(sessionEstablished: boolean): TrustSignal {
  return {
    id: 'pqc_session',
    hardFail: true,
    score: sessionEstablished ? 1 : 0,
    weight: 0,
    reasons: sessionEstablished ? [] : ['no ML-KEM-768 session established'],
  };
}

export function entropySealSignal(sealValid: boolean, reason?: string): TrustSignal {
  return {
    id: 'entropy_seal',
    hardFail: true,
    score: sealValid ? 1 : 0,
    weight: 0,
    reasons: sealValid ? [] : [reason ?? 'entropy seal invalid'],
  };
}

export function automationSignal(detected: boolean, reasons: string[]): TrustSignal {
  return {
    id: 'automation',
    hardFail: true,
    score: detected ? 0 : 1,
    weight: 0,
    reasons: detected ? reasons : [],
  };
}

export function frankensteinSignal(score: number): TrustSignal {
  // Matches sniperFilter's existing >=100 immediate-ban threshold — kept as a
  // hard gate here for the same reason automation/entropy-seal are: this
  // check is already treated as independently sufficient to ban in server.ts,
  // so folding it into soft fusion would weaken a decision this repo already
  // relies on elsewhere.
  const failed = score >= 100;
  return {
    id: 'frankenstein',
    hardFail: failed,
    score: failed ? 0 : Math.max(0, 1 - score / 100),
    weight: 1,
    reasons: failed ? [`frankenstein score ${score} >= 100`] : score > 0 ? [`frankenstein score ${score}`] : [],
  };
}

export function rhythmTrustSignal(trustScore: number): TrustSignal {
  return {
    id: 'rhythm',
    hardFail: false,
    score: Math.max(0, Math.min(1, trustScore)),
    weight: 2, // Gaussian-scored, session-persistent — weighted higher than one-shot signals
    reasons: [`rhythm trustScore=${trustScore.toFixed(2)}`],
  };
}

export function classifierSignal(agentClass: AgentClass, confidence: number): TrustSignal {
  // classifyAgent's confidence is "how sure are we about this class," not
  // "how trustworthy is this session" — a confident MALICIOUS_BOT call must
  // map to a LOW score, not a high one. HUMAN and LEGIT_AGENT both count as
  // legitimate traffic for this gate (LEGIT_AGENT is the expected shape for
  // most callers here), so both map confidence directly to score.
  const score = agentClass === 'MALICIOUS_BOT' ? 1 - confidence : confidence;
  return {
    id: 'classifier',
    hardFail: false,
    score,
    weight: 1.5,
    reasons: [`class=${agentClass} confidence=${confidence.toFixed(2)}`],
  };
}

export function walletSybilSignal(sharedWallets: number, sybilThreshold = 3): TrustSignal {
  // sharedWallets=1 (unique fingerprint, no sharing) -> score 1. At the
  // threshold and beyond, score bottoms out rather than hitting exactly 0 —
  // this is a soft signal (fed into fusion), not the hard hasSybilBeenFlagged
  // gate walletBinder.ts already exposes separately for callers that want
  // a binary cutoff instead.
  const score = Math.max(0, 1 - (sharedWallets - 1) / sybilThreshold);
  return {
    id: 'wallet_sybil',
    hardFail: false,
    score,
    weight: 1,
    reasons: sharedWallets > 1 ? [`behavioral fingerprint shared by ${sharedWallets} wallets`] : [],
  };
}
