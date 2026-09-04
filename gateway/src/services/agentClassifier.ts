/**
 * 3-class request classifier: HUMAN / LEGIT_AGENT / MALICIOUS_BOT
 *
 * Scoring is additive; the class with the highest score wins.
 * Confidence = winner_score / total_score (0–1).
 */

export type AgentClass = 'HUMAN' | 'LEGIT_AGENT' | 'MALICIOUS_BOT';

export interface ClassificationInput {
  ua: string;
  spearmanRho: number;
  variance: number;
  entropy: number;
  frankensteinScore: number;
  hasPoW: boolean;
  headers: Record<string, string | undefined>;
}

export interface ClassificationResult {
  agentClass: AgentClass;
  confidence: number;
  signals: string[];
}

const KNOWN_AGENT_UA: RegExp[] = [
  /anthropic/i, /claude/i, /openai/i, /gpt/i, /gemini/i,
  /cohere/i, /perplexity/i, /langchain/i, /autogpt/i,
  /python-httpx/i, /python-requests/i, /axios/i, /got\//i,
  /node-fetch/i, /undici/i, /agentic/i,
];

const MALICIOUS_BOT_UA: RegExp[] = [
  /puppeteer/i, /selenium/i, /phantomjs/i, /headless/i,
  /playwright/i, /webdriver/i, /scrapy/i, /masscan/i,
];

export function classifyAgent(input: ClassificationInput): ClassificationResult {
  const signals: string[] = [];
  let h = 0; // human score
  let a = 0; // agent score
  let b = 0; // bot score

  // ── Spearman ρ ──────────────────────────────────────────────────────────────
  if (input.spearmanRho > 0.6) {
    h += 30; signals.push('rho:high→human');
  } else if (input.spearmanRho >= 0.3) {
    a += 15; signals.push('rho:mid→agent');
  } else {
    b += 25; signals.push('rho:low→bot');
  }

  // ── Variance ────────────────────────────────────────────────────────────────
  if (input.variance >= 2.0 && input.variance < 10.0) {
    h += 20; signals.push('variance:natural→human');
  } else if (input.variance < 0.5) {
    b += 30; signals.push('variance:zero→bot');
  } else if (input.variance < 2.0) {
    a += 20; signals.push('variance:low_nonzero→agent');
  } else {
    b += 15; signals.push('variance:chaotic→bot');
  }

  // ── Entropy ─────────────────────────────────────────────────────────────────
  if (input.entropy > 2.5) {
    h += 15; signals.push('entropy:high→human');
  } else if (input.entropy > 1.0) {
    a += 10; signals.push('entropy:medium→agent');
  } else {
    b += 10; signals.push('entropy:low→bot');
  }

  // ── User-Agent ──────────────────────────────────────────────────────────────
  if (MALICIOUS_BOT_UA.some(p => p.test(input.ua))) {
    b += 40; signals.push('ua:known_malicious');
  } else if (KNOWN_AGENT_UA.some(p => p.test(input.ua))) {
    a += 35; signals.push('ua:known_agent');
  } else if (input.ua.includes('Mozilla')) {
    h += 15; signals.push('ua:browser');
  }

  // ── Frankenstein ────────────────────────────────────────────────────────────
  if (input.frankensteinScore === 0) {
    h += 10; signals.push('frankenstein:clean');
  } else if (input.frankensteinScore >= 100) {
    b += 30; signals.push('frankenstein:puppet');
  } else {
    b += Math.floor(input.frankensteinScore / 10);
    signals.push(`frankenstein:${input.frankensteinScore}`);
  }

  // ── PoW verified ────────────────────────────────────────────────────────────
  if (input.hasPoW) {
    h += 10; a += 10; signals.push('pow:verified');
  }

  // ── Classify ────────────────────────────────────────────────────────────────
  const total = h + a + b || 1;

  if (b > h && b > a) {
    return { agentClass: 'MALICIOUS_BOT', confidence: b / total, signals };
  }
  if (a > h) {
    return { agentClass: 'LEGIT_AGENT', confidence: a / total, signals };
  }
  return { agentClass: 'HUMAN', confidence: h / total, signals };
}
