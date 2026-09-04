// src/services/jitterProbe.ts
// L0 CPU-jitter — the meaningful core.
//
// The probe worker used to time two ADJACENT `process.hrtime.bigint()` calls with
// nothing between them ("Physical micro-pause" — but there was no pause), so every
// delta was just call overhead: near-constant, no physical signal. This module
// gives L0 a real deterministic micro-workload to time, plus pure statistics and a
// verdict that distinguishes:
//   - organic : real hardware/scheduler jitter (natural spread, some autocorr)
//   - flat    : suspiciously deterministic timing (VM/sandbox — CPU pinned, no noise)
//   - chaotic : artificial high-variance noise with no memory (Math.random-style)
//
// microWorkload() is the thing the worker times; jitterStats()/jitterVerdict()/
// jitterSyntheticScore() are pure and unit-tested on fixture delta arrays.

import { shannonEntropy, calculateAutocorrelation } from '../utils/math';

/**
 * Deterministic integer-mixing busy loop (Knuth multiplicative hash + xorshift).
 * Real CPU work whose *timing* varies with scheduler/cache/frequency noise. Returns
 * the accumulator so the caller can sink it and the JIT can't eliminate the loop.
 */
export function microWorkload(rounds = 256): number {
  let acc = 0 >>> 0;
  for (let i = 0; i < rounds; i++) {
    acc = (acc + ((i * 2654435761) >>> 0)) >>> 0;
    acc ^= acc >>> 13;
    acc = (acc * 5) >>> 0;
  }
  return acc >>> 0;
}

export interface JitterStats {
  n: number;
  mean: number;
  variance: number;
  stddev: number;
  cv: number;        // coefficient of variation = stddev/mean (scale-free jitter)
  entropy: number;   // Shannon entropy of the delta distribution (bits)
  autocorr: number;  // lag-1 autocorrelation
  min: number;
  max: number;
  range: number;
}

export function jitterStats(deltas: number[]): JitterStats {
  const n = deltas.length;
  if (n === 0) {
    return { n: 0, mean: 0, variance: 0, stddev: 0, cv: 0, entropy: 0, autocorr: 0, min: 0, max: 0, range: 0 };
  }
  const mean = deltas.reduce((a, b) => a + b, 0) / n;
  const variance = deltas.reduce((a, b) => a + (b - mean) * (b - mean), 0) / n;
  const stddev = Math.sqrt(variance);
  const cv = mean !== 0 ? stddev / Math.abs(mean) : 0;
  const min = Math.min(...deltas);
  const max = Math.max(...deltas);
  return {
    n, mean, variance, stddev, cv,
    entropy: shannonEntropy(deltas),
    autocorr: calculateAutocorrelation(deltas),
    min, max, range: max - min,
  };
}

export type JitterVerdict = 'organic' | 'flat' | 'chaotic' | 'insufficient';

// Thresholds are interpretable, not a trained model. Tuned so a real busy-loop
// timing series reads "organic", a pinned/deterministic VM reads "flat", and
// uniform-random noise reads "chaotic".
const FLAT_CV = 0.03;       // < 3% relative spread == suspiciously deterministic
const FLAT_ENTROPY = 1.2;   // and low distributional entropy
const CHAOTIC_CV = 0.8;     // very high relative spread (heavy-tailed) ...
const CHAOTIC_AUTOCORR = 0.12; // ... with no lag-1 memory == synthetic randomness

export function jitterVerdict(stats: JitterStats): JitterVerdict {
  if (stats.n < 10) return 'insufficient';
  if (stats.cv < FLAT_CV && stats.entropy < FLAT_ENTROPY) return 'flat';
  if (stats.cv > CHAOTIC_CV && Math.abs(stats.autocorr) < CHAOTIC_AUTOCORR) return 'chaotic';
  return 'organic';
}

/** [0,1] synthetic-environment risk from a jitter verdict/stats. Honest neutral
 *  (0.5) when there isn't enough data yet. */
export function jitterSyntheticScore(stats: JitterStats): number {
  const v = jitterVerdict(stats);
  if (v === 'insufficient') return 0.5;
  if (v === 'flat') return 0.85;
  if (v === 'chaotic') return 0.7;
  return 0.15;
}
