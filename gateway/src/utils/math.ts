// src/utils/math.ts — Pure mathematical primitives for Silicon DNA analysis

/**
 * Shannon entropy of a sample array.
 * Uses adaptive bin count (max(4, n/2)) to stay valid on small arrays.
 */
export function shannonEntropy(data: number[]): number {
  const n = data.length;
  if (n === 0) return 0;

  const bins = Math.max(4, Math.floor(n / 2));
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min;
  if (range === 0) return 0;

  const counts = new Array<number>(bins).fill(0);
  data.forEach(v => {
    const idx = Math.min(bins - 1, Math.floor(((v - min) / range) * bins));
    counts[idx]++;
  });

  return -counts
    .filter(c => c > 0)
    .reduce((sum, c) => {
      const p = c / n;
      return sum + p * Math.log2(p);
    }, 0);
}

/**
 * Autocorrelation at lag-1 (Pearson).
 * Returns 0.5 (neutral) when fewer than 5 samples — avoids false positives.
 */
export function calculateAutocorrelation(data: number[]): number {
  if (data.length < 5) return 0.5;
  const n = data.length;
  const mean = data.reduce((a, b) => a + b, 0) / n;

  let num = 0;
  let den = 0;
  for (let i = 0; i < n - 1; i++) {
    num += (data[i] - mean) * (data[i + 1] - mean);
  }
  for (let i = 0; i < n; i++) {
    den += Math.pow(data[i] - mean, 2);
  }
  return den === 0 ? 0 : num / den;
}

/**
 * Spearman rank correlation between two equal-length arrays.
 * Returns 0 when n < 2.
 */
export function spearmanRankCorrelation(x: number[], y: number[]): number {
  const n = x.length;
  if (n < 2 || n !== y.length) return 0;

  const rankX = calculateRank(x);
  const rankY = calculateRank(y);

  let d2Sum = 0;
  for (let i = 0; i < n; i++) {
    const d = rankX[i] - rankY[i];
    d2Sum += d * d;
  }

  const denominator = n * (n * n - 1);
  if (denominator === 0) return 0;
  return 1 - (6 * d2Sum) / denominator;
}

/**
 * Fractional rank with tie averaging.
 */
export function calculateRank(arr: number[]): number[] {
  const sorted = [...arr].sort((a, b) => a - b);
  return arr.map(v => {
    const first = sorted.indexOf(v);
    const count = sorted.filter(e => e === v).length;
    return first + 1 + (count - 1) / 2;
  });
}
