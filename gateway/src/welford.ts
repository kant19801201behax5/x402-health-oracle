/**
 * Silicon DNA — Welford online algorithm for stable hardware DNA profile.
 * Accumulates running mean/variance without storing raw samples.
 * After ~1000 samples the profile converges to a stable hardware fingerprint.
 */

export class WelfordProfile {
  count  = 0
  mean   = 0
  private M2 = 0

  update(value: number): void {
    this.count++
    const delta  = value - this.mean
    this.mean   += delta / this.count
    const delta2 = value - this.mean
    this.M2     += delta * delta2
  }

  /** Sample variance (Bessel-corrected) */
  get variance(): number {
    return this.count > 1 ? this.M2 / (this.count - 1) : 0
  }

  get stddev(): number {
    return Math.sqrt(this.variance)
  }

  /** Profile is reliable only after enough samples */
  isStable(minSamples = 100): boolean {
    return this.count >= minSamples
  }

  /**
   * Approximate Gaussian probability distribution over ±sigmas.
   * Returns normalized histogram (bins sum ≈ 1).
   */
  toDistribution(bins = 20, sigmas = 3): number[] {
    const dist = Array<number>(bins).fill(0)
    if (this.count < 10) return dist
    const std = this.stddev || 1
    const lo  = this.mean - sigmas * std
    const hi  = this.mean + sigmas * std
    const width = (hi - lo) / bins
    for (let i = 0; i < bins; i++) {
      const x = lo + (i + 0.5) * width
      const z = (x - this.mean) / std
      dist[i] = Math.exp(-0.5 * z * z) / (std * Math.sqrt(2 * Math.PI)) * width
    }
    return normalizeDistribution(dist)
  }

  /** Serialisable snapshot for persistence */
  toJSON(): { count: number; mean: number; variance: number } {
    return { count: this.count, mean: this.mean, variance: this.variance }
  }

  /** Restore from persisted snapshot */
  static fromJSON(data: { count: number; mean: number; variance: number }): WelfordProfile {
    const p = new WelfordProfile()
    p.count = data.count
    p.mean  = data.mean
    p.M2    = data.variance * (data.count - 1)
    return p
  }
}

/** KL-divergence D(p||q). Both arrays must be same length and positive. */
export function klDivergence(p: number[], q: number[]): number {
  if (p.length !== q.length) throw new Error('Arrays must be same length')
  const eps = 1e-10
  let kl = 0
  for (let i = 0; i < p.length; i++) {
    const pi = p[i] + eps
    const qi = q[i] + eps
    kl += pi * Math.log(pi / qi)
  }
  return kl
}

/** Normalise so values sum to 1 */
export function normalizeDistribution(dist: number[]): number[] {
  const sum = dist.reduce((a, b) => a + b, 0)
  return sum > 0 ? dist.map(x => x / sum) : dist.slice()
}

/**
 * Compare new jitter batch to a stable reference profile.
 * Returns KL-divergence — low = same hardware, high = different hardware.
 */
export function compareToProfile(
  profile: WelfordProfile,
  newSamples: number[],
  bins = 20
): number {
  if (!profile.isStable(50)) return 0 // not enough data yet

  const refDist = profile.toDistribution(bins)

  // Build empirical distribution of new samples
  const std = profile.stddev || 1
  const lo  = profile.mean - 3 * std
  const hi  = profile.mean + 3 * std
  const width = (hi - lo) / bins
  const empirical = Array<number>(bins).fill(0)

  for (const v of newSamples) {
    const idx = Math.max(0, Math.min(bins - 1, Math.floor((v - lo) / width)))
    empirical[idx]++
  }

  const normEmp = normalizeDistribution(empirical)
  return klDivergence(normEmp, refDist)
}
