/**
 * Silicon DNA — SNIPER Filter core logic
 * Pure functions: no I/O, no side effects, fully testable.
 */

export interface RequestHeaders {
  userAgent?: string
  acceptLanguage?: string
  secFetchMode?: string
  secFetchSite?: string
}

export interface ScoreBreakdown {
  varianceScore: number
  entropyScore: number
  autocorrScore: number
  uaScore: number
  acceptLangScore: number
  secFetchModeScore: number
  secFetchSiteScore: number
}

export interface SniperScore {
  total: number
  breakdown: ScoreBreakdown
  variance: number
  entropy: number
  autocorr: number
  blocked: boolean
}

export const BLOCK_THRESHOLD = 60

/** σ² of a sample array */
export function computeVariance(values: number[]): number {
  if (values.length < 2) return 0
  const mean = values.reduce((a, b) => a + b, 0) / values.length
  return values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length
}

/**
 * Shannon entropy of interval deviations.
 * Bin count scales with sample size to avoid coarse bucketing on small arrays.
 */
export function intervalEntropy(intervals: number[], binCount?: number): number {
  if (intervals.length < 2) return 0
  const n = binCount ?? Math.max(4, Math.floor(intervals.length / 2))
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
  const deviations = intervals.map(x => Math.abs(x - mean))
  const maxDev = Math.max(...deviations, 0.001)
  const bins = Array(n).fill(0)
  deviations.forEach(d => bins[Math.min(n - 1, Math.floor((d / maxDev) * n))]++)
  const total = bins.reduce((a, b) => a + b, 0)
  return -bins.reduce((sum, b) => {
    const p = b / total
    return p > 0 ? sum + p * Math.log2(p) : sum
  }, 0)
}

/**
 * Lag-1 autocorrelation of intervals.
 * Near 1.0 = machine rhythm, near 0 = random human, negative = oscillating.
 */
export function computeAutocorrelation(intervals: number[]): number {
  if (intervals.length < 3) return 0
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
  const variance = computeVariance(intervals)
  if (variance === 0) return 1 // perfect repetition → maximal correlation
  let corr = 0
  for (let i = 1; i < intervals.length; i++) {
    corr += (intervals[i] - mean) * (intervals[i - 1] - mean)
  }
  return corr / ((intervals.length - 1) * variance)
}

/**
 * Multi-factor bot score for a sequence of inter-request intervals.
 * sniperThreshold: σ² cutoff for "machine-perfect" (ms², default 2.5)
 */
export function scoreBotRequest(
  intervals: number[],
  headers: RequestHeaders,
  sniperThreshold = 2.5
): SniperScore {
  const variance  = computeVariance(intervals)
  const entropy   = intervalEntropy(intervals)
  const autocorr  = computeAutocorrelation(intervals)
  const ua        = headers.userAgent ?? ''
  const isBotUA   = !ua || !/mozilla/i.test(ua)

  // ── Variance score ────────────────────────────────────────────────────────
  let varianceScore = 0
  if (variance < sniperThreshold)          varianceScore = 40 // machine-perfect
  else if (variance < sniperThreshold * 4) varianceScore = 20 // suspiciously regular

  // ── Entropy score ─────────────────────────────────────────────────────────
  let entropyScore = 0
  if (entropy < 0.5)      entropyScore = 30 // near-uniform distribution
  else if (entropy < 2.0) entropyScore = 12 // low but not zero

  // ── Autocorrelation score ─────────────────────────────────────────────────
  let autocorrScore = 0
  if (autocorr > 0.7)      autocorrScore = 25 // highly periodic
  else if (autocorr > 0.4) autocorrScore = 12 // moderately periodic

  // ── Header scores ─────────────────────────────────────────────────────────
  const uaScore          = isBotUA                    ? 20 : 0
  const acceptLangScore  = headers.acceptLanguage     ?  0 : 10
  const secFetchModeScore = headers.secFetchMode      ?  0 : 15
  const secFetchSiteScore = headers.secFetchSite      ?  0 : 10

  const total = varianceScore + entropyScore + autocorrScore
              + uaScore + acceptLangScore + secFetchModeScore + secFetchSiteScore

  return {
    total,
    breakdown: {
      varianceScore, entropyScore, autocorrScore,
      uaScore, acceptLangScore, secFetchModeScore, secFetchSiteScore,
    },
    variance, entropy, autocorr,
    blocked: total >= BLOCK_THRESHOLD,
  }
}

/** IP blocklist with TTL. Accepts injectable clock for deterministic testing. */
export class IpBlocklist {
  private map = new Map<string, number>()

  constructor(private readonly now: () => number = Date.now) {}

  block(ip: string, durationMs: number): void {
    this.map.set(ip, this.now() + durationMs)
  }

  isBlocked(ip: string): boolean {
    const expiry = this.map.get(ip)
    if (expiry === undefined) return false
    if (this.now() < expiry) return true
    this.map.delete(ip) // TTL expired
    return false
  }

  delete(ip: string): void {
    this.map.delete(ip)
  }

  get size(): number {
    return this.map.size
  }
}

/** Per-IP request timestamp log for SNIPER analysis. */
export class RequestLog {
  private log = new Map<string, number[]>()
  private readonly SESSION_GAP_MS = 5000
  private readonly MAX_SAMPLES    = 20
  private readonly MIN_SAMPLES    = 7
  private readonly SKIP_WARMUP    = 1 // skip first interval (TCP warmup)

  record(ip: string, tsMs: number): number[] | null {
    let timestamps = this.log.get(ip) ?? []

    // Reset if IP was silent > 5s (new session)
    if (timestamps.length > 0 && tsMs - timestamps[timestamps.length - 1] > this.SESSION_GAP_MS) {
      timestamps = []
    }

    timestamps.push(tsMs)
    if (timestamps.length > this.MAX_SAMPLES) timestamps.shift()
    this.log.set(ip, timestamps)

    if (timestamps.length < this.MIN_SAMPLES) return null

    // Build interval array, skip first (TCP warmup anomaly)
    const len = timestamps.length
    const intervals: number[] = []
    for (let i = len - 5; i < len; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1])
    }
    return intervals
  }

  reset(ip: string): void {
    this.log.delete(ip)
  }
}
