/**
 * Drift-adaptive anomaly thresholding (P2.7).
 *
 * WHY THIS EXISTS
 * ───────────────
 * The synthetic-rhythm gate compares a request's timing variance σ² against a
 * cutoff (liveRules.sigma2): below it, timing is "machine-perfect". The old
 * calibrator recomputed that cutoff every 5 minutes as clamp(p10·1.5, 1, 5) over a
 * batch of samples — single-signal, throws away history each cycle, uses magic
 * constants, and never tells anyone when the traffic distribution actually shifts.
 *
 * This module replaces that with two well-established streaming algorithms:
 *   • P2Quantile — the P² algorithm (Jain & Chlamtac, 1985): tracks a chosen
 *     quantile of an unbounded stream in O(1) memory, adapting continuously to
 *     distribution drift. No sample buffer, no periodic reset.
 *   • PageHinkley — a sequential change detector: raises an explicit drift alarm
 *     when the running mean of the signal moves beyond a tolerance. This is the
 *     future-proofing bit: the system reports *when its own calibration
 *     assumptions have moved*, instead of silently sliding.
 *
 * DriftAdaptiveThreshold ties them together: a clamped, continuously-updated
 * threshold plus a warmup/stable/drift status.
 *
 * ANTI-POISONING: callers must feed only samples from requests that already passed
 * the full pipeline (presumed legit). The threshold is additionally clamped to a
 * hard [floor, ceil] so no amount of crafted traffic can push the gate into a
 * degenerate always-open / always-closed state. Residual risk (a patient attacker
 * slowly shifting the legit baseline within the clamp) is bounded by those clamps
 * and surfaced by the Page-Hinkley drift alarm.
 */

/**
 * Single-quantile estimator over a stream (P² algorithm, Jain & Chlamtac 1985).
 * Uses five markers; O(1) memory and O(1) update. Before five samples are seen it
 * returns the exact quantile of what it has.
 */
export class P2Quantile {
  private readonly p: number;
  private readonly q: number[] = [];   // marker heights
  private readonly n: number[] = [];   // actual marker positions (1-indexed)
  private readonly np: number[] = [];  // desired marker positions
  private readonly dn: number[] = [];  // desired-position increments
  private readonly init: number[] = []; // first-5 buffer
  private cnt = 0;

  constructor(p: number) {
    if (!(p > 0 && p < 1)) throw new RangeError('quantile p must be in (0,1)');
    this.p = p;
  }

  get count(): number { return this.cnt; }

  observe(x: number): void {
    if (!Number.isFinite(x)) return;
    this.cnt++;

    if (this.cnt <= 5) {
      this.init.push(x);
      if (this.cnt === 5) {
        this.init.sort((a, b) => a - b);
        for (let i = 0; i < 5; i++) { this.q[i] = this.init[i]; this.n[i] = i + 1; }
        const p = this.p;
        this.np[0] = 1;
        this.np[1] = 1 + 2 * p;
        this.np[2] = 1 + 4 * p;
        this.np[3] = 3 + 2 * p;
        this.np[4] = 5;
        this.dn[0] = 0;
        this.dn[1] = p / 2;
        this.dn[2] = p;
        this.dn[3] = (1 + p) / 2;
        this.dn[4] = 1;
      }
      return;
    }

    // 1. locate cell k
    let k: number;
    if (x < this.q[0]) { this.q[0] = x; k = 0; }
    else if (x >= this.q[4]) { this.q[4] = x; k = 3; }
    else {
      k = 0;
      for (let i = 0; i < 4; i++) { if (this.q[i] <= x && x < this.q[i + 1]) { k = i; break; } }
    }

    // 2. increment actual positions right of the cell, and all desired positions
    for (let i = k + 1; i < 5; i++) this.n[i] += 1;
    for (let i = 0; i < 5; i++) this.np[i] += this.dn[i];

    // 3. adjust interior markers
    for (let i = 1; i <= 3; i++) {
      const d0 = this.np[i] - this.n[i];
      if ((d0 >= 1 && this.n[i + 1] - this.n[i] > 1) ||
          (d0 <= -1 && this.n[i - 1] - this.n[i] < -1)) {
        const d = Math.sign(d0);
        const qp = this.parabolic(i, d);
        if (this.q[i - 1] < qp && qp < this.q[i + 1]) this.q[i] = qp;
        else this.q[i] = this.linear(i, d);
        this.n[i] += d;
      }
    }
  }

  private parabolic(i: number, d: number): number {
    const { q, n } = this;
    return q[i] + (d / (n[i + 1] - n[i - 1])) * (
      (n[i] - n[i - 1] + d) * (q[i + 1] - q[i]) / (n[i + 1] - n[i]) +
      (n[i + 1] - n[i] - d) * (q[i] - q[i - 1]) / (n[i] - n[i - 1])
    );
  }

  private linear(i: number, d: number): number {
    const { q, n } = this;
    return q[i] + d * (q[i + d] - q[i]) / (n[i + d] - n[i]);
  }

  /** Current quantile estimate. */
  get value(): number {
    if (this.cnt === 0) return NaN;
    if (this.cnt < 5) {
      const s = [...this.init].sort((a, b) => a - b);
      const idx = Math.min(s.length - 1, Math.max(0, Math.floor(this.p * s.length)));
      return s[idx];
    }
    return this.q[2];
  }
}

export type DriftStatus = 'warmup' | 'stable' | 'drift';

/**
 * Two-sided Page-Hinkley change detector on the running mean of a stream.
 * Flags when the cumulative deviation of the mean (in either direction) exceeds
 * `lambda`, tolerating drift smaller than `delta` per sample.
 */
export class PageHinkley {
  private readonly delta: number;
  private readonly lambda: number;
  private mean = 0;
  private cnt = 0;
  private mUp = 0; private minUp = 0;   // detects an increase
  private mDn = 0; private maxDn = 0;   // detects a decrease
  private drifting = false;

  constructor(opts: { delta?: number; lambda?: number } = {}) {
    this.delta = opts.delta ?? 0.005;
    this.lambda = opts.lambda ?? 50;
  }

  /** @returns whether a drift is currently signalled and the larger PH statistic. */
  observe(x: number): { drift: boolean; magnitude: number } {
    if (!Number.isFinite(x)) return { drift: this.drifting, magnitude: 0 };
    this.cnt++;
    this.mean += (x - this.mean) / this.cnt;

    // increase detector: cumsum(x - mean - delta) rises above its running min
    this.mUp += x - this.mean - this.delta;
    this.minUp = Math.min(this.minUp, this.mUp);
    const phUp = this.mUp - this.minUp;

    // decrease detector: cumsum(x - mean + delta) falls below its running max
    this.mDn += x - this.mean + this.delta;
    this.maxDn = Math.max(this.maxDn, this.mDn);
    const phDn = this.maxDn - this.mDn;

    const magnitude = Math.max(phUp, phDn);
    this.drifting = magnitude > this.lambda;
    return { drift: this.drifting, magnitude };
  }

  get drift(): boolean { return this.drifting; }

  /** Reset accumulators after acting on a drift (keeps the running mean). */
  reset(): void {
    this.mUp = this.minUp = this.mDn = this.maxDn = 0;
    this.drifting = false;
  }
}

export interface DriftThresholdOptions {
  /** false-positive budget: place the threshold at this quantile of legit signal. */
  quantile: number;
  /** hard clamps — the threshold can never leave [floor, ceil]. */
  floor: number;
  ceil: number;
  /** multiply the quantile estimate (headroom above the legit tail). */
  margin?: number;
  /** samples required before `ready`/adapting. */
  warmup?: number;
  /** Page-Hinkley parameters for the drift alarm. */
  ph?: { delta?: number; lambda?: number };
}

/**
 * Clamped, continuously-updated threshold for a monitored signal, with a
 * warmup → stable ↔ drift status driven by Page-Hinkley.
 */
export class DriftAdaptiveThreshold {
  private readonly quantile: P2Quantile;
  private readonly ph: PageHinkley;
  private readonly opts: Required<Omit<DriftThresholdOptions, 'ph'>>;
  private status_: DriftStatus = 'warmup';
  private driftEvents = 0;

  constructor(opts: DriftThresholdOptions) {
    if (opts.floor > opts.ceil) throw new RangeError('floor must be <= ceil');
    this.opts = {
      quantile: opts.quantile,
      floor: opts.floor,
      ceil: opts.ceil,
      margin: opts.margin ?? 1,
      warmup: opts.warmup ?? 50,
    };
    this.quantile = new P2Quantile(opts.quantile);
    this.ph = new PageHinkley(opts.ph);
  }

  /** Feed one presumed-legit sample of the monitored signal. */
  observe(value: number): void {
    if (!Number.isFinite(value)) return;
    this.quantile.observe(value);
    const { drift } = this.ph.observe(value);
    if (this.quantile.count < this.opts.warmup) { this.status_ = 'warmup'; return; }
    if (drift) {
      if (this.status_ !== 'drift') this.driftEvents++;
      this.status_ = 'drift';
      // acknowledge so the alarm re-arms for the *next* shift rather than latching
      this.ph.reset();
    } else {
      this.status_ = 'stable';
    }
  }

  /** Clamped adaptive threshold. Falls back to the floor until warmed up. */
  get threshold(): number {
    if (this.quantile.count < this.opts.warmup) return this.opts.floor;
    const raw = this.quantile.value * this.opts.margin;
    return Math.min(this.opts.ceil, Math.max(this.opts.floor, raw));
  }

  get ready(): boolean { return this.quantile.count >= this.opts.warmup; }
  get status(): DriftStatus { return this.status_; }
  get count(): number { return this.quantile.count; }
  get drifts(): number { return this.driftEvents; }

  snapshot() {
    return {
      threshold: Number(this.threshold.toFixed(3)),
      status: this.status_,
      samples: this.quantile.count,
      drifts: this.driftEvents,
    };
  }
}
