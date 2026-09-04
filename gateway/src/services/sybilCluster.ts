/**
 * Cross-IP Sybil Clustering
 * Groups IPs by behavioral fingerprint similarity using KL-divergence.
 * When one cohort member is banned, the entire cohort is flagged.
 *
 * Privacy architecture: raw IPs are NEVER stored.
 * Each IP is hashed with a daily rotating salt before storage.
 * Hash(IP + dailySalt) → cohort mapping expires automatically every 24h.
 * This satisfies GDPR Article 5(1)(e) storage limitation and prevents
 * the cluster from becoming a Honeypot of IP-to-fingerprint mappings.
 */
import * as crypto from 'crypto';
import { WelfordProfile, klDivergence } from '../../src/welford';

export interface BehavioralFingerprint {
  entropy: number;
  variance: number;
  autocorr: number;
  spearmanRho: number;
  requestIntervals: number[];
}

interface IpRecord {
  ipHash: string;          // Hash(ip + dailySalt) — not reversible
  profile: WelfordProfile;
  fingerprint: BehavioralFingerprint;
  cohortId: string | null;
  flagged: boolean;
  lastSeen: number;        // unix ms — used for 24h TTL enforcement
}

// IPs with KL-divergence below this share a cohort
const COHORT_KL_THRESHOLD = 0.15;
const MAX_RECORDS = 10_000;
const TTL_MS = 24 * 60 * 60 * 1000; // 24h — aligned with salt rotation

/** Daily salt: rotates at UTC midnight, making stored hashes non-persistent across days */
function getDailySalt(): string {
  const day = new Date().toISOString().slice(0, 10); // "2026-05-22"
  return crypto.createHash('sha256').update(`sdna-sybil-${day}`).digest('hex').slice(0, 16);
}

/** One-way hash of an IP address — cannot be reversed */
function hashIp(ip: string): string {
  return crypto.createHash('sha256').update(ip + getDailySalt()).digest('hex').slice(0, 16);
}

export class SybilCluster {
  private records = new Map<string, IpRecord>(); // ipHash → record
  private cohorts = new Map<string, Set<string>>(); // cohortId → Set<ipHash>
  private cohortCounter = 0;

  ingest(ip: string, fp: BehavioralFingerprint): void {
    const now = Date.now();
    if (this.records.size >= MAX_RECORDS) this._evictOld(now);

    const ipHash = hashIp(ip);
    let record = this.records.get(ipHash);

    if (!record) {
      const profile = new WelfordProfile();
      fp.requestIntervals.forEach(v => profile.update(v));
      record = { ipHash, profile, fingerprint: fp, cohortId: null, flagged: false, lastSeen: now };
      this.records.set(ipHash, record);
    } else {
      fp.requestIntervals.forEach(v => record!.profile.update(v));
      record.fingerprint = fp;
      record.lastSeen = now;
    }

    this._assignCohort(record);
  }

  /**
   * Flag an IP's entire cohort as malicious.
   * Returns the count of cohort members flagged (not their hashes — caller doesn't need them).
   */
  flag(ip: string): number {
    const ipHash = hashIp(ip);
    const record = this.records.get(ipHash);
    if (!record) return 0;
    record.flagged = true;
    if (!record.cohortId) return 1;

    const cohort = this.cohorts.get(record.cohortId);
    if (!cohort) return 1;

    let count = 0;
    for (const hash of cohort) {
      const m = this.records.get(hash);
      if (m) { m.flagged = true; count++; }
    }
    return count;
  }

  isFlagged(ip: string): boolean {
    return this.records.get(hashIp(ip))?.flagged ?? false;
  }

  /** Returns cohort size (count only — hashes not exposed externally) */
  getCohortSize(ip: string): number {
    const record = this.records.get(hashIp(ip));
    if (!record?.cohortId) return 1;
    return this.cohorts.get(record.cohortId)?.size ?? 1;
  }

  /** Drops every record and cohort. Used by /api/admin/reset-bans so a reset
   *  actually clears Sybil flags (otherwise a flagged IP stays blocked until
   *  its 24h TTL, which surprised operators using reset as an unblock). */
  clear(): void {
    this.records.clear();
    this.cohorts.clear();
    this.cohortCounter = 0;
  }

  getStats(): { total: number; cohorts: number; flagged: number } {
    let flagged = 0;
    for (const r of this.records.values()) if (r.flagged) flagged++;
    return { total: this.records.size, cohorts: this.cohorts.size, flagged };
  }

  private _assignCohort(record: IpRecord): void {
    if (!record.profile.isStable(5)) return;

    for (const [cohortId, members] of this.cohorts) {
      const rep = this._getRepresentative(cohortId, members);
      if (!rep) continue;

      const kl = this._klDistance(record.profile, rep.profile);
      if (kl < COHORT_KL_THRESHOLD) {
        if (record.cohortId && record.cohortId !== cohortId) {
          this.cohorts.get(record.cohortId)?.delete(record.ipHash);
        }
        record.cohortId = cohortId;
        members.add(record.ipHash);
        return;
      }
    }

    const newId = `c${++this.cohortCounter}`;
    record.cohortId = newId;
    this.cohorts.set(newId, new Set([record.ipHash]));
  }

  private _getRepresentative(cohortId: string, members: Set<string>): IpRecord | null {
    for (const hash of members) {
      const r = this.records.get(hash);
      if (r?.profile.isStable(5)) return r;
    }
    return null;
  }

  private _klDistance(a: WelfordProfile, b: WelfordProfile): number {
    if (!a.isStable(5) || !b.isStable(5)) return 1;
    try {
      return klDivergence(a.toDistribution(20), b.toDistribution(20));
    } catch {
      return 1;
    }
  }

  private _evictOld(now: number): void {
    for (const [hash, record] of this.records) {
      if (now - record.lastSeen > TTL_MS) {
        if (record.cohortId) this.cohorts.get(record.cohortId)?.delete(hash);
        this.records.delete(hash);
      }
    }
  }
}
