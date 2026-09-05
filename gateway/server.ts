
import express from 'express';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { createMlKem768 } from 'mlkem';

import { Worker } from 'node:worker_threads';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'path';
import { performance } from 'perf_hooks';
import { LRUCache } from 'lru-cache';
import { updateNoise } from './src/services/noiseBridge';
import * as rhythmManager from './src/services/rhythmManager';
import * as sealValidator from './src/services/sealValidator';
import { shannonEntropy, calculateAutocorrelation, spearmanRankCorrelation } from './src/utils/math';
import { argon2id } from 'hash-wasm';
import { persistBan, persistProfile, loadActiveBans, loadProfile, logEvent, clearBans } from './src/db/persist';
import { SybilCluster } from './src/services/sybilCluster';
import { scoreBotRequest, type RequestHeaders } from './src/sniper';
import { resolveTlsFp, tlsRisk } from './src/services/tlsFingerprint';
import { jitterStats, jitterVerdict, type JitterVerdict } from './src/services/jitterProbe';
import { verifyEip191, verifyAgentCredential, verifyMlDsaCredential, agentTrustDecision } from './src/services/agentIdentity';
import { classifyAgent } from './src/services/agentClassifier';
import { PrivacyPassIssuer } from './src/services/privacyPass';
import { DriftAdaptiveThreshold } from './src/services/driftModel';
import { detectAutomation } from './src/services/automationDetector';
import { shadowFilterMiddleware, getShadowStats, clearShadowRecords } from './src/middleware/shadowFilter';
import { computeBehavioralHash, validateSignatureStructure, bindWallet, lookupWallet, getWalletsByHash, getBindingStats, clearBindings } from './src/services/walletBinder';
import { issueProof, redeemProof, clearProofs, type LayerResult } from './src/services/zkProof';
import { evaluateTrust } from './src/services/trustEngine';
import {
  pqcSessionSignal, automationSignal, frankensteinSignal,
  rhythmTrustSignal, classifierSignal, walletSybilSignal,
} from './src/services/trustSignals';

function isXdpAttached(): boolean {
  try {
    return execSync('ip link show eth0', { encoding: 'utf8' }).includes('xdp');
  } catch { return false; }
}

function isLsmLoaded(): boolean {
  try {
    return execSync('cat /sys/kernel/security/lsm', { encoding: 'utf8' }).includes('bpf');
  } catch { return false; }
}

async function startServer() {
  const app = express();
  const server = createServer(app);
  const wss = new WebSocketServer({ server });

  const PORT = Number(process.env.PORT) || 3000;

  // ── TRUSTED PROXY / CLIENT IP RESOLUTION ────────────────────────────────────
  // x-forwarded-for is attacker-controlled unless it arrives from a proxy we
  // operate — trusting it blindly lets a bot evade its ban by rotating a fake
  // header and lets an attacker frame an innocent IP. Only trust XFF when the
  // real TCP peer is a known proxy (TRUSTED_PROXY_IPS). Behind nginx on the same
  // host set TRUSTED_PROXY_IPS=127.0.0.1,::1 (see .env.example); unset ⇒ every
  // route falls back to the real socket address.
  const TRUSTED_PROXY_IPS = new Set(
    (process.env.TRUSTED_PROXY_IPS || '').split(',').map(s => s.trim()).filter(Boolean)
  );
  function getClientIp(req: { headers: Record<string, unknown>; socket: { remoteAddress?: string } }): string {
    const remote = req.socket.remoteAddress || 'unknown';
    if (TRUSTED_PROXY_IPS.has(remote)) {
      const xff = req.headers['x-forwarded-for'];
      const raw = typeof xff === 'string' ? xff : Array.isArray(xff) ? xff[0] : '';
      const first = raw?.split(',')[0]?.trim();
      if (first) return first;
    }
    return remote;
  }

  let mode: 'IDLE' | 'STRESS' | 'SNIPER' = 'IDLE';
  const startTime = Date.now();
  let globalPassedCount = 0;
  let globalDroppedCount = 0;
  let sniperArmed = false;

  // Phase 58.0: Live rules pulled from agent every 60s (sigma2, rho, argon2 thresholds)
  let liveRules = { sigma2: 2.0, rho: 0.3, argon2: { time: 3, memory: 65536, parallelism: 4 } };
  const AGENT_URL = process.env.AGENT_URL || '';
  if (AGENT_URL) {
    const syncRules = () => {
      fetch(`${AGENT_URL}/api/admin/rules`, {
        headers: process.env.AGENT_TOKEN ? { Authorization: 'Bearer ' + process.env.AGENT_TOKEN } : {},
      })
        .then(r => r.json())
        .then((data: any) => {
          if (data?.rules) {
            // σ² is owned locally by the drift-adaptive model (P2.7); agent still
            // provides rho + argon2. Ignoring a agent-sent sigma2 avoids the two
            // calibrators fighting over the same value.
            const { sigma2: _driftOwned, ...rest } = data.rules;
            liveRules = { ...liveRules, ...rest };
            console.log(`[🧬 DNA-RULES] Synced: σ²=${liveRules.sigma2}(drift-owned) ρ=${liveRules.rho}`);
          }
        })
        .catch((e: Error) => console.warn(`[DNA-RULES] sync failed: ${e.message}`));
    };
    syncRules();
    setInterval(syncRules, 60_000);
  }
  // ── Drift-adaptive σ² cutoff (P2.7) ────────────────────────────────────────
  // Replaces the old 5-minute batch calibrator (clamp(p10·1.5, 1, 5) over a
  // sample buffer). The P²-quantile tracks the 10th percentile of *passed* timing
  // variance online (O(1) memory, no periodic reset), and the Page-Hinkley test
  // raises an explicit drift alarm when that distribution shifts. Threshold is
  // hard-clamped to [1,5] so no crafted traffic can drive the gate degenerate.
  const sigmaDrift = new DriftAdaptiveThreshold({
    quantile: 0.10, floor: 1.0, ceil: 5.0, margin: 1.5, warmup: 50,
    ph: { delta: 0.05, lambda: 50 },
  });

  // ── Sybil Cluster (cross-IP cohort detection) ──────────────────────────────
  const sybilCluster = new SybilCluster();

  // ── Privacy Pass issuer (P1.6): OPRF(P-384) anonymous one-time tokens ───────
  // A client solves ONE Argon2 PoW, exchanges it for a batch of blinded tokens,
  // then redeems one per protected request instead of re-solving — cheaper and
  // unlinkable. Key from env so it survives restarts; else ephemeral per boot.
  const privacyPass = new PrivacyPassIssuer({ keyHex: process.env.PRIVACY_PASS_KEY });

  // ── PQC cooldown flag: jitter readings taken during ML-KEM CPU spike are discarded ──
  // ML-KEM-768 generateKeyPair() and decap() are CPU-intensive lattice operations.
  // On a shared-core VPS they contaminate probe-worker hrtime measurements via
  // CPU time-slicing. We mark a window after each KEM operation as "dirty" and
  // skip those jitter batches to preserve L7 measurement integrity.
  let pqcCooldownUntil = 0; // unix ms — skip jitter batches while Date.now() < this

  // ── Health Decay (STRATEGY_2026.md) ─────────────────────────────────────────
  // Tracks freshness of jitter measurements to expose operational status.
  // operational = fresh (<60s) | degraded = stale (60-300s) | unavailable = dead (>300s)
  // Protocols MUST know when the radar goes blind → safe:null if degraded/unavailable.
  let lastJitterTs = 0;

  function getHealthStatus(): { health: 'operational' | 'degraded' | 'unavailable' } {
    if (lastJitterTs === 0) return { health: 'unavailable' };
    const age = Date.now() - lastJitterTs;
    if (age < 60_000)  return { health: 'operational' };
    if (age < 300_000) return { health: 'degraded' };
    return { health: 'unavailable' };
  }

  let lastClientIp = 'unknown'; // tracks last WS client for per-IP trustScore in metrics
  let lastSpearmanRho = 0.5;   // last computed ρ from microStall (fed into quantum DNA hash)
  // L2 TLS fingerprint — populated only when a JA4-capable front sends x-tls-ja4
  // from a trusted proxy; null (honest "unknown") otherwise. Replaces the old
  // hardcoded ja3:0.5 that was never real.
  let lastJa4: string | null = null;
  let lastTlsRisk: number | null = null;
  // L0 CPU-jitter verdict from the (now real) micro-workload timings.
  let lastJitterVerdict: JitterVerdict = 'insufficient';
  let lastJitterCv = 0;

  type CurrentMetrics = {
    mean: number; variance: number; entropy: number; autocorr: number;
    temp: number; pol: number; histogram: number[]; dnaHash: string;
    trustScore: number; keyRatchetCycles: number;
    mode: 'IDLE' | 'STRESS' | 'SNIPER';
  };

  let currentMetrics: CurrentMetrics = {
    mean: 0, variance: 0, entropy: 0, autocorr: 0,
    temp: 35.0, pol: 0, histogram: Array(60).fill(0),
    dnaHash: 'INITIALIZING...', trustScore: 1.0, keyRatchetCycles: 0, mode: 'IDLE'
  };

  // COOP/COEP — required for SharedArrayBuffer + Atomics.wait in browser workers
  app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    next();
  });

  const requestLog = new Map<string, number[]>();

  // ── UNIFIED BAN SYSTEM ─────────────────────────────────────────────────────
  // Single LRU with TTL — replaces the old Set<string> + manual setTimeout pattern.
  // All ban paths (Frankenstein, Spearman, Variance, PoW abuse) write here.
  const bannedIPs = new LRUCache<string, { reason: string; ts: number }>({
    max: 100000,
    ttl: 1000 * 60 * 60, // 1h isolation
  });

  // Warm LRU from persisted bans — bans survive server restarts
  for (const { ip, reason, ts } of loadActiveBans()) {
    bannedIPs.set(ip, { reason, ts });
  }

  // LRU with 5-min TTL prevents accumulation on abandoned challenges
  const pendingChallenges = new LRUCache<string, {
    target: string; startTime: number; m_cost: number; t_cost: number;
  }>({ max: 10000, ttl: 1000 * 60 * 5 });

  const verifiedPoW = new LRUCache<string, {
    nonce: string; calcTime: number; m_cost: number; verifiedAt: number;
  }>({ max: 10000, ttl: 1000 * 60 * 5 });

  // P1.5: per-client PQC sessions — keyed by client IP, not a single shared
  // 'default'. Each WebSocket connection gets its own ML-KEM shared secret, so
  // one client can't ride another's tunnel and the seal/ratchet/sequence are
  // isolated per client.
  const sessionKeys = new LRUCache<string, { key: Buffer; counter: number }>({
    max: 5000, ttl: 1000 * 60 * 60
  });

  // P1.5: per-connection PQC session id. A per-IP key can't isolate clients
  // behind Cloudflare (shared/ambiguous source IP), so each WS handshake mints a
  // random session token, returns it to the client, and the client echoes it in
  // `x-silicon-dna-session`. Falls back to 'default' when absent, so the existing
  // dashboard (which doesn't send a token yet) keeps working unchanged.
  function sessionIdOf(req: { headers: Record<string, unknown> }): string {
    const h = req.headers['x-silicon-dna-session'];
    const s = typeof h === 'string' ? h : Array.isArray(h) ? h[0] : '';
    return s && /^[a-f0-9]{16,64}$/i.test(s) ? s : 'default';
  }

  // Server-side DNA key: the quantum DNA hash is the SERVER's own entropy
  // commitment (published to all clients over WS), so it uses a stable
  // server-generated key rather than borrowing a client's session key. This also
  // means jitter/DNA metrics flow immediately, not only after some client's PQC
  // handshake (the old `sessionKeys.get('default')` gate froze metrics headless).
  const serverDnaKey = crypto.randomBytes(32);

  const packetSequences = new LRUCache<string, number>({
    max: 5000, ttl: 1000 * 60 * 10
  });

  const globalPowGovernor = { count: 0, lastReset: Date.now() };
  const POW_LIMIT_PER_SEC = 50;

  const argonProfiles = new LRUCache<string, {
    m_cost: number; t_cost: number; successes: number;
  }>({ max: 10000, ttl: 1000 * 60 * 60 * 24 });

  // argonProfiles: also warm from persisted profiles on startup (handled per-request via loadProfile fallback)

  interface StallRecord { serverDelays: number[]; clientGaps: number[]; lastReq?: number; }
  const stallHistory = new LRUCache<string, StallRecord>({
    max: 50000, ttl: 1000 * 60 * 5
  });

  // ── FREE-TIER RATE LIMITER ─────────────────────────────────────────────────
  // Free endpoints: 30 req/min per IP. Paid x402 endpoints are unlimited.
  // Over-limit response includes x402 upgrade path.
  const freeRateCounter = new LRUCache<string, number>({
    max: 50000, ttl: 1000 * 60, // 1-minute window
  });
  const FREE_RATE_LIMIT = 30;

  function checkFreeRateLimit(ip: string): { allowed: boolean; remaining: number } {
    const count = (freeRateCounter.get(ip) ?? 0) + 1;
    freeRateCounter.set(ip, count);
    return { allowed: count <= FREE_RATE_LIMIT, remaining: Math.max(0, FREE_RATE_LIMIT - count) };
  }

  // ── THREAT BROADCAST ───────────────────────────────────────────────────────
  function broadcastThreat(ip: string, threatType: string, details: Record<string, unknown>) {
    // Truncate IP for privacy in logs
    const safeIp = ip.slice(-8);
    const event = JSON.stringify({ type: 'SILICON_THREAT', ip: safeIp, threatType, details, t: Date.now() });
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) client.send(event);
    });
  }

  // ── QUANTUM DNA HASH ───────────────────────────────────────────────────────
  function computeQuantumDNAHash(
    sessionKey: Buffer,
    jitterMean: number, jitterVar: number, spearmanRho: number,
    powTotalTime: number, powMemCost: number, powHash: string
  ): string {
    const buf = Buffer.allocUnsafe(8 + 8 + 8 + 8 + 4 + 32);
    let offset = 0;
    buf.writeDoubleBE(jitterMean, offset);   offset += 8;
    buf.writeDoubleBE(jitterVar, offset);    offset += 8;
    buf.writeDoubleBE(spearmanRho, offset);  offset += 8;
    buf.writeDoubleBE(powTotalTime, offset); offset += 8;
    buf.writeUInt32BE(powMemCost, offset);   offset += 4;
    // Pad powHash to 64 hex chars if shorter
    Buffer.from(powHash.slice(0, 64).padEnd(64, '0'), 'hex').copy(buf, offset);
    return crypto.createHmac('sha256', sessionKey).update(buf).digest('hex');
  }

  // ── MICRO-STALL MIDDLEWARE (L3: Spearman Grey Zone) ────────────────────────
  const microStallMiddleware = async (
    req: express.Request, res: express.Response, next: express.NextFunction
  ) => {
    const ip = getClientIp(req);

    if (bannedIPs.has(ip)) {
      globalDroppedCount++;
      req.socket.destroy();
      return;
    }

    const record = stallHistory.get(ip) || { serverDelays: [], clientGaps: [], lastReq: undefined };
    const now = Date.now();

    // Collect client reaction gap to previous stall
    if (record.lastReq !== undefined) {
      const gap = now - record.lastReq;
      if (gap > 0 && gap < 30000 && record.serverDelays.length > record.clientGaps.length) {
        record.clientGaps.push(gap);
      }
    }
    record.lastReq = now;

    // Evaluate once we have 7+ pairs
    if (record.clientGaps.length >= 7) {
      const rho = spearmanRankCorrelation(
        record.serverDelays.slice(-7),
        record.clientGaps.slice(-7)
      );
      if (!isNaN(rho)) lastSpearmanRho = rho;

      if (isNaN(rho) || rho < liveRules.rho) {
        const rhoStr = isNaN(rho) ? 'NaN' : rho.toFixed(3);
        console.warn(`[SNIPER: KILL] Static script ρ=${rhoStr}. IP: ${ip}`);
        globalDroppedCount++;
        bannedIPs.set(ip, { reason: `Spearman ρ=${rhoStr}`, ts: Date.now() });
        persistBan(ip, `Spearman ρ=${rhoStr}`, 1000 * 60 * 60);
        logEvent(ip, 'STATIC_SCRIPT', { rho: isNaN(rho) ? null : rho });
        broadcastThreat(ip, 'STATIC_SCRIPT', { rho: isNaN(rho) ? null : rho, threshold: 0.3 });
        stallHistory.delete(ip);
        req.socket.destroy();
        return;
      }

      if (rho < 0.6) {
        (res.locals as any).greyZone = true;
        (res.locals as any).c_tox = 0.85;
        console.log(`[SNIPER: GREY] Grey zone ρ=${rho.toFixed(3)}. IP: ${ip}`);
        broadcastThreat(ip, 'GREY_ZONE', { rho, range: '0.3–0.6' });
      }

      // Reset pairs after evaluation
      record.serverDelays = [];
      record.clientGaps = [];
    }
    stallHistory.set(ip, record);

    // Inject stall only in SNIPER mode and when toxicity warrants it
    const toxicity = (res.locals as any).c_tox ?? 0.5;
    const isGrayZone = sniperArmed && (toxicity >= 0.2 || (res.locals as any).greyZone);
    const stallMs = isGrayZone ? Math.floor(5 + Math.random() * 25) : 0;

    if (stallMs > 0) await new Promise(resolve => setTimeout(resolve, stallMs));

    const stallStart = Date.now();
    res.once('finish', () => {
      if (stallMs > 0) {
        const updated = stallHistory.get(ip);
        if (updated) {
          updated.serverDelays.push(Date.now() - stallStart);
          stallHistory.set(ip, updated);
        }
      }
    });

    next();
  };

  // ── DIGITAL FRANKENSTEIN DETECTOR ─────────────────────────────────────────
  const checkConsistency = (req: express.Request): number => {
    const ua = req.headers['user-agent'] || '';
    const platform = (req.headers['sec-ch-ua-platform'] as string) || '';
    const fetchMode = req.headers['sec-fetch-mode'];

    let score = 0;
    if (ua.includes('Mozilla') && !fetchMode) score += 40;
    if (ua.includes('Windows') && platform === '"Linux"') score += 50;
    if (ua.includes('Macintosh') && platform === '"Windows"') score += 50;
    if (ua.includes('Chrome') && !req.headers['sec-ch-ua']) score += 30;
    if (req.headers['x-puppeteer-version'] || req.headers['x-selenium-id']) score += 100;
    return score;
  };

  // ── SNIPER FILTER ──────────────────────────────────────────────────────────
  const sniperFilter = (
    req: express.Request, res: express.Response, next: express.NextFunction
  ) => {
    const ip = getClientIp(req);

    // L2 TLS: consume a real JA4 from a trusted front (x-tls-ja4), never fabricate.
    const fp = resolveTlsFp(req.headers as Record<string, unknown>,
                            TRUSTED_PROXY_IPS.has(req.socket.remoteAddress || ''));
    if (fp.ja4) { lastJa4 = fp.ja4; lastTlsRisk = tlsRisk(fp, (req.headers['user-agent'] as string) || ''); }

    if (bannedIPs.has(ip) || sybilCluster.isFlagged(ip)) {
      globalDroppedCount++;
      req.socket.destroy();
      return;
    }

    const toxScore = checkConsistency(req);
    (res.locals as any).c_tox = toxScore / 100;

    if (toxScore >= 100) {
      const reason = `Frankenstein score=${toxScore}`;
      bannedIPs.set(ip, { reason, ts: Date.now() });
      persistBan(ip, reason, 1000 * 60 * 60);
      logEvent(ip, 'FRANKENSTEIN', { toxScore });
      globalDroppedCount++;
      broadcastThreat(ip, 'FRANKENSTEIN', {
        toxScore,
        ua: (req.headers['user-agent'] || '').slice(0, 80)
      });
      console.warn(`[SNIPER: DROP] ${reason}. IP: ${ip}`);
      req.socket.destroy();
      return;
    }

    if (!sniperArmed) return next();

    const now = performance.now();
    const timestamps = requestLog.get(ip) || [];
    timestamps.push(now);
    if (timestamps.length > 20) timestamps.shift();
    requestLog.set(ip, timestamps);

    if (timestamps.length >= 10) {
      const intervals: number[] = [];
      for (let i = 1; i < timestamps.length; i++) {
        intervals.push(timestamps[i] - timestamps[i - 1]);
      }

      // Tested multi-factor SNIPER core (src/sniper.ts, 45 unit tests) — replaces
      // the old inline variance-only heuristic. σ² + entropy + autocorr + header
      // score; score ≥ 60 ⇒ synthetic. Same module the sniper.test.ts cases cover.
      const headers: RequestHeaders = {
        userAgent: req.headers['user-agent'] as string | undefined,
        acceptLanguage: req.headers['accept-language'] as string | undefined,
        secFetchMode: req.headers['sec-fetch-mode'] as string | undefined,
        secFetchSite: req.headers['sec-fetch-site'] as string | undefined,
      };
      const score = scoreBotRequest(intervals, headers, liveRules.sigma2);

      // L2.5 Sybil: feed every fingerprint (clean traffic too) so a shared
      // botnet signature can be told apart from an ordinary residential IP pool.
      // Previously SybilCluster was instantiated but only reachable via manual
      // admin endpoints — now it is live on the detection path.
      sybilCluster.ingest(ip, {
        entropy: score.entropy, variance: score.variance, autocorr: score.autocorr,
        spearmanRho: lastSpearmanRho, requestIntervals: intervals,
      });

      if (score.blocked) {
        const reason = `Synthetic rhythm score=${score.total} σ²=${score.variance.toFixed(3)} R1=${score.autocorr.toFixed(3)}`;
        bannedIPs.set(ip, { reason, ts: Date.now() });
        persistBan(ip, reason, 1000 * 60 * 60);
        const cohortSize = sybilCluster.flag(ip);
        logEvent(ip, 'SYNTHETIC_RHYTHM', { score: score.total, breakdown: score.breakdown, cohortSize });
        globalDroppedCount++;
        broadcastThreat(ip, 'SYNTHETIC_RHYTHM', { score: score.total, variance: score.variance, autocorr: score.autocorr, cohortSize });
        console.warn(`[SNIPER: DROP] ${reason} cohort=${cohortSize}. IP: ${ip}`);
        req.socket.destroy();
        return;
      }

      // P2.7: only passed (presumed-legit) variance feeds the drift model — blocked
      // traffic returns above and never reaches here, which is the anti-poisoning
      // guard. Adapt the σ² cutoff online and log when the distribution drifts.
      sigmaDrift.observe(score.variance);
      if (sigmaDrift.ready) {
        const adapted = Number(sigmaDrift.threshold.toFixed(2));
        if (Math.abs(adapted - liveRules.sigma2) > 0.1) {
          liveRules.sigma2 = adapted;
          console.log(`[🧬 DRIFT-CAL] σ² → ${adapted} (q10·1.5, n=${sigmaDrift.count}${sigmaDrift.status === 'drift' ? ', DRIFT' : ''})`);
        }
      }
    }

    globalPassedCount++;
    next();
  };

  // ── SHADOW FILTER (L7: agentClassifier, ~0ms overhead) ──────────────────────
  // Was defined but never mounted (SYSTEM_MAP §7.2 flagged it dead — /api/shadow-stats
  // always zeros). Now live: classifies HUMAN/LEGIT_AGENT/MALICIOUS_BOT in the
  // background after the response is sent, and throttles an IP's *next* request
  // once it racks up repeated malicious verdicts. Additive early-warning layer —
  // never replaces the hard bans in sniperFilter/microStallMiddleware. Resolves
  // IP via getClientIp (trusted-proxy aware) and exempts control/observability
  // paths so a flagged monitor/admin IP can't lock out /metrics or reset.
  app.use(shadowFilterMiddleware((req) => ({
    spearmanRho: lastSpearmanRho,
    variance: currentMetrics.variance,
    entropy: currentMetrics.entropy,
    frankensteinScore: checkConsistency(req),
    hasPoW: verifiedPoW.has(getClientIp(req)),
  }), getClientIp));

  // ── /api/challenge ─────────────────────────────────────────────────────────
  app.get('/api/challenge', (req, res) => {
    const ip = getClientIp(req);
    const now = Date.now();

    if (now - globalPowGovernor.lastReset > 1000) {
      globalPowGovernor.count = 0;
      globalPowGovernor.lastReset = now;
    }
    if (globalPowGovernor.count >= POW_LIMIT_PER_SEC) {
      return res.status(429).json({ error: 'GLOBAL_STRESS_THRESHOLD', retryAfter: 1 });
    }
    globalPowGovernor.count++;

    const target = crypto.randomBytes(32).toString('hex');
    const profile = argonProfiles.get(ip) || { m_cost: liveRules.argon2.memory, t_cost: liveRules.argon2.time, successes: 0 };
    pendingChallenges.set(ip, { target, startTime: now, m_cost: profile.m_cost, t_cost: profile.t_cost });
    res.json({ target, m_cost: profile.m_cost, t_cost: profile.t_cost, p: 1 });
  });

  // ── /api/verify-pow ────────────────────────────────────────────────────────
  app.post('/api/verify-pow', express.json(), async (req, res) => {
    const ip = getClientIp(req);
    const { hash, calcTime, m_cost, fp } = req.body;
    const challenge = pendingChallenges.get(ip);

    if (!challenge) return res.status(403).json({ error: 'NO_CHALLENGE' });

    // GPU vs UA consistency (L1.1)
    if (fp?.gpu && typeof fp.gpu === 'string') {
      const ua = req.headers['user-agent'] || '';
      const gpuStr = fp.gpu as string;
      const isMacUA = ua.includes('Macintosh');
      const hasAppleGpu = gpuStr.includes('Apple') || gpuStr.includes('Metal');
      const gpuKnown = !gpuStr.includes('unknown') && !gpuStr.includes('error');
      if (isMacUA && !hasAppleGpu && gpuKnown) {
        const reason = `GPU/UA mismatch: ${gpuStr.slice(0, 50)}`;
        bannedIPs.set(ip, { reason, ts: Date.now() });
        persistBan(ip, reason, 1000 * 60 * 60);
        logEvent(ip, 'FINGERPRINT_MISMATCH', { gpu: gpuStr.slice(0, 40) });
        broadcastThreat(ip, 'FINGERPRINT_MISMATCH', { gpu: gpuStr.slice(0, 60), ua: ua.slice(0, 60) });
        console.warn(`[SNIPER: KILL] ${reason}. IP: ${ip}`);
        req.socket.destroy();
        return;
      }
    }

    // Automation / WebDriver artifact detection (L1.2)
    const automation = detectAutomation({
      webdriver: fp?.webdriver,
      hasChromedriverCdc: fp?.hasChromedriverCdc,
      hasPhantomArtifact: fp?.hasPhantomArtifact,
      hasNightmareArtifact: fp?.hasNightmareArtifact,
      pluginsLength: fp?.pluginsLength,
      languagesEmpty: fp?.languagesEmpty,
    });
    if (automation.detected) {
      const reason = "Automation detected: " + automation.reasons.join(', ');
      bannedIPs.set(ip, { reason, ts: Date.now() });
      persistBan(ip, reason, 1000 * 60 * 60);
      logEvent(ip, 'AUTOMATION_DETECTED', { reasons: automation.reasons });
      broadcastThreat(ip, 'AUTOMATION_DETECTED', { reasons: automation.reasons });
      console.warn('[SNIPER: KILL] ' + reason + '. IP: ' + ip);
      req.socket.destroy();
      return;
    }

    // Minimum theoretical Argon2 time (ASIC/GPU spoof guard)
    const t_min = (m_cost / 1024) * 0.8;
    if (typeof calcTime === 'number' && calcTime < t_min) {
      const reason = `ASIC spoof T_calc=${calcTime.toFixed(1)} < T_min=${t_min.toFixed(1)}`;
      bannedIPs.set(ip, { reason, ts: Date.now() });
      persistBan(ip, reason, 1000 * 60 * 60);
      logEvent(ip, 'ASIC_SPOOF', { calcTime, t_min });
      broadcastThreat(ip, 'ASIC_SPOOF', { calcTime, t_min });
      console.warn(`[SNIPER: KILL] ${reason}. IP: ${ip}`);
      req.socket.destroy();
      return;
    }

    // Slow-time attack: client claims more time than server wall clock allows
    const T_total = Date.now() - challenge.startTime;
    const RTT_GRACE = 70;
    if (typeof calcTime === 'number' && calcTime > T_total + RTT_GRACE) {
      const reason = `Slow-time attack T_claimed=${calcTime} > T_wall=${T_total}`;
      bannedIPs.set(ip, { reason, ts: Date.now() });
      persistBan(ip, reason, 1000 * 60 * 60);
      logEvent(ip, 'SLOW_TIME_ATTACK', { calcTime, T_total });
      broadcastThreat(ip, 'SLOW_TIME_ATTACK', { calcTime, T_total });
      console.warn(`[SNIPER: KILL] ${reason}. IP: ${ip}`);
      req.socket.destroy();
      return;
    }

    // Structural validation: argon2-browser returns 64-char hex for hashLen=32
    const isValid = typeof hash === 'string' && /^[0-9a-f]{64}$/i.test(hash);
    if (!isValid) {
      return res.status(401).json({ error: 'INVALID_POW_STRUCTURE' });
    }

    // Delete challenge before verification — prevents replay even if verification is slow
    const verifiedChallenge = challenge;
    pendingChallenges.delete(ip);

    // ── REAL SERVER-SIDE ARGON2ID VERIFICATION ──────────────────────────────
    // Recomputes argon2id(target, salt='quantum_salt_3.2') and compares with
    // the submitted hash. A forged hash that doesn't match kills the session.
    try {
      const serverHash = await argon2id({
        password: verifiedChallenge.target,
        salt: 'quantum_salt_3.2',
        iterations: verifiedChallenge.t_cost,
        memorySize: m_cost,
        hashLength: 32,
        parallelism: 1,
        outputType: 'hex',
      });

      if (serverHash !== hash.toLowerCase()) {
        const reason = 'PoW hash forgery — submitted hash != argon2id(target)';
        bannedIPs.set(ip, { reason, ts: Date.now() });
        persistBan(ip, reason, 1000 * 60 * 60);
        logEvent(ip, 'POW_FORGERY', { submitted: hash.slice(0, 16) });
        broadcastThreat(ip, 'POW_FORGERY', {
          submitted: hash.slice(0, 16) + '...',
          expected: serverHash.slice(0, 16) + '...',
        });
        console.warn(`[SNIPER: KILL] PoW forgery detected. IP: ${ip}`);
        return res.status(403).json({ error: 'POW_HASH_INVALID' });
      }
    } catch (err) {
      console.error('[PoW] Argon2 server verify error:', err);
      return res.status(500).json({ error: 'POW_VERIFY_ERROR' });
    }

    verifiedPoW.set(ip, { nonce: hash, calcTime, m_cost, verifiedAt: Date.now() });

    const persisted = loadProfile(ip);
    const profile = argonProfiles.get(ip) || {
      m_cost: persisted?.m_cost ?? liveRules.argon2.memory,
      t_cost: persisted?.t_cost ?? liveRules.argon2.time,
      successes: persisted?.successes ?? 0,
    };
    profile.successes++;
    if (calcTime < 150) profile.m_cost = Math.min(profile.m_cost * 2, 131072);
    else if (calcTime > 600) profile.m_cost = Math.max(profile.m_cost / 1.5, 8192);
    argonProfiles.set(ip, profile);
    persistProfile(ip, { m_cost: profile.m_cost, t_cost: profile.t_cost, successes: profile.successes });

    res.json({ status: 'VERIFIED', next_m_cost: profile.m_cost });
  });

  // ── Privacy Pass (P1.6) ──────────────────────────────────────────────────────
  // Public suite/key discovery — clients need the suite id to build tokens; the
  // public key is only useful for a future verifiable (DLEQ) upgrade.
  app.get('/api/pat/config', (_req, res) => res.json(privacyPass.config()));

  // Issuance is GATED behind a currently-verified Argon2 PoW: tokens must be
  // "paid for" once with real work, otherwise they'd be a free bypass. The server
  // only sees blinded elements here, so issuance is unlinkable to later redemption.
  app.post('/api/pat/issue', express.json(), (req, res) => {
    const ip = getClientIp(req);
    if (sniperArmed && !verifiedPoW.get(ip)) {
      return res.status(403).json({ error: 'ACTIVE_INTERROGATION_REQUIRED' });
    }
    const blinded = req.body?.blindedElements;
    if (!Array.isArray(blinded)) {
      return res.status(400).json({ error: 'BLINDED_ELEMENTS_REQUIRED' });
    }
    try {
      const evaluatedElements = privacyPass.issueBatch(blinded);
      res.json({ evaluatedElements, issued: evaluatedElements.length });
    } catch (err) {
      return res.status(400).json({ error: 'ISSUE_FAILED', detail: (err as Error).message });
    }
  });

  // Redeem a token as an alternative to re-solving PoW. Returns true on the first
  // valid presentation of an unspent token; consumed thereafter (one-time).
  function tryRedeemToken(req: express.Request): boolean {
    const nonce = req.headers['x-privacy-pass-token'];
    const output = req.headers['x-privacy-pass-output'];
    if (typeof nonce !== 'string' || typeof output !== 'string') return false;
    return privacyPass.redeem(nonce, output).valid;
  }

  // ── /api/sync-pulse ────────────────────────────────────────────────────────
  app.get('/api/sync-pulse', (req, res) => {
    const ip = getClientIp(req);
    const entry = sessionKeys.get(sessionIdOf(req));
    if (!entry) return res.status(403).json({ error: 'PQC_SESSION_NOT_ESTABLISHED' });
    const pulse = rhythmManager.generateSyncPulse(ip, entry.key);
    res.json({ pulse, driftAdjustment: rhythmManager.getDriftAdjustment(ip) });
  });

  app.post('/api/verify-rhythm', express.json(), (req, res) => {
    const ip = getClientIp(req);
    const { timings, ramSalt } = req.body;
    // §7.3 fix: the client's RAM-latency "software PUF" (rhythmWorker.ts ramDna)
    // was sent as `ramSalt` but the server never read it. Now it's folded into the
    // DNA noise pool as a real physical-entropy source for the quantum DNA hash.
    if (Array.isArray(ramSalt)) {
      const salt = ramSalt.map(Number).filter(Number.isFinite);
      if (salt.length) updateNoise(salt);
    }
    const result = rhythmManager.validateRhythm(ip, timings);
    res.json(result);
  });

  // ── /api/enclave (Protected) ───────────────────────────────────────────────
  app.get('/api/enclave', sniperFilter, microStallMiddleware, (req, res) => {
    const ip = getClientIp(req);
    const pow = verifiedPoW.get(ip);

    const sealHeader = req.headers['x-silicon-dna-seal'] as string;
    const noiseHeader = req.headers['x-silicon-dna-noise'] as string;
    const sid = sessionIdOf(req);            // per-connection token, or 'default'
    const entry = sessionKeys.get(sid);

    if (!entry) return res.status(403).json({ error: 'PQC_SESSION_NOT_ESTABLISHED' });

    // Sequence counter is per-session (sid), not per-IP — two clients behind the
    // same NAT/proxy IP have independent sessions, so one's seq must not look like
    // a replay of the other's.
    const lastSeq = packetSequences.get(sid) || 0;
    const expectedSeq = lastSeq + 1;

    // L5 anti-replay: a captured seal carries the sequence number it was minted
    // for. Reusing one whose seq was already consumed (seq ≤ lastSeq) is a replay
    // — ban it explicitly with a REPLAY_ATTACK label rather than letting it fall
    // through as a generic seal failure. Only fires once a session has advanced
    // (lastSeq>0), so a legitimate retry at the current seq is never mislabeled.
    let claimedSeq: unknown = null;
    try { claimedSeq = JSON.parse(Buffer.from(sealHeader || '', 'base64').toString('utf-8'))?.seq; } catch { /* verifyEntropySeal handles malformed */ }
    if (lastSeq > 0 && typeof claimedSeq === 'number' && claimedSeq <= lastSeq) {
      const reason = `REPLAY_ATTACK seq=${claimedSeq} ≤ consumed=${lastSeq}`;
      bannedIPs.set(ip, { reason, ts: Date.now() });
      persistBan(ip, reason, 1000 * 60 * 60);
      logEvent(ip, 'REPLAY_ATTACK', { claimedSeq, lastSeq });
      broadcastThreat(ip, 'REPLAY_ATTACK', { seq: claimedSeq, consumed: lastSeq });
      globalDroppedCount++;
      console.warn(`[SNIPER: KILL] ${reason}. IP: ${ip}`);
      return res.status(403).json({ error: 'REPLAY_ATTACK' });
    }

    // sessionId='default' matches client generateSeal which prefixes 'default'
    const { valid, requiresArgon2 } = sealValidator.verifyEntropySeal(
      'default', sealHeader, noiseHeader, expectedSeq, entry.key
    );

    if (!valid) {
      console.warn(`[SNIPER: DROP] Entropy Seal Failure seq=${expectedSeq}. IP: ${ip}`);
      globalDroppedCount++;
      return res.status(403).json({ error: 'ENTROPY_SEAL_INVALID' });
    }

    // Key ratcheting — evolve key with physical noise from client every 50 packets
    entry.counter++;
    if (entry.counter >= 50) {
      const noiseSum = noiseHeader
        ? noiseHeader.split(',').map(Number).filter(isFinite).reduce((a, b) => a + b, 0)
        : Math.random();
      entry.key = crypto.createHash('sha256')
        .update(Buffer.concat([entry.key, Buffer.from(noiseSum.toString())]))
        .digest();
      entry.counter = 0;
      sessionKeys.set(sid, entry);
      currentMetrics.keyRatchetCycles++;
      console.log(`[PQC: RATCHET] Key rotation #${currentMetrics.keyRatchetCycles}`);
    }

    packetSequences.set(sid, expectedSeq);

    // A valid Privacy Pass token (P1.6) is a one-time substitute for re-solving PoW.
    if (sniperArmed && !pow && requiresArgon2 && !tryRedeemToken(req)) {
      return res.status(403).json({ error: 'ACTIVE_INTERROGATION_REQUIRED' });
    }

    res.json({ asset: 'Cognitive_Enclave', status: 'PROTECTED', dna: currentMetrics.dnaHash });
  });

  // ── /api/wallet (Protected) ────────────────────────────────────────────────
  app.get('/api/wallet', sniperFilter, microStallMiddleware, (req, res) => {
    const ip = getClientIp(req);
    const pow = verifiedPoW.get(ip);
    if (sniperArmed && !pow && !tryRedeemToken(req)) return res.status(403).json({ error: 'ACTIVE_INTERROGATION_REQUIRED' });
    res.json({ asset: 'Crypto_Wallet', status: 'PROTECTED', dna: currentMetrics.dnaHash });
  });

  // ── /metrics (Prometheus) ─────────────────────────────────────────────────
  app.get('/metrics', (_req, res) => {
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    const modeNum = currentMetrics.mode === 'IDLE' ? 0 : currentMetrics.mode === 'STRESS' ? 1 : 2;
    const lines = [
      `# HELP silicon_dna_jitter_mean_us Mean CPU jitter (microseconds)`,
      `# TYPE silicon_dna_jitter_mean_us gauge`,
      `silicon_dna_jitter_mean_us ${currentMetrics.mean}`,
      `# HELP silicon_dna_jitter_variance Jitter variance (us^2)`,
      `# TYPE silicon_dna_jitter_variance gauge`,
      `silicon_dna_jitter_variance ${currentMetrics.variance}`,
      `# HELP silicon_dna_entropy_bits Shannon entropy (bits)`,
      `# TYPE silicon_dna_entropy_bits gauge`,
      `silicon_dna_entropy_bits ${currentMetrics.entropy}`,
      `# HELP silicon_dna_autocorr_r1 Autocorrelation lag-1`,
      `# TYPE silicon_dna_autocorr_r1 gauge`,
      `silicon_dna_autocorr_r1 ${currentMetrics.autocorr}`,
      `# HELP silicon_dna_temperature_celsius Thermal profile (simulated)`,
      `# TYPE silicon_dna_temperature_celsius gauge`,
      `silicon_dna_temperature_celsius ${currentMetrics.temp}`,
      `# HELP silicon_dna_pol_percent Probability of Life 0-100`,
      `# TYPE silicon_dna_pol_percent gauge`,
      `silicon_dna_pol_percent ${currentMetrics.pol}`,
      `# HELP silicon_dna_requests_passed_total Organic requests passed`,
      `# TYPE silicon_dna_requests_passed_total counter`,
      `silicon_dna_requests_passed_total ${globalPassedCount}`,
      `# HELP silicon_dna_requests_dropped_total Synthetic requests dropped`,
      `# TYPE silicon_dna_requests_dropped_total counter`,
      `silicon_dna_requests_dropped_total ${globalDroppedCount}`,
      `# HELP silicon_dna_trust_score Rhythm trust score 0-1`,
      `# TYPE silicon_dna_trust_score gauge`,
      `silicon_dna_trust_score ${currentMetrics.trustScore}`,
      `# HELP silicon_dna_key_ratchet_cycles PQC key rotation count`,
      `# TYPE silicon_dna_key_ratchet_cycles counter`,
      `silicon_dna_key_ratchet_cycles ${currentMetrics.keyRatchetCycles}`,
      `# HELP silicon_dna_spearman_rho Last measured Spearman correlation`,
      `# TYPE silicon_dna_spearman_rho gauge`,
      `silicon_dna_spearman_rho ${lastSpearmanRho}`,
      `# HELP silicon_dna_mode_numeric Mode: 0=IDLE 1=STRESS 2=SNIPER`,
      `# TYPE silicon_dna_mode_numeric gauge`,
      `silicon_dna_mode_numeric ${modeNum}`,
      `# HELP silicon_dna_banned_ips_total Currently banned IP count`,
      `# TYPE silicon_dna_banned_ips_total gauge`,
      `silicon_dna_banned_ips_total ${bannedIPs.size}`,
    ];
    res.send(lines.join('\n') + '\n');
  });

  // ── JITTER PROBE WORKER ────────────────────────────────────────────────────
  const probePath = path.join(process.cwd(), 'probe-worker.mjs');
  const worker = new Worker(probePath);

  worker.on('message', (msg: any) => {
    if (msg.type === 'INTEGRITY_FAIL') {
      console.error('[CRITICAL] eBPF Integrity Audit Failed! Probe worker compromised.');
      return;
    }

    // Discard jitter batch if measured during ML-KEM CPU spike (L0/L7 isolation)
    if (Date.now() < pqcCooldownUntil) {
      return;
    }

    const deltas = msg.deltas as number[];
    updateNoise(deltas);
    lastJitterTs = Date.now(); // Health Decay: L0 probe is alive (before PQC guard)

    const now = Date.now();
    const elapsedSec = (now - startTime) / 1000;

    if (elapsedSec < 10) mode = 'IDLE';
    else if (elapsedSec < 35) mode = 'STRESS';
    else mode = 'SNIPER';
    sniperArmed = mode === 'SNIPER';

    // L0 stats via the tested jitterProbe module. Now that the worker times a real
    // micro-workload (not two adjacent hrtime calls), these are a genuine physical
    // signal. jitterVerdict = organic (real HW) / flat (VM/sandbox) / chaotic.
    const jstats = jitterStats(deltas);
    const mean = jstats.mean;
    const variance = jstats.variance;
    const entropy = jstats.entropy;
    const r1 = jstats.autocorr;
    lastJitterVerdict = jitterVerdict(jstats);
    lastJitterCv = Number(jstats.cv.toFixed(4));

    const targetTemp = mode === 'STRESS' ? 76.4 : 38.2;
    const friction = variance / 100000;
    currentMetrics.temp += (targetTemp + friction - currentMetrics.temp) * 0.05 + (Math.random() - 0.5) * 0.2;

    const pol = mode === 'SNIPER'
      ? Math.min(99.9, 70 + entropy * 1.2 + Math.abs(r1) * 15 + Math.abs(currentMetrics.temp - 38) * 0.2)
      : 0;

    const bins = Array(60).fill(0);
    const maxVal = mode === 'STRESS' ? 500000 : 50000;
    deltas.forEach(d => { bins[Math.min(59, Math.floor((d / maxVal) * 60))]++; });
    const maxBin = Math.max(...bins, 1);
    const normalizedHistogram = bins.map(b => (b / maxBin) * 100);

    const jitterHash = crypto.createHash('sha256').update(deltas.join(',')).digest('hex');
    // P1.5: the DNA hash is the server's own entropy commitment — keyed by the
    // stable serverDnaKey, not any client's per-session key. No PQC-session gate,
    // so jitter/DNA metrics flow even with no client connected (fixes the old
    // headless-freeze where metrics stayed 0 until a browser did the handshake).
    // Use IP-specific PoW; fall back to most recent if client hasn't verified yet
    const latestPow = verifiedPoW.get(lastClientIp) ?? Array.from(verifiedPoW.values()).pop();

    const quantumHash = computeQuantumDNAHash(
      serverDnaKey,
      mean / 1000,      // ns → µs
      variance / 1e6,   // ns² → µs²
      lastSpearmanRho,  // FIXED: actual Spearman ρ from microStall filter
      latestPow?.calcTime ?? 0,
      latestPow?.m_cost ?? 0,
      latestPow?.nonce ?? jitterHash
    );

    currentMetrics = {
      ...currentMetrics,
      mean: Number((mean / 1000).toFixed(2)),
      variance: Number((variance / 1e6).toFixed(4)),
      entropy: Number(entropy.toFixed(3)),
      autocorr: Number(r1.toFixed(3)),
      temp: Number(currentMetrics.temp.toFixed(2)),
      pol: Number(pol.toFixed(1)),
      histogram: normalizedHistogram,
      dnaHash: quantumHash,
      // FIXED: use actual client IP session, not hardcoded 'global'
      trustScore: Number(rhythmManager.getTrustStatus(lastClientIp).toFixed(2)),
      mode
    };

    const payload = JSON.stringify({
      ...currentMetrics,
      filterStats: { passed: globalPassedCount, dropped: globalDroppedCount },
      t: (now / 1000 % 100).toFixed(2)
    });

    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) client.send(payload);
    });
  });

  // ── WEBSOCKET (ML-KEM-768 Real Handshake — NIST FIPS 203) ─────────────────
  // Pre-initialize KEM instance once at startup (async, reusable)
  const _kemInit = createMlKem768();

  wss.on('connection', (ws, req) => {
    const ip = getClientIp(req);
    lastClientIp = ip;

    // Generate real ML-KEM-768 keypair per connection (pk=1184B, sk=2400B)
    // Mark jitter dirty for 150ms: keygen is the heaviest lattice operation
    pqcCooldownUntil = Date.now() + 150;
    _kemInit.then(async (kem) => {
      const [pk, sk] = await kem.generateKeyPair();
      // Keygen done — extend cooldown so probe-worker hrtime settles
      pqcCooldownUntil = Date.now() + 100;
      ws.send(JSON.stringify({ type: 'PQC_INIT', pk: Buffer.from(pk).toString('base64') }));

      ws.on('message', async (msg) => {
        try {
          const data = JSON.parse(msg.toString());
          if (data.type === 'PQC_RESP') {
            const ct = Buffer.from(data.ciphertext, 'base64');
            if (ct.length !== 1088) return;
            // Decap also CPU-heavy — mark dirty before and after
            pqcCooldownUntil = Date.now() + 100;
            const sharedSecret = await kem.decap(new Uint8Array(ct), sk);
            pqcCooldownUntil = Date.now() + 50; // tail cooldown post-decap
            // Per-connection session token (works behind Cloudflare's shared IP,
            // unlike per-IP keying). Also refresh 'default' for backward-compat
            // with clients that don't echo the token yet (e.g. current dashboard).
            const sid = crypto.randomBytes(16).toString('hex');
            const secret = { key: Buffer.from(sharedSecret), counter: 0 };
            sessionKeys.set(sid, secret);
            sessionKeys.set('default', { key: Buffer.from(sharedSecret), counter: 0 });
            ws.send(JSON.stringify({ type: 'PQC_ESTABLISHED', sessionId: sid }));
            console.log(`[PQC] ML-KEM-768 tunnel established. ss=${Buffer.from(sharedSecret).toString('hex').slice(0,16)}... IP: ${ip}`);
          }
        } catch (_e) { /* malformed JSON ignored */ }
      });
    }).catch((e) => console.error('[PQC] KEM init error:', e));
  });

  // ── Phoenix Zero state (declared here so /api/silicon-metrics can reference) ─
  type PhoenixEvent = { ts: number; type?: string; event?: string; pid?: number; cmd?: string; dst_ip?: string; rtt_ms?: number; [k: string]: unknown };
  const phoenixEvents: PhoenixEvent[] = [];
  const PHOENIX_RING = 500;
  let phoenixExecCount = 0;
  let phoenixTcpCount = 0;
  let phoenixRttEma = 0;
  let phoenixThreatScore = 0;

  // ── /api/silicon-metrics (current snapshot for agent FastAPI) ────────────
  // Returns the same 5 values siliconDnaLink.ts streams over WS, as plain JSON.
  // agent FastAPI calls this when assembling episode.state.vector[485-489].
  app.get('/api/silicon-metrics', (_req, res) => {
    const passed  = globalPassedCount;
    const dropped = globalDroppedCount;
    const total   = passed + dropped;
    const { health } = getHealthStatus();
    res.json({
      // Health Decay (STRATEGY_2026.md): operational / degraded / unavailable
      health,
      safe:            health === 'operational' ? true : null,  // null = radar blind, don't trust
      last_measurement_s: lastJitterTs > 0 ? Math.round((Date.now() - lastJitterTs) / 1000) : null,
      // Core metrics
      bot_drop_rate:   total > 0 ? dropped / total : 0,
      phoenix_threat:  phoenixThreatScore,
      phoenix_exec:    phoenixExecCount,
      phoenix_tcp:     phoenixTcpCount,
      phoenix_rtt_ms:  Math.round(phoenixRttEma * 10) / 10,
      entropy_norm:    currentMetrics.entropy / 8,
      autocorr_norm:   (currentMetrics.autocorr + 1) / 2,
      trust_score:     currentMetrics.trustScore,
      banned_count:    bannedIPs.size,
      // L2 TLS: real JA4 when a JA4-capable front is present, else null (honest —
      // no fabricated constant). tls_risk is [0,1] or null when unknown.
      tls_ja4:         lastJa4,
      tls_risk:        lastTlsRisk,
      // L0 CPU-jitter verdict from the real micro-workload timings.
      jitter_verdict:  lastJitterVerdict,
      jitter_cv:       lastJitterCv,
      // Privacy Pass (P1.6): anonymous one-time token issuance/redemption counters.
      pat_issued:      privacyPass.stats.issued,
      pat_redeemed:    privacyPass.stats.redeemed,
      pat_rejected:    privacyPass.stats.rejected,
      pat_spent:       privacyPass.spentSize,
      // Drift-adaptive σ² model (P2.7): current adaptive cutoff + drift state.
      adaptive_sigma2: sigmaDrift.snapshot().threshold,
      drift_status:    sigmaDrift.status,       // warmup | stable | drift
      drift_samples:   sigmaDrift.count,
      drift_events:    sigmaDrift.drifts,
      mode:            currentMetrics.mode,
      t:               Date.now(),
    });
  });

  // ── /api/check-ip (localhost-only ban-list lookup) ─────────────────────────
  // Lets other local services (e.g. the x402 payment gateway) gate access on
  // Silicon DNA's own bot detection without duplicating ban logic. Read-only,
  // never mutates bannedIPs. Reason string is withheld from the response —
  // only the boolean is meant to leave this box, so a caller who is banned
  // can't use this to calibrate around the specific rule that caught them.
  app.get('/api/check-ip', (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
    if (!isLocal) { res.status(403).json({ error: 'LOCALHOST_ONLY' }); return; }

    const ip = (req.query.ip as string) || '';
    if (!ip) { res.status(400).json({ error: 'ip query param required' }); return; }
    res.json({ banned: bannedIPs.has(ip) });
  });

  // ── Phoenix Zero eBPF event ingestion ────────────────────────────────────
  // Accepts kernel-level events from phoenix_zero_sensor.py (localhost only).
  // Processes events locally; optionally forwards to agent (fire-and-forget).
  app.post('/api/agent/interact', express.json({ limit: '1mb' }), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
    if (!isLocal) { res.status(403).json({ error: 'LOCALHOST_ONLY' }); return; }

    const body = req.body ?? {};
    // Sensor sends: { agent_id, data_type, payload: { events, systemic_risk, ... } }
    // Also accept flat: { events: [...] } for direct testing
    const inner = (body.payload && typeof body.payload === 'object') ? body.payload as Record<string, unknown> : body;
    const rawEvents: unknown[] = Array.isArray(inner.events) ? inner.events
      : Array.isArray(body.events) ? body.events
      : body.event ? [body] : [];

    const systemicRisk = typeof (inner as Record<string, unknown>).systemic_risk === 'number'
      ? (inner as Record<string, unknown>).systemic_risk as number : null;

    for (const raw of rawEvents) {
      if (!raw || typeof raw !== 'object') continue;
      const evt = raw as Record<string, unknown>;
      const entry: PhoenixEvent = { ts: Date.now(), ...evt };
      phoenixEvents.push(entry);
      if (phoenixEvents.length > PHOENIX_RING) phoenixEvents.shift();
      const t = (entry.type ?? entry.event ?? '') as string;
      if (t === 'exec' || t === 'sys_execve') phoenixExecCount++;
      if (t === 'tcp' || t === 'tcp_connect') phoenixTcpCount++;
      if (typeof entry.rtt_ms === 'number') {
        phoenixRttEma = phoenixRttEma === 0 ? entry.rtt_ms : phoenixRttEma * 0.9 + entry.rtt_ms * 0.1;
      }
    }

    // Threat score: use sensor's systemic_risk if available, else velocity heuristic
    if (systemicRisk !== null) {
      phoenixThreatScore = Math.max(phoenixThreatScore * 0.8, systemicRisk);
    } else {
      const windowStart = Date.now() - 10_000;
      const recentCount = phoenixEvents.filter(e => e.ts >= windowStart).length;
      phoenixThreatScore = Math.min(1, recentCount / 100);
    }

    res.json({ ok: true, processed: rawEvents.length, threat_score: phoenixThreatScore });

    // Optional agent forward (fire-and-forget — never blocks sensor)
    const agentUrl = process.env.AGENT_URL;
    if (agentUrl) {
      fetch(`${agentUrl}/api/agent/interact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(process.env.AGENT_TOKEN ? { 'Authorization': 'Bearer ' + process.env.AGENT_TOKEN } : {}) },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5_000),
      }).catch((err: Error) => console.warn(`[Phoenix→agent] ${err.message}`));
    }
  });

  // XDP kernel-level threat filter sync — exposes banned IPs for the eBPF loader
  app.get('/api/admin/xdp-sync', (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      res.status(403).end(); return;
    }
    res.json({
      ips: [...bannedIPs],
      count: bannedIPs.size,
      threat_score: phoenixThreatScore,
      t: Date.now(),
    });
  });

  // ── /api/health-proof — verifiable proof of node health ────
  // Returns a ZK-lite commitment proving current node health metrics without
  // revealing raw values. When x402 gateway is configured, /api/v1/health-proof
  // proxies here with payment gating. Direct access for demo/hackathon.
  app.get('/api/health-proof', (req, res) => {
    const clientIp = getClientIp(req);
    const { health } = getHealthStatus();
    const uptime = Math.round((Date.now() - startTime) / 1000);

    const layers: LayerResult = {
      l0_pqc:          sessionKeys.has(clientIp),
      l1_gpu_ua:       true,
      l2_frankenstein: true,
      l3_spearman:     lastSpearmanRho >= (liveRules.rho ?? 0.3),
      l4_variance:     currentMetrics.variance >= 2.0 && currentMetrics.variance < 10.0,
      l5_argon2:       false,
      l6_entropy:      currentMetrics.entropy > 1.0,
      l7_jitter:       currentMetrics.mode === 'SNIPER',
    };

    const proof = issueProof(serverDnaKey, layers, clientIp);
    const total = globalPassedCount + globalDroppedCount;

    res.json({
      node: {
        health,
        uptime_s: uptime,
        version: '5.0.0',
        threat_score: phoenixThreatScore,
        layers_passed: proof.layersBitmap.toString(2).padStart(8, '0'),
        trust_ratio: total > 0 ? Math.round((globalPassedCount / total) * 1000) / 1000 : 1.0,
        ebpf: {
          xdp_shield: isXdpAttached(),
          lsm_guard: isLsmLoaded(),
          banned_ips: bannedIPs.size,
        },
      },
      proof,
      payment_rails: ['base_usdc', 'hedera_hbar'],
      pricing: {
        base_usdc: { amount: '0.01', chain_id: 8453, token: 'USDC' },
        hedera_hbar: { amount: '0.01', network: 'hedera:testnet', token: 'HBAR' },
      },
      t: Date.now(),
    });
  });

  // Remote calibration — update liveRules thresholds (localhost only)
  app.post('/api/admin/calibrate', express.json(), (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      res.status(403).end(); return;
    }
    const { sigma2, rho, argon2 } = req.body ?? {};
    if (typeof sigma2 === 'number' && sigma2 > 0) liveRules.sigma2 = sigma2;
    if (typeof rho === 'number' && rho > 0 && rho < 1) liveRules.rho = rho;
    if (argon2?.time) liveRules.argon2.time = argon2.time;
    if (argon2?.memory) liveRules.argon2.memory = argon2.memory;
    console.log(`[🧬 CALIBRATE] σ²=${liveRules.sigma2} ρ=${liveRules.rho} argon2=${JSON.stringify(liveRules.argon2)}`);
    res.json({ ok: true, rules: liveRules });
  });

  // Demo/test helper — clears in-memory + on-disk bans (localhost only)
  app.post('/api/admin/reset-bans', (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      res.status(403).end(); return;
    }
    bannedIPs.clear();
    // Was: raw fs.writeFileSync(bansPath, '[]') here, bypassing persist.ts's
    // own _bans object — left stale in-memory entries that would get written
    // back into the file (as the wrong array shape, see persist.ts's load
    // guard) on the next persistBan() call. clearBans() owns this state.
    clearBans();
    // Full reset: previously only bannedIPs was cleared, so a Sybil-flagged IP
    // stayed blocked (24h TTL) and shadow throttles persisted despite "reset".
    sybilCluster.clear();
    clearShadowRecords();
    requestLog.clear();
    globalDroppedCount = 0;
    globalPassedCount = 0;
    res.json({ ok: true, message: 'Full reset: bans, sybil, shadow, timing (memory + disk)' });
  });

  // Expose Phoenix Zero state for dashboard + external reads
  app.get('/api/phoenix-status', (_req, res) => {
    const windowStart = Date.now() - 10_000;
    res.json({
      running: true,
      exec_total: phoenixExecCount,
      tcp_total: phoenixTcpCount,
      rtt_ema_ms: Math.round(phoenixRttEma * 10) / 10,
      threat_score: phoenixThreatScore,
      recent_10s: phoenixEvents.filter(e => e.ts >= windowStart).length,
      ring_size: phoenixEvents.length,
      last_event: phoenixEvents.at(-1) ?? null,
    });
  });

  // ── /.well-known/x402 — x402 V2 agent discovery metadata ──
  // Lets facilitators and agent directories auto-discover our paid endpoints.
  app.get('/.well-known/x402', (_req, res) => {
    res.json({
      version: '2.0',
      provider: 'Phoenix Zero',
      description: 'Real-time L2 sequencer health oracle with kernel-level bot detection',
      facilitators: [
        { url: 'https://api.cdp.coinbase.com/platform/v2/x402', network: 'eip155:8453' },
        { url: 'https://api.testnet.blocky402.com', network: 'hedera:testnet' },
      ],
      endpoints: [
        {
          method: 'GET', path: '/api/v1/safe',
          description: 'Boolean safety check — safe to execute?',
          price: '$0.01', network: 'eip155:8453', token: 'USDC',
        },
        {
          method: 'GET', path: '/api/v1/health',
          description: 'Full sequencer health snapshot (all chains)',
          price: '$0.01', network: 'eip155:8453', token: 'USDC',
        },
        {
          method: 'GET', path: '/api/v1/chains/{chain}',
          description: 'Single-chain health (base|arbitrum|optimism|zksync)',
          price: '$0.01', network: 'eip155:8453', token: 'USDC',
        },
        {
          method: 'GET', path: '/api/v1/price',
          description: 'Current pricing with MEV surge multiplier',
          price: '$0.01', network: 'eip155:8453', token: 'USDC',
        },
        {
          method: 'POST', path: '/api/v1/classify',
          description: 'Agent identity classification (HUMAN/LEGIT_AGENT/MALICIOUS_BOT)',
          price: '$0.01', network: 'eip155:8453', token: 'USDC',
        },
        {
          method: 'GET', path: '/api/v1/health-proof',
          description: 'Cryptographic proof of node health (HMAC-SHA256 commitment)',
          price: '$0.01', network: 'eip155:8453', token: 'USDC',
        },
      ],
      hedera_endpoints: [
        {
          method: 'GET', path: '/api/v1/health',
          description: 'Full sequencer health snapshot (Hedera rail)',
          price: '$0.01', network: 'hedera:testnet', token: 'HBAR',
        },
        {
          method: 'GET', path: '/api/v1/safe',
          description: 'Boolean safety check (Hedera rail)',
          price: '$0.01', network: 'hedera:testnet', token: 'HBAR',
        },
      ],
      pay_to: '0xbb967F16C7f3e9B4c1626680684445d41dBE44Ab',
      free_endpoints: ['/api/health', '/api/health-proof', '/api/silicon-metrics'],
      security: {
        ebpf_xdp: isXdpAttached(),
        ebpf_lsm: isLsmLoaded(),
        pqc: 'ML-KEM-768',
        zk_proofs: 'HMAC-SHA256 commitment',
        layers: 14,
      },
      contact: 'aleksandrkent64@gmail.com',
    });
  });

  // ── /api/health — public health endpoint (Health Decay, STRATEGY_2026.md) ──
  // Returns HTTP 503 when unavailable so load balancers and pull-oracle clients
  // know the radar is blind. Clients MUST treat safe=null as "do not trade".
  app.get('/api/health', (_req, res) => {
    const { health } = getHealthStatus();
    const code = health === 'unavailable' ? 503 : 200;
    res.status(code).json({
      health,
      safe:               health === 'operational' ? true : null,
      mode,               // local var — reflects real elapsedSec-based transitions
      uptime_s:           Math.round((Date.now() - startTime) / 1000),
      last_measurement_s: lastJitterTs > 0 ? Math.round((Date.now() - lastJitterTs) / 1000) : null,
      version:            '5.0.0',
    });
  });

  // Phase 57.8: Push Silicon DNA metrics to agent every 60s
  if (AGENT_URL) {
    setInterval(() => {
      const total = globalPassedCount + globalDroppedCount;
      const trust = total > 0 ? globalPassedCount / total : 1.0;
      const jitter = currentMetrics.entropy ?? 0.5;
      const sniper = currentMetrics.variance > 0 ? Math.min(currentMetrics.variance / 10, 1) : 0.5;
      const entropy_norm  = (currentMetrics.entropy ?? 0) / 8;
      const autocorr_norm = ((currentMetrics.autocorr ?? 0) + 1) / 2;
      const bot_drop_rate = total > 0 ? globalDroppedCount / total : 0;
      fetch(`${AGENT_URL}/api/silicon-dna`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(process.env.AGENT_TOKEN ? { 'Authorization': 'Bearer ' + process.env.AGENT_TOKEN } : {}) },
        // ja3 kept for agent schema back-compat but now carries the REAL TLS risk
        // (from a JA4 front) when available; 0.5 is an honest "unknown", not a fake.
        body: JSON.stringify({ jitter, sniper, ja3: lastTlsRisk ?? 0.5, ja4: lastJa4, behavioral: 0.5, trust, entropy_norm, autocorr_norm, bot_drop_rate }),
      }).catch((e: Error) => console.warn(`[DNA→agent] ${e.message}`));
    }, 60_000);
  }

  // ── /api/sybil — cross-IP cohort detection ────────────────────────────────
  app.post('/api/sybil/ingest', express.json(), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
    if (!isLocal) { res.status(403).json({ error: 'LOCALHOST_ONLY' }); return; }

    const { ip, entropy, variance, autocorr, spearmanRho, requestIntervals } = req.body ?? {};
    if (!ip || !Array.isArray(requestIntervals)) {
      res.status(400).json({ error: 'MISSING_FIELDS' }); return;
    }
    sybilCluster.ingest(ip, { entropy: entropy ?? 0, variance: variance ?? 0, autocorr: autocorr ?? 0, spearmanRho: spearmanRho ?? 0, requestIntervals });
    res.json({ ok: true, cohort_size: sybilCluster.getCohortSize(ip), stats: sybilCluster.getStats() });
  });

  app.post('/api/sybil/flag', express.json(), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
    if (!isLocal) { res.status(403).json({ error: 'LOCALHOST_ONLY' }); return; }

    const { ip } = req.body ?? {};
    if (!ip) { res.status(400).json({ error: 'MISSING_IP' }); return; }
    const count = sybilCluster.flag(ip);
    res.json({ ok: true, count, flagged_cohort_size: count });
  });

  app.get('/api/sybil/stats', (_req, res) => {
    res.json(sybilCluster.getStats());
  });

  // ── /api/classify — 3-class agent detection ───────────────────────────────
  app.post('/api/classify', express.json(), (req, res) => {
    const clientIp = getClientIp(req);
    const rl = checkFreeRateLimit(clientIp);
    if (!rl.allowed) {
      res.status(429).json({
        error: 'rate_limit_exceeded',
        limit: FREE_RATE_LIMIT,
        window: '1m',
        upgrade: 'POST /api/v1/classify via x402 for unlimited access ($0.01 USDC)',
        discovery: '/.well-known/x402',
      });
      return;
    }
    const result = classifyAgent({
      ua: (req.headers['user-agent'] as string) ?? '',
      spearmanRho: lastSpearmanRho,
      variance: currentMetrics.variance,
      entropy: currentMetrics.entropy,
      frankensteinScore: checkConsistency(req),
      hasPoW: verifiedPoW.has(clientIp),
      headers: req.headers as Record<string, string>,
    });
    res.set('X-RateLimit-Remaining', String(rl.remaining));
    res.json(result);
  });

  // ── /api/trust-assessment — fused, graduated trust decision ───────────────
  // Composes the existing PQC/Frankenstein/rhythm/classifier/wallet-Sybil
  // checks behind one policy (src/services/trustEngine.ts) instead of each
  // being evaluated in isolation at its own call site. Hard gates (PQC
  // session, WebDriver artifacts, Frankenstein >=100) short-circuit to DENY;
  // everything else fuses into one score with weakest-signal moderation,
  // landing in ALLOW / STEP_UP / SHADOW_LIMIT / DENY rather than a bare
  // boolean. None of the underlying checks changed — this only adds the
  // fusion layer over signals server.ts already computes elsewhere.
  app.post('/api/trust-assessment', express.json(), (req, res) => {
    const ip = getClientIp(req);
    const rl = checkFreeRateLimit(ip);
    if (!rl.allowed) {
      res.status(429).json({
        error: 'rate_limit_exceeded', limit: FREE_RATE_LIMIT, window: '1m',
        upgrade: 'Use x402 paid endpoints for unlimited access ($0.01 USDC)',
        discovery: '/.well-known/x402',
      });
      return;
    }
    res.set('X-RateLimit-Remaining', String(rl.remaining));
    const { wallet, automationFingerprint } = req.body ?? {};

    const frankensteinScore = checkConsistency(req);
    const classification = classifyAgent({
      ua: (req.headers['user-agent'] as string) ?? '',
      spearmanRho: lastSpearmanRho,
      variance: currentMetrics.variance,
      entropy: currentMetrics.entropy,
      frankensteinScore,
      hasPoW: verifiedPoW.has(ip),
      headers: req.headers as Record<string, string>,
    });

    const automationVerdict = automationFingerprint ? detectAutomation(automationFingerprint) : null;

    const signals = [
      pqcSessionSignal(sessionKeys.has(sessionIdOf(req))),
      automationSignal(automationVerdict?.detected ?? false, automationVerdict?.reasons ?? []),
      frankensteinSignal(frankensteinScore),
      rhythmTrustSignal(rhythmManager.getTrustStatus(ip)),
      classifierSignal(classification.agentClass, classification.confidence),
    ];

    if (wallet) {
      const binding = lookupWallet(wallet);
      if (binding) {
        signals.push(walletSybilSignal(getWalletsByHash(binding.behavioralHash).length));
      }
    }

    const assessment = evaluateTrust(signals);

    // Give the decision real teeth — matches every other detector in this file
    // (Spearman/Frankenstein/PoW-forgery, see e.g. the bannedIPs.set() calls
    // above): DENY actually bans, not just reports. Added 2026-08-10 after
    // it shipped as assessment-only with no enforcement wired to it — this
    // was a real gap, not a design choice, flagged and closed same day.
    if (assessment.decision === 'DENY') {
      const reason = assessment.reasons[0] ?? 'trust_assessment_deny';
      globalDroppedCount++;
      bannedIPs.set(ip, { reason, ts: Date.now() });
      persistBan(ip, reason, 1000 * 60 * 60);
      logEvent(ip, 'TRUST_ASSESSMENT_DENY', { fusedScore: assessment.fusedScore, reasons: assessment.reasons });
      broadcastThreat(ip, 'TRUST_ASSESSMENT_DENY', { fusedScore: assessment.fusedScore, reasons: assessment.reasons });
    }

    res.json(assessment);
  });

  // ── /api/agent/verify — cryptographic agent identity (P1.4) ───────────────
  // The machine-economy answer to "which agent is this?": an agent presents a
  // signed credential (agentId + issuer + reputation + expiry + nonce). We do
  // REAL secp256k1 ecrecover (EIP-191), confirm the signer == issuer, check
  // expiry / trusted-issuer allowlist, then return a graduated ALLOW/STEP_UP/DENY
  // that blends verifiable identity+reputation with this request's behavior risk.
  // A verified, reputable agent is allowed even though it's automated — that's the
  // point; anonymous callers still fall back to behavior.
  // P2.8: the caller may instead present a post-quantum credential by sending
  // alg='ml-dsa-65' + publicKey (hex); we then verify with ML-DSA-65 (FIPS 204)
  // instead of secp256k1. Same credential shape, same ALLOW/STEP_UP/DENY output —
  // so the identity is post-quantum end to end alongside the ML-KEM-768 channel.
  app.post('/api/agent/verify', express.json(), (req, res) => {
    const ip = getClientIp(req);
    const { credential, signature, alg, publicKey } = req.body ?? {};
    if (!credential || !signature) {
      res.status(400).json({ error: 'MISSING_FIELDS', required: ['credential', 'signature'] }); return;
    }
    const isPq = alg === 'ml-dsa-65';
    if (isPq && typeof publicKey !== 'string') {
      res.status(400).json({ error: 'MISSING_FIELDS', required: ['publicKey (for alg=ml-dsa-65)'] }); return;
    }
    const trusted = (process.env.TRUSTED_AGENT_ISSUERS || '')
      .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const opts = trusted.length ? { trustedIssuers: new Set(trusted) } : {};
    const check = isPq
      ? verifyMlDsaCredential(credential, signature, publicKey, opts)
      : verifyAgentCredential(credential, signature, opts);
    // Behavior risk for this caller: Frankenstein score (0..1), blended with TLS risk.
    const behaviorRisk = Math.max(checkConsistency(req) / 100, lastTlsRisk ?? 0);
    const decision = agentTrustDecision(check, behaviorRisk);
    logEvent(ip, 'AGENT_VERIFY', { valid: check.valid, reason: check.reason, agentId: check.agentId, decision });
    res.json({
      verified: check.valid,
      reason: check.reason,
      alg: isPq ? 'ml-dsa-65' : 'secp256k1',
      agent_id: check.agentId ?? null,
      reputation: check.reputation ?? null,
      signer: check.signer ?? null,
      behavior_risk: Number(behaviorRisk.toFixed(3)),
      decision,
    });
  });

  // ── /api/shadow-stats — RPC shadow filter metrics ─────────────────────────
  app.get('/api/shadow-stats', (_req, res) => {
    res.json(getShadowStats());
  });

  app.post('/api/admin/clear-shadow', (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      res.status(403).end(); return;
    }
    clearShadowRecords();
    res.json({ ok: true });
  });

  // ── /api/wallet/bind — on-chain wallet identity binding ───────────────────
  app.post('/api/wallet/bind', express.json(), (req, res) => {
    const clientIp = getClientIp(req);
    const { wallet, signature, challenge } = req.body ?? {};

    if (!wallet || !signature || !challenge) {
      res.status(400).json({ error: 'MISSING_FIELDS', required: ['wallet', 'signature', 'challenge'] }); return;
    }

    if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
      res.status(400).json({ error: 'INVALID_WALLET_FORMAT' }); return;
    }

    if (!validateSignatureStructure(signature)) {
      res.status(400).json({ error: 'INVALID_SIGNATURE_FORMAT' }); return;
    }

    // REAL EIP-191 ecrecover — the binding now proves control of the private key.
    // Previously only signature *structure* was checked, so any 65-byte blob bound
    // any wallet to any fingerprint (spoofable identity). Fixed 2026-08-16.
    const recovered = verifyEip191(challenge, signature);
    if (!recovered || recovered !== wallet.toLowerCase()) {
      logEvent(clientIp, 'WALLET_SIG_INVALID', { wallet: wallet.toLowerCase(), recovered });
      res.status(401).json({ error: 'SIGNATURE_INVALID', reason: 'recovered signer != wallet' }); return;
    }

    // Per-client session key as the HMAC secret; stable serverDnaKey fallback
    // (the old per-call crypto.randomBytes made no-session hashes non-reproducible).
    const secret = sessionKeys.get(sessionIdOf(req))?.key ?? serverDnaKey;
    const behavioralHash = computeBehavioralHash(
      secret,
      currentMetrics.entropy,
      currentMetrics.variance,
      lastSpearmanRho
    );

    const result = bindWallet(wallet, behavioralHash, clientIp);
    res.json({
      ok: true,
      wallet,
      behavioral_hash: behavioralHash.slice(0, 16) + '...',
      sybil_detected: result.sybilDetected,
      shared_wallets: result.sharedWallets,
    });
  });

  app.get('/api/wallet/lookup', (req, res) => {
    const wallet = (req.query.wallet as string) ?? '';
    if (!wallet) { res.status(400).json({ error: 'MISSING_WALLET' }); return; }
    const binding = lookupWallet(wallet);
    if (!binding) { res.status(404).json({ error: 'NOT_FOUND' }); return; }
    res.json({
      wallet: binding.wallet,
      bound_at: binding.boundAt,
      behavioral_hash: binding.behavioralHash.slice(0, 16) + '...',
    });
  });

  app.get('/api/wallet/stats', (_req, res) => {
    res.json(getBindingStats());
  });

  app.post('/api/admin/clear-wallets', (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      res.status(403).end(); return;
    }
    clearBindings();
    res.json({ ok: true });
  });

  // ── /api/zk — ZK-lite proof generation and redemption ────────────────────
  app.post('/api/zk/issue', (req, res) => {
    const clientIp = getClientIp(req);
    // Per-client session key as the HMAC secret; stable serverDnaKey fallback
    // (the old per-call crypto.randomBytes made no-session hashes non-reproducible).
    const secret = sessionKeys.get(sessionIdOf(req))?.key ?? serverDnaKey;

    const pow = verifiedPoW.get(clientIp);
    const layers: LayerResult = {
      l0_pqc:          sessionKeys.has(clientIp),
      l1_gpu_ua:        true,
      l2_frankenstein:  true,
      l3_spearman:      lastSpearmanRho >= (liveRules.rho ?? 0.3),
      l4_variance:      currentMetrics.variance >= 2.0 && currentMetrics.variance < 10.0,
      l5_argon2:        !!pow,
      l6_entropy:       currentMetrics.entropy > 1.0,
      l7_jitter:        currentMetrics.mode === 'SNIPER',
    };

    const proof = issueProof(secret, layers, clientIp);
    res.json({ proof, layers_passed: proof.layersBitmap.toString(2).padStart(8, '0') });
  });

  app.post('/api/zk/verify', express.json(), (req, res) => {
    // Per-client session key as the HMAC secret; stable serverDnaKey fallback
    // (the old per-call crypto.randomBytes made no-session hashes non-reproducible).
    const secret = sessionKeys.get(sessionIdOf(req))?.key ?? serverDnaKey;
    const proof = req.body?.proof;

    if (!proof || typeof proof.commitment !== 'string') {
      res.status(400).json({ error: 'INVALID_PROOF' }); return;
    }

    const result = redeemProof(secret, proof);
    res.json(result);
  });

  app.post('/api/admin/clear-proofs', (req, res) => {
    const ip = req.socket.remoteAddress ?? '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      res.status(403).end(); return;
    }
    clearProofs();
    res.json({ ok: true });
  });

  // ── VITE DEV / PRODUCTION STATIC ──────────────────────────────────────────
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Silicon DNA [L0_CORE] Active  → http://localhost:${PORT}`);
    console.log(`Prometheus metrics            → http://localhost:${PORT}/metrics`);
  });
}

startServer();
