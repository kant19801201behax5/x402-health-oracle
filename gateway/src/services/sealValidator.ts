// src/services/sealValidator.ts
// Протокол "Golden Seal" v4.0 — Энтропийные замки
// Связывает каждый пакет с физическим состоянием процессора (джиттер) и криптографическим ключом.

import crypto from 'crypto';
import { getTrustStatus } from './rhythmManager';

const SEAL_HEADER = 'x-silicon-dna-seal'; 
const NOISE_HEADER = 'x-silicon-dna-noise';
const ARGON2_COST_THRESHOLD = 0.7; 

interface SealData {
  sig: string;
  ts: number;
  seq: number;
}

/**
 * Проверяет входящий seal на сервере.
 */
export function verifyEntropySeal(
  sessionId: string,
  sealHeader: string | undefined,
  noiseHeader: string | undefined,
  packetIndex: number,
  sharedSecret: Buffer
): { valid: boolean; trustImpact: number; requiresArgon2: boolean } {
  if (!sealHeader) {
    return { valid: false, trustImpact: -0.3, requiresArgon2: true };
  }

  try {
    const sealData: SealData = JSON.parse(Buffer.from(sealHeader, 'base64').toString('utf-8'));
    const { sig, ts, seq } = sealData;

    // 1. Anti-Replay window, with clock-skew tolerance.
    // A hard `age < 0` rejected any client whose clock was even a few hundred ms
    // AHEAD of the server — which is most real clients (browsers behind Cloudflare
    // etc.), so the enclave seal only ever validated when the caller ran on the
    // server itself. We keep a 5s freshness window against replay, but allow up to
    // CLOCK_SKEW into the "future" so a normally-skewed client isn't rejected.
    const CLOCK_SKEW_US = 30_000_000; // 30s each way for NTP drift / latency
    const nowMicro = Date.now() * 1000;
    const age = nowMicro - ts;
    if (age > 5_000_000 + CLOCK_SKEW_US || age < -CLOCK_SKEW_US) {
      return { valid: false, trustImpact: -0.5, requiresArgon2: true };
    }

    // 2. Sequence check (Strict Enforcement)
    if (seq !== packetIndex) {
       return { valid: false, trustImpact: -0.6, requiresArgon2: true };
    }

    // 3. Signature Verification
    // The client sends noise in NOISE_HEADER to prove physical presence
    const noiseStr = noiseHeader || '';
    const hmac = crypto.createHmac('sha256', sharedSecret);
    hmac.update(sessionId);
    hmac.update(seq.toString());
    hmac.update(noiseStr);
    const expectedSig = hmac.digest('hex');

    if (sig !== expectedSig) {
       return { valid: false, trustImpact: -0.4, requiresArgon2: true };
    }

    const currentTrust = getTrustStatus(sessionId);
    if (currentTrust < ARGON2_COST_THRESHOLD) {
      return { valid: true, trustImpact: 0.02, requiresArgon2: true }; 
    }

    return { valid: true, trustImpact: 0.05, requiresArgon2: false };
  } catch (e) {
    return { valid: false, trustImpact: -0.4, requiresArgon2: true };
  }
}

export function shouldTriggerArgon2(sessionId: string): boolean {
  return getTrustStatus(sessionId) < ARGON2_COST_THRESHOLD;
}
