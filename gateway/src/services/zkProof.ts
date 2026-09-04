/**
 * ZK-lite Proof Layer — Commit-and-Reveal for 7-layer Silicon DNA verification
 *
 * Scheme: HMAC-SHA256 commitment
 *   Commit  = HMAC(secret, bitmap || ":" || salt || ":" || ts || ":" || ip_hash)
 *   Reveal  = share { commitment, salt, layersBitmap, ts, ip_hash }
 *   Verify  = recompute HMAC and compare with timing-safe equality
 *
 * Privacy: raw entropy / variance / spearman values never leave the server.
 * Proofs are single-use and expire after TTL_MS.
 */
import * as crypto from 'crypto';

export interface LayerResult {
  l0_pqc: boolean;         // ML-KEM-768 handshake established
  l1_gpu_ua: boolean;      // GPU/UA consistency check passed
  l2_frankenstein: boolean; // Frankenstein score < 100
  l3_spearman: boolean;    // Spearman ρ above threshold
  l4_variance: boolean;    // variance in natural human range
  l5_argon2: boolean;      // Argon2id PoW verified
  l6_entropy: boolean;     // Shannon entropy seal valid
  l7_jitter: boolean;      // CPU jitter DNA match
}

export interface ZkProof {
  commitment: string;   // HMAC hex (public)
  salt: string;         // 16-byte random hex (revealed for verification)
  layersBitmap: number; // 8-bit mask: which layers passed
  ts: number;           // issuance timestamp (unix ms)
  ip_hash: string;      // 16-char truncated SHA-256 of IP (privacy-preserving)
  version: number;
}

export interface VerifyResult {
  valid: boolean;
  allLayersPassed: boolean;
  layerCount: number;
  age_ms: number;
}

const PROOF_VERSION = 1;
const PROOF_TTL_MS = 5 * 60 * 1000; // 5 minutes

// One-time-use registry — prevents replay attacks
const issuedProofs = new Map<string, number>(); // commitment → issuedAt

function layersToInt(l: LayerResult): number {
  return (
    (l.l0_pqc         ? 0b00000001 : 0) |
    (l.l1_gpu_ua      ? 0b00000010 : 0) |
    (l.l2_frankenstein ? 0b00000100 : 0) |
    (l.l3_spearman    ? 0b00001000 : 0) |
    (l.l4_variance    ? 0b00010000 : 0) |
    (l.l5_argon2      ? 0b00100000 : 0) |
    (l.l6_entropy     ? 0b01000000 : 0) |
    (l.l7_jitter      ? 0b10000000 : 0)
  );
}

function countBits(n: number): number {
  let count = 0;
  while (n) { count += n & 1; n >>>= 1; }
  return count;
}

function buildPayload(bitmap: number, salt: string, ts: number, ipHash: string): string {
  return `${bitmap}:${salt}:${ts}:${ipHash}`;
}

export function generateZkProof(
  secret: Buffer,
  layers: LayerResult,
  ip: string
): ZkProof {
  const salt = crypto.randomBytes(16).toString('hex');
  const ts = Date.now();
  const bitmap = layersToInt(layers);
  const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
  const commitment = crypto
    .createHmac('sha256', secret)
    .update(buildPayload(bitmap, salt, ts, ipHash))
    .digest('hex');

  return { commitment, salt, layersBitmap: bitmap, ts, ip_hash: ipHash, version: PROOF_VERSION };
}

export function verifyZkProof(secret: Buffer, proof: ZkProof): VerifyResult {
  const age = Date.now() - proof.ts;
  if (age > PROOF_TTL_MS) {
    return { valid: false, allLayersPassed: false, layerCount: 0, age_ms: age };
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(buildPayload(proof.layersBitmap, proof.salt, proof.ts, proof.ip_hash))
    .digest('hex');

  let valid = false;
  try {
    valid = crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(proof.commitment, 'hex')
    );
  } catch {
    valid = false;
  }

  return {
    valid,
    allLayersPassed: proof.layersBitmap === 0xff,
    layerCount: countBits(proof.layersBitmap),
    age_ms: age,
  };
}

export function issueProof(secret: Buffer, layers: LayerResult, ip: string): ZkProof {
  const proof = generateZkProof(secret, layers, ip);
  issuedProofs.set(proof.commitment, proof.ts);
  // Evict expired proofs to prevent unbounded growth
  const cutoff = Date.now() - PROOF_TTL_MS;
  for (const [k, v] of issuedProofs) if (v < cutoff) issuedProofs.delete(k);
  return proof;
}

export function redeemProof(
  secret: Buffer,
  proof: ZkProof
): VerifyResult & { replay: boolean } {
  if (!issuedProofs.has(proof.commitment)) {
    return { valid: false, allLayersPassed: false, layerCount: 0, age_ms: 0, replay: true };
  }
  const result = verifyZkProof(secret, proof);
  if (result.valid) issuedProofs.delete(proof.commitment); // one-time use
  return { ...result, replay: false };
}

export function clearProofs(): void {
  issuedProofs.clear();
}
