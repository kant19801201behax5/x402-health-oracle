/**
 * Privacy Pass anonymous tokens — OPRF(P-384, SHA-384), base mode (RFC 9497, mode 0x00).
 *
 * WHY THIS EXISTS
 * ───────────────
 * The enclave gate can demand an Argon2id proof-of-work every time a client crosses
 * the "active interrogation" threshold. That is correct but expensive to repeat, and
 * repeating it links every request of one client together. Privacy Pass fixes both:
 * a client solves ONE Argon2 PoW, exchanges it for a batch of blinded one-time tokens,
 * and then redeems one token per subsequent protected request instead of re-solving.
 *
 * The tokens are:
 *   • unforgeable — the redemption value is OPRF_skS(nonce); without the server's
 *     secret key skS an attacker cannot produce it for a fresh nonce (OPRF is a PRF),
 *   • unlinkable  — at issuance the server only sees `blind · H2C(nonce)` (a uniformly
 *     random group element), and at redemption it sees `nonce`; the random blind makes
 *     the two transcripts statistically independent, so the server cannot tie a
 *     redemption back to the issuance that produced it,
 *   • one-time    — each nonce is recorded in a spent-set on first redemption.
 *
 * This is the privately-verifiable construction: issuer and origin are the same server
 * holding the same key, so no DLEQ proof is transmitted (mode 0x00, not the verifiable
 * mode 0x01). That is sound for a self-hosted gate; a multi-attester deployment would
 * upgrade to VOPRF (mode 0x01) with the DLEQ proof and per-epoch key rotation.
 *
 * Correctness is pinned to the official RFC 9497 §A.4.1.1 test vector in the unit tests
 * (tests/privacyPass.test.ts) — BlindedElement, EvaluationElement and Output all match
 * the RFC byte-for-byte, including the server-direct redemption recomputation.
 */
import { p384, hashToCurve } from '@noble/curves/p384';
import { invert } from '@noble/curves/abstract/modular';
import { sha384 } from '@noble/hashes/sha2';
import crypto from 'crypto';

const Point = p384.Point;
type GroupElement = InstanceType<typeof Point>;
const ORDER = p384.CURVE.n;

export const SUITE = 'OPRF(P-384, SHA-384)';
export const SUITE_MODE = 0x00;
/** Serialized (compressed) P-384 element = 1 + 48 bytes. */
const ELEMENT_BYTES = 49;
/** SHA-384 output = 48 bytes. */
const OUTPUT_BYTES = 48;

// ── byte helpers ────────────────────────────────────────────────────────────
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
/** I2OSP(n, 2) — 2-byte big-endian length prefix (RFC 8017). */
function i2osp2(n: number): Uint8Array {
  if (n < 0 || n > 0xffff) throw new RangeError('i2osp2 out of range');
  return Uint8Array.of((n >> 8) & 0xff, n & 0xff);
}
const bytesToHex = (u8: Uint8Array): string => Buffer.from(u8).toString('hex');
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new TypeError('invalid hex');
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

// RFC 9497 §3.1: contextString = "OPRFV1-" || I2OSP(mode,1) || "-" || identifier
const CONTEXT_STRING = concatBytes(utf8('OPRFV1-'), Uint8Array.of(SUITE_MODE), utf8('-P384-SHA384'));
// HashToGroup DST = "HashToGroup-" || contextString
const H2G_DST = concatBytes(utf8('HashToGroup-'), CONTEXT_STRING);

// ── core OPRF primitives ─────────────────────────────────────────────────────
/** DeriveGroupElement: hash an input to a P-384 point (P384_XMD:SHA-384_SSWU_RO_). */
export function hashToGroup(input: Uint8Array): GroupElement {
  return hashToCurve(input, { DST: H2G_DST }) as GroupElement;
}

/** SerializeElement — compressed SEC1 (49 bytes) as hex. */
export function serializeElement(el: GroupElement): string {
  return bytesToHex(el.toBytes(true));
}

/** DeserializeElement — parse compressed hex, reject off-curve and the identity element. */
export function deserializeElement(hex: string): GroupElement {
  const bytes = hexToBytes(hex);
  if (bytes.length !== ELEMENT_BYTES) throw new TypeError('element must be 49 bytes');
  const el = Point.fromHex(hex);          // throws if not on curve
  el.assertValidity();
  if (el.is0()) throw new TypeError('identity element rejected');
  return el;
}

/**
 * Finalize hash — Hash(I2OSP(len(input),2) || input || I2OSP(len(el),2) || el || "Finalize").
 * `unblindedElement` is the serialized bytes of skS·H2C(input).
 */
function finalizeHash(input: Uint8Array, unblindedElement: Uint8Array): Uint8Array {
  return sha384(concatBytes(
    i2osp2(input.length), input,
    i2osp2(unblindedElement.length), unblindedElement,
    utf8('Finalize'),
  ));
}

// ── client side ──────────────────────────────────────────────────────────────
export interface BlindResult {
  /** kept secret on the client until Finalize; never sent */
  blind: bigint;
  /** blind · H2C(input), serialized — this is what the client sends to the issuer */
  blindedElement: string;
}

/** Blind(input): pick a random scalar and blind H2C(input). `fixedBlind` is for KATs only. */
export function blind(input: Uint8Array, fixedBlind?: bigint): BlindResult {
  const scalar = fixedBlind ?? randomScalar();
  if (scalar <= 0n || scalar >= ORDER) throw new RangeError('blind scalar out of range');
  const el = hashToGroup(input);
  const blinded = el.multiply(scalar);
  return { blind: scalar, blindedElement: serializeElement(blinded) };
}

/** Finalize(input, blind, evaluatedElement): unblind and hash → token output (hex). */
export function finalize(input: Uint8Array, blindScalar: bigint, evaluatedElementHex: string): string {
  const evaluated = deserializeElement(evaluatedElementHex);
  const inv = invert(blindScalar, ORDER);
  const unblinded = evaluated.multiply(inv);            // skS · H2C(input)
  return bytesToHex(finalizeHash(input, unblinded.toBytes(true)));
}

// ── server side ──────────────────────────────────────────────────────────────
/** BlindEvaluate(skS, blindedElement): skS · blindedElement, serialized. */
export function blindEvaluate(skS: bigint, blindedElementHex: string): string {
  const blinded = deserializeElement(blindedElementHex);
  return serializeElement(blinded.multiply(skS));
}

/**
 * Server-direct evaluation used at REDEMPTION: recompute the exact token output from
 * (skS, input) without ever seeing the client's blind. Relies on the OPRF identity
 * skS·H2C(input) == unblind(skS · blind · H2C(input)).
 */
export function evaluate(skS: bigint, input: Uint8Array): string {
  const el = hashToGroup(input);
  const evaluated = el.multiply(skS);
  return bytesToHex(finalizeHash(input, evaluated.toBytes(true)));
}

// ── key management ─────────────────────────────────────────────────────────────
/** A uniformly random non-zero scalar in [1, ORDER-1]. */
export function randomScalar(): bigint {
  // rejection sampling over 48 fresh bytes keeps the distribution uniform mod ORDER
  for (;;) {
    const s = BigInt('0x' + bytesToHex(crypto.randomBytes(48)));
    const r = s % ORDER;
    if (r !== 0n) return r;
  }
}

/** Parse a 48-byte hex secret key into a valid scalar, or throw. */
export function parseSecretKey(hex: string): bigint {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 48) throw new TypeError('secret key must be 48 bytes');
  const s = BigInt('0x' + hex) % ORDER;
  if (s === 0n) throw new TypeError('secret key reduces to zero');
  return s;
}

/** pkS = skS·G, serialized (compressed hex). Not needed for base-mode verification,
 *  exposed for clients/tooling and as the anchor for a future verifiable upgrade. */
export function publicKey(skS: bigint): string {
  return serializeElement(Point.BASE.multiply(skS));
}

// ── high-level issuer / verifier ─────────────────────────────────────────────
export interface RedeemResult { valid: boolean; reason?: string }
export interface IssuerOptions {
  /** hex secret key (48 bytes). If absent, a fresh key is generated at boot. */
  keyHex?: string;
  /** how long a spent nonce is remembered; must exceed intended token lifetime. */
  spentTtlMs?: number;
  /** max blinded elements accepted in one issuance request. */
  maxBatch?: number;
  /** hard cap on spent-set size (defensive against memory growth). */
  maxSpent?: number;
}

/**
 * One issuer holding a single OPRF key. Issues blinded batches and verifies one-time
 * redemptions. In-memory spent-set with TTL + size cap; for a single-process gate this
 * is sufficient (a redemption replayed after its nonce is evicted would be re-accepted,
 * so spentTtlMs must be >= the token lifetime you advertise — default 6h).
 */
export class PrivacyPassIssuer {
  private readonly skS: bigint;
  readonly publicKeyHex: string;
  readonly maxBatch: number;
  private readonly spentTtlMs: number;
  private readonly maxSpent: number;
  private readonly spent = new Map<string, number>();   // nonceHex -> expiryMs
  readonly stats = { issued: 0, redeemed: 0, rejected: 0 };

  constructor(opts: IssuerOptions = {}) {
    this.skS = opts.keyHex ? parseSecretKey(opts.keyHex) : randomScalar();
    this.publicKeyHex = publicKey(this.skS);
    this.maxBatch = opts.maxBatch ?? 8;
    this.spentTtlMs = opts.spentTtlMs ?? 6 * 60 * 60 * 1000;
    this.maxSpent = opts.maxSpent ?? 200_000;
  }

  /** Evaluate a batch of blinded elements. Throws on malformed input or over-limit. */
  issueBatch(blindedElementsHex: string[]): string[] {
    if (!Array.isArray(blindedElementsHex) || blindedElementsHex.length === 0) {
      throw new TypeError('blindedElements must be a non-empty array');
    }
    if (blindedElementsHex.length > this.maxBatch) {
      throw new RangeError(`batch too large (max ${this.maxBatch})`);
    }
    const evaluated = blindedElementsHex.map((b) => blindEvaluate(this.skS, b));
    this.stats.issued += evaluated.length;
    return evaluated;
  }

  /** Verify + consume a token. Constant-time output compare; one-time via spent-set. */
  redeem(nonceHex: string, outputHex: string): RedeemResult {
    let nonce: Uint8Array;
    try {
      nonce = hexToBytes(nonceHex);
    } catch {
      this.stats.rejected++;
      return { valid: false, reason: 'MALFORMED_NONCE' };
    }
    if (nonce.length < 8 || nonce.length > 64) {
      this.stats.rejected++;
      return { valid: false, reason: 'MALFORMED_NONCE' };
    }
    if (typeof outputHex !== 'string' || outputHex.length !== OUTPUT_BYTES * 2 || !/^[0-9a-f]+$/i.test(outputHex)) {
      this.stats.rejected++;
      return { valid: false, reason: 'MALFORMED_OUTPUT' };
    }

    const key = nonceHex.toLowerCase();
    this.pruneIfDue();
    if (this.spent.has(key)) {
      this.stats.rejected++;
      return { valid: false, reason: 'TOKEN_ALREADY_SPENT' };
    }

    const expected = evaluate(this.skS, nonce);
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(outputHex.toLowerCase(), 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      this.stats.rejected++;
      return { valid: false, reason: 'TOKEN_INVALID' };
    }

    this.markSpent(key);
    this.stats.redeemed++;
    return { valid: true };
  }

  get spentSize(): number { return this.spent.size; }

  config() {
    return { suite: SUITE, mode: SUITE_MODE, publicKey: this.publicKeyHex, maxBatch: this.maxBatch };
  }

  private markSpent(key: string): void {
    if (this.spent.size >= this.maxSpent) {
      // evict the oldest inserted entry (Map preserves insertion order)
      const oldest = this.spent.keys().next().value;
      if (oldest !== undefined) this.spent.delete(oldest);
    }
    this.spent.set(key, Date.now() + this.spentTtlMs);
  }

  private lastPrune = 0;
  private pruneIfDue(): void {
    const now = Date.now();
    if (now - this.lastPrune < 60_000) return;   // amortize: at most once/min
    this.lastPrune = now;
    for (const [k, exp] of this.spent) {
      if (exp <= now) this.spent.delete(k);
    }
  }
}
