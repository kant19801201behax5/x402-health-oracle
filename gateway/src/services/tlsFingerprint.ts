// src/services/tlsFingerprint.ts
// L2 TLS fingerprint — real JA4 (FoxIO spec), replacing the old hardcoded ja3:0.5.
//
// Two honest modes:
//  1. A JA4-capable TLS front (Cloudflare Enterprise Bot Management, or the
//     bundled ja4-front TLS-peek proxy) terminates TLS, computes JA4 from the raw
//     ClientHello, and passes it in `x-tls-ja4`. resolveTlsFp() trusts that header
//     ONLY when the request came from a trusted proxy IP.
//  2. No such front → we report `ja4: null` and a NEUTRAL risk, never a fabricated
//     constant. (Behind vanilla Cloudflare the raw ClientHello isn't visible, and
//     JA3 is obsolete since Chrome 110 randomised extension order — so a fixed
//     number there was meaningless.)
//
// computeJA4()/parseClientHello() are pure and let any front (or a test) turn raw
// ClientHello bytes into a JA4 string.

import crypto from 'crypto';

// GREASE values (RFC 8701) — must be excluded from JA4 before counting/hashing.
const GREASE = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);
const isGrease = (v: number) => GREASE.has(v);

export interface ClientHelloInfo {
  tlsVersion: number;       // negotiated: highest from supported_versions, else legacy_version
  sni: boolean;             // server_name (0x0000) present
  ciphers: number[];        // wire order, GREASE included (stripped in computeJA4)
  extensions: number[];     // wire order, GREASE included (stripped in computeJA4)
  alpn: string[];           // ALPN protocol list
  sigAlgs: number[];        // signature_algorithms (0x000d), wire order, GREASE included
}

const sha12 = (s: string) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);
const hex4 = (n: number) => n.toString(16).padStart(4, '0');
const tlsVerLabel = (v: number): string =>
  v === 0x0304 ? '13' : v === 0x0303 ? '12' : v === 0x0302 ? '11' : v === 0x0301 ? '10' : '00';

function alpnCode(alpn: string[]): string {
  if (!alpn.length) return '00';
  const a = alpn[0];
  if (a.length === 0) return '00';
  if (a.length === 1) return a + a;
  return a[0] + a[a.length - 1];
}

/**
 * Compute the FoxIO JA4 fingerprint from a parsed ClientHello.
 * JA4 = JA4_a _ JA4_b _ JA4_c
 *   JA4_a: <t|q><ver><d|i><cipherCount 2d><extCount 2d><alpn 2ch>
 *   JA4_b: sha256(sorted ciphers, comma-joined 4-hex)[:12]
 *   JA4_c: sha256(sorted exts (minus SNI 0x0000 & ALPN 0x0010) , "_" sorted sigAlgs)[:12]
 */
export function computeJA4(info: ClientHelloInfo, transport: 't' | 'q' = 't'): string {
  const ciphers = info.ciphers.filter(c => !isGrease(c));
  const extsAll = info.extensions.filter(e => !isGrease(e));
  const cc = String(Math.min(ciphers.length, 99)).padStart(2, '0');
  const ec = String(Math.min(extsAll.length, 99)).padStart(2, '0');
  const ja4a = `${transport}${tlsVerLabel(info.tlsVersion)}${info.sni ? 'd' : 'i'}${cc}${ec}${alpnCode(info.alpn)}`;

  const sortedCiphers = [...ciphers].sort((a, b) => a - b).map(hex4).join(',');
  const ja4b = sha12(sortedCiphers);

  // JA4_c: extensions minus SNI(0x0000) and ALPN(0x0010), sorted; then sig algs in wire order.
  const extsForHash = extsAll.filter(e => e !== 0x0000 && e !== 0x0010).sort((a, b) => a - b).map(hex4).join(',');
  const sigAlgs = info.sigAlgs.filter(s => !isGrease(s)).map(hex4).join(',');
  const ja4c = sha12(`${extsForHash}_${sigAlgs}`);

  return `${ja4a}_${ja4b}_${ja4c}`;
}

/**
 * Parse a raw TLS ClientHello (starting at the TLS record header, 0x16 0x03 ...,
 * OR at the handshake header 0x01 ...) into the fields JA4 needs. Returns null on
 * anything malformed — never throws. Bounds-checked throughout.
 */
export function parseClientHello(buf: Buffer): ClientHelloInfo | null {
  try {
    let p = 0;
    // Optional TLS record layer: 0x16 (handshake) 0x03 0xNN len(2)
    if (buf[0] === 0x16) {
      if (buf.length < 5) return null;
      p = 5;
    }
    // Handshake header: 0x01 (ClientHello) len(3)
    if (buf[p] !== 0x01) return null;
    p += 4; // type(1) + length(3)
    if (p + 2 > buf.length) return null;
    const legacyVersion = buf.readUInt16BE(p); p += 2;
    p += 32; // random
    if (p >= buf.length) return null;
    const sidLen = buf[p]; p += 1 + sidLen; // session id
    if (p + 2 > buf.length) return null;
    const csLen = buf.readUInt16BE(p); p += 2;
    const ciphers: number[] = [];
    for (let i = 0; i + 1 < csLen && p + 1 < buf.length; i += 2) {
      ciphers.push(buf.readUInt16BE(p)); p += 2;
    }
    if (p >= buf.length) return null;
    const compLen = buf[p]; p += 1 + compLen; // compression methods
    let tlsVersion = legacyVersion;
    let sni = false;
    const extensions: number[] = [];
    const alpn: string[] = [];
    const sigAlgs: number[] = [];
    if (p + 2 <= buf.length) {
      const extTotal = buf.readUInt16BE(p); p += 2;
      const extEnd = Math.min(p + extTotal, buf.length);
      while (p + 4 <= extEnd) {
        const type = buf.readUInt16BE(p); p += 2;
        const len = buf.readUInt16BE(p); p += 2;
        const body = p; const bodyEnd = Math.min(p + len, extEnd);
        extensions.push(type);
        if (type === 0x0000) sni = true;
        else if (type === 0x002b) {
          // supported_versions: list(1-byte len) of 2-byte versions; pick highest non-GREASE
          if (body < bodyEnd) {
            const listLen = buf[body];
            let best = 0;
            for (let i = 0; i + 1 < listLen && body + 1 + i + 1 < bodyEnd + 1; i += 2) {
              const v = buf.readUInt16BE(body + 1 + i);
              if (!isGrease(v) && v > best && v <= 0x0304) best = v;
            }
            if (best) tlsVersion = best;
          }
        } else if (type === 0x0010) {
          // ALPN: 2-byte list len, then [1-byte proto len][proto]...
          let q = body + 2;
          while (q < bodyEnd) {
            const l = buf[q]; q += 1;
            if (q + l > bodyEnd) break;
            alpn.push(buf.toString('ascii', q, q + l)); q += l;
          }
        } else if (type === 0x000d) {
          // signature_algorithms: 2-byte list len, then 2-byte entries
          let q = body + 2;
          while (q + 1 < bodyEnd) { sigAlgs.push(buf.readUInt16BE(q)); q += 2; }
        }
        p = bodyEnd;
      }
    }
    return { tlsVersion, sni, ciphers, extensions, alpn, sigAlgs };
  } catch {
    return null;
  }
}

export interface TlsFp { ja4: string | null; source: 'front-header' | 'none'; }

/**
 * Resolve the client's TLS fingerprint from request headers. Only trusts the
 * `x-tls-ja4` header when the request arrived from a trusted proxy (the TLS-
 * terminating front); otherwise returns null. Never fabricates a value.
 */
export function resolveTlsFp(
  headers: Record<string, unknown>,
  fromTrustedProxy: boolean,
): TlsFp {
  if (fromTrustedProxy) {
    const h = headers['x-tls-ja4'];
    const ja4 = typeof h === 'string' ? h.trim() : Array.isArray(h) ? String(h[0]).trim() : '';
    // Full JA4 shape: <t|q><2-digit ver><d|i><2-digit cc><2-digit ec><2-char alpn>_<12 hex>_<12 hex>
    if (ja4 && /^[tq]\d{2}[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/.test(ja4)) {
      return { ja4, source: 'front-header' };
    }
  }
  return { ja4: null, source: 'none' };
}

// Known automation/bot TLS stacks by JA4_a prefix or full JA4 (extend as observed).
// Deliberately small + interpretable, not an ML model.
const KNOWN_BOT_JA4_A = new Set<string>([
  't13i00', // TLS1.3, no SNI, zero ciphers — not a real browser
]);

/**
 * TLS risk signal in [0,1]. null fingerprint → 0.5 (neutral/unknown, honest),
 * NOT a low "looks fine" value. Known-bot stacks or UA/JA4 class mismatch → high.
 */
export function tlsRisk(fp: TlsFp, ua: string): number {
  if (!fp.ja4) return 0.5;
  const ja4a = fp.ja4.split('_')[0] ?? '';
  if (KNOWN_BOT_JA4_A.has(ja4a.slice(0, 6))) return 0.9;
  // A "browser" UA with no SNI ('i') is inconsistent — real browsers send SNI.
  const claimsBrowser = /mozilla/i.test(ua);
  if (claimsBrowser && ja4a[3] === 'i') return 0.8;
  return 0.1;
}
