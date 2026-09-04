/**
 * On-chain Wallet Identity Binding
 * Binds Ethereum wallet addresses to Silicon DNA behavioral fingerprints.
 * Verifies EIP-191 personal_sign signature structure.
 * Stores HMAC commitments only — raw data never persisted.
 */
import * as crypto from 'crypto';

export interface WalletBinding {
  wallet: string;
  behavioralHash: string;
  boundAt: number;
  ipHash: string;
}

const byWallet = new Map<string, WalletBinding>();
const byBehavioralHash = new Map<string, string[]>(); // hash → wallets

// 3+ wallets sharing one behavioral fingerprint = Sybil signal
const SYBIL_THRESHOLD = 3;

export function computeBehavioralHash(
  secret: Buffer,
  entropy: number,
  variance: number,
  spearmanRho: number
): string {
  const payload = `${entropy.toFixed(3)}:${variance.toFixed(4)}:${spearmanRho.toFixed(3)}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

export function validateSignatureStructure(signature: string): boolean {
  const hex = signature.startsWith('0x') ? signature.slice(2) : signature;
  return /^[0-9a-fA-F]{130}$/.test(hex); // 65 bytes = r(32) + s(32) + v(1)
}

export function bindWallet(
  wallet: string,
  behavioralHash: string,
  ipRaw: string
): { ok: boolean; sybilDetected: boolean; sharedWallets: number } {
  const addr = wallet.toLowerCase();
  const ipHash = crypto.createHash('sha256').update(ipRaw).digest('hex').slice(0, 16);

  byWallet.set(addr, { wallet: addr, behavioralHash, boundAt: Date.now(), ipHash });

  const list = byBehavioralHash.get(behavioralHash) ?? [];
  if (!list.includes(addr)) list.push(addr);
  byBehavioralHash.set(behavioralHash, list);

  return {
    ok: true,
    sybilDetected: list.length >= SYBIL_THRESHOLD,
    sharedWallets: list.length,
  };
}

export function lookupWallet(wallet: string): WalletBinding | null {
  return byWallet.get(wallet.toLowerCase()) ?? null;
}

export function getWalletsByHash(behavioralHash: string): string[] {
  return byBehavioralHash.get(behavioralHash) ?? [];
}

export function getBindingStats(): {
  totalBound: number;
  sybilGroups: number;
  largestGroup: number;
} {
  let sybilGroups = 0;
  let largestGroup = 0;
  for (const wallets of byBehavioralHash.values()) {
    if (wallets.length >= SYBIL_THRESHOLD) sybilGroups++;
    if (wallets.length > largestGroup) largestGroup = wallets.length;
  }
  return { totalBound: byWallet.size, sybilGroups, largestGroup };
}

export function clearBindings(): void {
  byWallet.clear();
  byBehavioralHash.clear();
}
