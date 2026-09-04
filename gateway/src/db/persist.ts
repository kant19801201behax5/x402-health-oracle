import fs from 'node:fs';
import path from 'node:path';

const DATA_DIR = path.join(process.cwd(), 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const BANS_FILE = path.join(DATA_DIR, 'bans.json');
const PROFILES_FILE = path.join(DATA_DIR, 'profiles.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.jsonl');

// ── Types ──────────────────────────────────────────────────────────────────────

type BanRecord = { reason: string; ts: number; expires: number };
type ProfileRecord = {
  m_cost: number; t_cost: number; successes: number;
  trust_score: number; last_seen: number;
};

// ── Bans ───────────────────────────────────────────────────────────────────────

let _bans: Record<string, BanRecord> = {};

// Bug found 2026-08-10 while live-testing the new trust-assessment ban path:
// bans.json on the production server held a stale "[]" (empty array, not "{}"),
// so JSON.parse gave _bans an actual Array. `_bans[ip] = {...}` still "worked"
// (arrays are objects; you can set arbitrary string keys), but JSON.stringify()
// on an array only serializes numeric indices — every persistBan() call since
// whenever that file got into this state was silently dropped on save. This
// wasn't specific to the new code; every ban source in server.ts goes through
// persistBan(), so no ban has actually survived a restart for as long as the
// file was in this shape. Guard against it regardless of how it got there.
try {
  const parsed = JSON.parse(fs.readFileSync(BANS_FILE, 'utf8'));
  _bans = (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : {};
} catch { /* fresh start */ }

// Expire stale bans on load
const _now = Date.now();
for (const ip of Object.keys(_bans)) {
  if (_bans[ip].expires < _now) delete _bans[ip];
}

function _saveBans() {
  fs.writeFileSync(BANS_FILE, JSON.stringify(_bans), 'utf8');
}
_saveBans();

// server.ts's /api/admin/reset-bans previously wrote a raw '[]' straight to
// BANS_FILE itself, bypassing this module's own _bans object entirely — that
// left stale entries sitting in memory here, ready to get written back into
// the file (re-corrupting it to the same array-vs-object shape this file's
// load guard now defends against) the next time any ban fired after a
// "clear". Found the same day as that load-guard fix, same root cause: two
// places owning the same on-disk state instead of one.
export function clearBans(): void {
  _bans = {};
  _saveBans();
}

export function persistBan(ip: string, reason: string, ttlMs: number): void {
  const now = Date.now();
  _bans[ip] = { reason, ts: now, expires: now + ttlMs };
  _saveBans();
}

export function loadActiveBans(): Array<{ ip: string; reason: string; ts: number }> {
  const now = Date.now();
  return Object.entries(_bans)
    .filter(([, v]) => v.expires > now)
    .map(([ip, v]) => ({ ip, reason: v.reason, ts: v.ts }));
}

// ── Profiles ───────────────────────────────────────────────────────────────────

let _profiles: Record<string, ProfileRecord> = {};

try { _profiles = JSON.parse(fs.readFileSync(PROFILES_FILE, 'utf8')); } catch { /* fresh start */ }

function _saveProfiles() {
  fs.writeFileSync(PROFILES_FILE, JSON.stringify(_profiles), 'utf8');
}

export function persistProfile(ip: string, data: Partial<ProfileRecord>): void {
  const defaults: ProfileRecord = { m_cost: 16384, t_cost: 3, successes: 0, trust_score: 1.0, last_seen: Date.now() };
  _profiles[ip] = { ...defaults, ..._profiles[ip], ...data, last_seen: Date.now() };
  _saveProfiles();
}

export function loadProfile(ip: string): ProfileRecord | undefined {
  return _profiles[ip];
}

// ── Events (append-only log) ───────────────────────────────────────────────────

export function logEvent(ip: string, type: string, extra: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ ip, type, ...extra, ts: Date.now() }) + '\n';
  fs.appendFileSync(EVENTS_FILE, line, 'utf8');
}
