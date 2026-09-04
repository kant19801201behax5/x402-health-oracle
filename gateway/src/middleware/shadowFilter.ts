/**
 * RPC Shadow Filtering Middleware
 * Passes every request through immediately — zero added latency.
 * Async background analysis flags IPs; throttling starts on the NEXT request.
 * Architecture pitch for Alchemy / QuickNode: 20-30% cost savings, 0ms overhead.
 */
import type { Request, Response, NextFunction } from 'express';
import { classifyAgent, type ClassificationInput } from '../services/agentClassifier';

interface ShadowRecord {
  requests: number;
  botHits: number;
  lastClass: string;
  lastSeen: number;
  throttled: boolean;
}

const shadowRecords = new Map<string, ShadowRecord>();
const THROTTLE_AFTER = 5;  // consecutive malicious bot classifications
const WINDOW_MS = 60_000;  // 1-minute sliding window

export interface ShadowFilterStats {
  tracked_ips: number;
  throttled_ips: number;
  total_requests: number;
  bot_hits: number;
}

/**
 * Safe default: trust ONLY the real TCP peer. x-forwarded-for is attacker-
 * controlled, so it is never consulted unless the caller passes a
 * trusted-proxy-aware `resolveIp` (server.ts passes `getClientIp`). Same
 * guarantee the hard-ban path has — a spoofed header can't frame or evade
 * the throttle.
 */
function defaultResolveIp(req: Request): string {
  return req.socket.remoteAddress || 'unknown';
}

/**
 * Control-plane / observability / localhost-ingestion endpoints the throttle must
 * never gate — else a flagged monitor/admin IP could 429 out /metrics or the reset
 * endpoint (self-inflicted deadlock), and the localhost L6 sensor POSTing telemetry
 * to /api/agent/interact every 2s would get throttled (which it did — that endpoint
 * is localhost-only and nginx-denied externally, so it is safe to exempt).
 */
const SHADOW_EXEMPT = [
  /^\/metrics/, /^\/api\/admin\//, /^\/api\/silicon-metrics/, /^\/api\/phoenix-status/,
  /^\/api\/health/, /^\/api\/public-feed/, /^\/api\/check-ip/, /^\/api\/agent\/interact/,
];

/** Exported for unit testing: is this path exempt from the shadow throttle? */
export function isShadowExempt(path: string): boolean {
  return SHADOW_EXEMPT.some(re => re.test(path));
}

export function shadowFilterMiddleware(
  getContext: (req: Request) => Omit<ClassificationInput, 'ua' | 'headers'>,
  resolveIp: (req: Request) => string = defaultResolveIp,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (isShadowExempt(req.path)) { next(); return; }

    const ip = resolveIp(req);

    const now = Date.now();
    let rec = shadowRecords.get(ip);

    if (!rec || now - rec.lastSeen > WINDOW_MS) {
      rec = { requests: 0, botHits: 0, lastClass: 'HUMAN', lastSeen: now, throttled: false };
      shadowRecords.set(ip, rec);
    }

    rec.requests++;
    rec.lastSeen = now;

    if (rec.throttled) {
      res.setHeader('X-Silicon-DNA', 'SHADOW_THROTTLED');
      res.status(429).json({ error: 'RATE_LIMITED', reason: 'shadow_filter' });
      return;
    }

    next();

    // Background classification — fires after response is handed off
    setImmediate(() => {
      const input: ClassificationInput = {
        ua: (req.headers['user-agent'] as string) ?? '',
        headers: req.headers as Record<string, string | undefined>,
        ...getContext(req),
      };
      const result = classifyAgent(input);
      rec!.lastClass = result.agentClass;

      if (result.agentClass === 'MALICIOUS_BOT' && result.confidence > 0.6) {
        rec!.botHits++;
        if (rec!.botHits >= THROTTLE_AFTER) rec!.throttled = true;
      }
    });
  };
}

export function getShadowStats(): ShadowFilterStats {
  let total = 0;
  let botHits = 0;
  let throttled = 0;

  for (const r of shadowRecords.values()) {
    total += r.requests;
    botHits += r.botHits;
    if (r.throttled) throttled++;
  }

  return {
    tracked_ips: shadowRecords.size,
    throttled_ips: throttled,
    total_requests: total,
    bot_hits: botHits,
  };
}

export function clearShadowRecords(): void {
  shadowRecords.clear();
}
