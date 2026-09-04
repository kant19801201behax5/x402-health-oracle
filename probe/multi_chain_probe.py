# Multi-chain RTT prober - HTTP eth_blockNumber every 2s per chain.
# Phase 63c: adaptive stall threshold (max(2xP95_1m, 500ms)) + slow-creep flag=2.
#            L1 Blob Base Fee thread (every 15s) + Gas Pressure metric.
# Phase 63d: L2 Revert Ratio (eth_getBlockReceipts) for Arbitrum + Base.
# v2.4 (2026-06-13):
#   (1) Revert De-Noiser: multi-block sampling, EMA, confidence, None vs 0.0 fix.
#   (2) Predictive Stall Forecaster: blob_vel + gas_vel + ZK_P99 -> stall_probability.
#   (3) Cross-Chain Causality: ZK_BASE_TRACKER.update() now called (was dead code).
#   (4) blob_velocity tracked alongside gas_velocity.
import threading, time, json, urllib.request, ssl, collections, os, ctypes
import requests, concurrent.futures

# [2026-07-21 — chain attribution] Each worker thread self-registers its own
# kernel TID -> label ONCE (first call), so the eBPF kernel-RTT sensor can
# attribute PHOENIX_KERNEL_RTT events to a specific chain/signal source
# without ever reading payload content. File is a simple append-only text
# registration list; the eBPF loader re-reads it periodically.
#
# os.gettid() (added in CPython 3.9) is unavailable on this box's Python
# 3.10.12 build (confirmed empirically) — fall back to the raw gettid(2)
# syscall via ctypes. Must be the REAL kernel TID (not threading.get_ident(),
# which is a Python-level id that does NOT match what bpf_get_current_pid_tgid()
# sees in the kernel) — otherwise the eBPF side's lookup never matches.
_SYS_GETTID = 186  # x86_64 Linux
_libc = ctypes.CDLL("libc.so.6", use_errno=True)

def _real_tid() -> int:
    try:
        return os.gettid()
    except AttributeError:
        return _libc.syscall(_SYS_GETTID)

_TID_LABELS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "tid_labels.txt")
_tid_label_lock = threading.Lock()
_registered_tids = set()

_tid_labels_pruned = False

def _prune_stale_tid_labels() -> None:
    """Drop registrations whose TID no longer belongs to THIS process.

    FIX 2026-07-25: this file was opened "a" and never truncated, so each restart appended a fresh set
    of TIDs while the dead ones stayed behind. Measured on the live server: 108 lines, of which 90 were
    stale and only 18 belonged to the running process. The kernel-side map took the entries in file
    order — i.e. the oldest, dead ones first — hit its ceiling, and rejected all 18 live TIDs, so
    `chain` came back empty in 333/333 broadcast events. This prune is the userspace half of the fix;
    raising the map ceiling in phoenix_rtt.bpf.c (64 -> 1024) is the kernel half. Runs once, before the
    first registration. /proc/self/task is the authority: TIDs are reused system-wide, so "does this
    TID still exist" is not enough — it must still be OURS.
    """
    global _tid_labels_pruned
    if _tid_labels_pruned:
        return
    _tid_labels_pruned = True
    try:
        if not os.path.exists(_TID_LABELS_PATH):
            return
        live = set(os.listdir("/proc/self/task"))
        kept = []
        with open(_TID_LABELS_PATH) as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2 and parts[0] in live:
                    kept.append(line if line.endswith("\n") else line + "\n")
        with open(_TID_LABELS_PATH, "w") as f:
            f.writelines(kept)
        print(f"[PROBE] tid_labels pruned -> {len(kept)} live entries")
    except Exception as e:
        print("[PROBE] tid_labels prune skipped:", e)

def _register_thread_label(label: str) -> None:
    tid = _real_tid()
    if tid in _registered_tids:
        return
    with _tid_label_lock:
        if tid in _registered_tids:
            return
        try:
            os.makedirs(os.path.dirname(_TID_LABELS_PATH), exist_ok=True)
            _prune_stale_tid_labels()
            with open(_TID_LABELS_PATH, "a") as f:
                f.write(f"{tid} {label}\n")
            _registered_tids.add(tid)
        except Exception:
            pass  # best-effort — missing attribution is not fatal

CHAINS = {
    'base':      'https://mainnet.base.org',
    'arbitrum':  'https://arb1.arbitrum.io/rpc',
    'optimism':  'https://mainnet.optimism.io',
    'zksync':    'https://mainnet.era.zksync.io',
    'mantle':    'https://rpc.mantle.xyz',
    'casper':    'https://node.mainnet.casper.network/rpc',
    'scroll':    'https://rpc.scroll.io',
    'blast':     'https://rpc.blast.io',
    'linea':     'https://rpc.linea.build',
    'mode':      'https://mainnet.mode.network',
    'polygon_zkevm': 'https://zkevm-rpc.com',
    'taiko':     'https://rpc.mainnet.taiko.xyz',
}

CHAIN_FALLBACK_RPCS = {
    'base':      ['https://base-rpc.publicnode.com', 'https://rpc.ankr.com/base'],
    'arbitrum':  ['https://rpc.ankr.com/arbitrum',   'https://arbitrum-one-rpc.publicnode.com'],
    'optimism':  ['https://optimism-rpc.publicnode.com', 'https://1rpc.io/op'],
    'zksync':    ['https://zksync-era.blockpi.network/v1/rpc/public'],
    'mantle':    ['https://mantle-rpc.publicnode.com'],
    'casper':    [],
    'scroll':    ['https://scroll-mainnet.public.blastapi.io', 'https://rpc.ankr.com/scroll'],
    'blast':     ['https://blast-rpc.publicnode.com'],
    'linea':     ['https://linea-rpc.publicnode.com', 'https://1rpc.io/linea'],
    'mode':      ['https://1rpc.io/mode'],
    'polygon_zkevm': [],
    'taiko':     ['https://taiko-rpc.publicnode.com'],
}

CHAIN_RPC_BODIES = {
    'casper': json.dumps({'jsonrpc':'2.0','method':'info_get_status','params':{},'id':1}).encode(),
}
PROBE_SEC        = 2.0
HTTP_TIMEOUT     = 5
WINDOW           = 60
WINDOW_1M        = 30
WINDOW_5M        = 150
STALL_MIN_MS     = 500
CREEP_RATIO      = 1.5
CREEP_MIN_MS     = 200
CHAIN_CONFIG = {
    'mantle': {
        'stall_min_ms': 800,
        'creep_ratio':  2.0,
        'creep_min_ms': 350,
    }
}
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'

ETH_RPC_URLS    = [
    'https://ethereum-rpc.publicnode.com',
    'https://rpc.ankr.com/eth',
]
BLOB_INTERVAL_S = 15

# L2 Revert Ratio: list of URLs per chain, tried in order
L2_REVERT_RPCS = {
    'arbitrum': ['https://arb1.arbitrum.io/rpc', 'https://arbitrum-one-rpc.publicnode.com', 'https://rpc.ankr.com/arbitrum'],
    'base':     ['https://base-rpc.publicnode.com', 'https://mainnet.base.org', 'https://rpc.ankr.com/base'],
}
REVERT_INTERVAL_S = 20
REVERT_N_BLOCKS   = 3
REVERT_N_BLOCKS_BY_CHAIN = {'arbitrum': 8, 'base': 3}   # arb few txs/block -> more blocks for stable n
REVERT_EMA_ALPHA  = 0.4
GAS_EMA_ALPHA     = 0.4   # smooth single-block gas noise

ctx = ssl.create_default_context()
_RPC_BODY = json.dumps({'jsonrpc':'2.0','method':'eth_blockNumber','params':[],'id':1}).encode()
_RPC_HDR  = {'Content-Type': 'application/json', 'User-Agent': UA}

PENALTY_MS = HTTP_TIMEOUT * 1000   # synthetic value on full RPC failure -- excluded from percentiles

def _pct(sorted_vals, q):
    """Linear-interpolation percentile on a pre-sorted list."""
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    if n == 1:
        return sorted_vals[0]
    idx = q * (n - 1)
    lo  = int(idx)
    hi  = min(lo + 1, n - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)


_LATEST = {'base_revert': None, 'blob_fee': None}

def _volatility_score(base_revert, blob_fee):
    # Magnitude-of-move forecast [0..1] from base_revert + blob_fee
    # (-> |ETH move| 5-15min; R2~0.045, 1.67x quartile, 14d/21k samples).
    # Bounds from 14d history; first-pass blend, NOT yet calibrated.
    if base_revert is None or blob_fee is None:
        return None
    r = max(0.0, min(1.0, (base_revert - 0.05) / 0.20))
    b = max(0.0, min(1.0, blob_fee / 0.10))
    return round(0.5 * r + 0.5 * b, 4)


# -- Per-chain RTT prober -----------------------------------------------------
class ChainProbe:
    def __init__(self, name, url, broadcast_fn):
        self.name     = name
        self.urls     = [url] + CHAIN_FALLBACK_RPCS.get(name, [])
        self.bcast    = broadcast_fn
        self._urls3    = self.urls[:3]
        self._sessions = [requests.Session() for _ in self._urls3]
        self._pool     = concurrent.futures.ThreadPoolExecutor(max_workers=max(len(self._urls3), 1), thread_name_prefix='rtt-' + name)
        self.rtts     = collections.deque(maxlen=WINDOW)
        self.rtts_1m  = collections.deque(maxlen=WINDOW_1M)
        self.rtts_5m  = collections.deque(maxlen=WINDOW_5M)
        cfg = CHAIN_CONFIG.get(name, {})
        self._stall_min_ms = cfg.get('stall_min_ms', STALL_MIN_MS)
        self._creep_ratio  = cfg.get('creep_ratio',  CREEP_RATIO)
        self._creep_min_ms = cfg.get('creep_min_ms', CREEP_MIN_MS)
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True, name='probe-'+name).start()
        print('[PROBE-' + name.upper() + '] started (' + str(int(PROBE_SEC*1000)) + 'ms)')

    def _measure(self, i):
        _register_thread_label(self.name)  # kernel chain-attribution (once per pool worker thread)
        # FIX 2026-07-25: time.time() is wall-clock — an NTP correction (slew or step) lands straight
        # in the measured RTT and surfaces downstream as a latency spike that never happened. Interval
        # timing needs a monotonic source: perf_counter() cannot move backwards and ignores clock sync.
        t0 = time.perf_counter()
        try:
            body = CHAIN_RPC_BODIES.get(self.name, _RPC_BODY)
            resp = self._sessions[i].post(self._urls3[i], data=body, headers=_RPC_HDR, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            resp.close()
            return (time.perf_counter() - t0) * 1000
        except Exception:
            return None

    def _probe_all(self):
        # Poll endpoints in parallel -> consensus. min = true latency, spread = provider divergence.
        futs = [self._pool.submit(self._measure, i) for i in range(len(self._urls3))]
        out = []
        for f in futs:
            try:
                r = f.result(timeout=HTTP_TIMEOUT + 2)
                if r is not None:
                    out.append(r)
            except Exception:
                pass
        return out

    def _loop(self):
        while not self._stop.is_set():
            t0      = time.perf_counter()  # 2026-07-25: same wall-clock issue as _measure — this one
                                           # skews the poll period (double-poll or long sleep on an NTP step)
            samples = self._probe_all()
            if samples:
                rtt_ms     = min(samples)
                rtt_spread = round(max(samples) - min(samples), 2) if len(samples) >= 2 else 0.0
            else:
                rtt_ms     = HTTP_TIMEOUT * 1000
                rtt_spread = 0.0

            self.rtts.append(rtt_ms)
            self.rtts_1m.append(rtt_ms)
            self.rtts_5m.append(rtt_ms)

            if len(self.rtts) >= 5:
                # Percentiles from REAL latencies only (exclude synthetic timeout penalty);
                # interpolation so p95 != p99 even on small windows.
                s = sorted(x for x in self.rtts if x < PENALTY_MS) or sorted(self.rtts)
                p95 = _pct(s, 0.95)
                p99 = _pct(s, 0.99)

                s1 = sorted(x for x in self.rtts_1m if x < PENALTY_MS) or sorted(self.rtts_1m)
                p95_1m = _pct(s1, 0.95)

                adaptive_thresh = max(2 * p95_1m, self._stall_min_ms)

                slow_creep = 0
                if len(self.rtts_5m) >= 30:
                    s5 = sorted(x for x in self.rtts_5m if x < PENALTY_MS) or sorted(self.rtts_5m)
                    p95_5m = _pct(s5, 0.95)
                    if p95_1m > self._creep_ratio * p95_5m and p95_5m > self._creep_min_ms:
                        slow_creep = 1

                if rtt_ms > adaptive_thresh:
                    stall = 1
                elif slow_creep:
                    stall = 2
                else:
                    stall = 0

                # Cross-chain causality: feed ZK tracker (fixes dead code bug)
                if self.name == 'zksync':
                    ZK_BASE_TRACKER.update(p99)

                self.bcast({
                    'type':         'PHOENIX_METRIC',
                    'chain':        self.name,
                    'rtt_ns':        int(rtt_ms * 1e6),
                    'rtt_min_ms':    round(rtt_ms, 2),
                    'rtt_spread_ms': rtt_spread,
                    'p99_ms':       p99,
                    'p95_ms':       p95,
                    'p95_1m_ms':    round(p95_1m, 2),
                    'stall_flag':   stall,
                    'mev_forecast': 1.0 if ZK_BASE_TRACKER.mev_forecast else 0.0,
                })

                if CROSS_CHAIN_MATRIX is not None:
                    CROSS_CHAIN_MATRIX.feed(self.name, rtt_ms)

            elapsed = time.perf_counter() - t0  # 2026-07-25: monotonic, pairs with t0 above
            time.sleep(max(0, PROBE_SEC - elapsed))


# -- L1 Ethereum signal thread: blob base fee + gas pressure ------------------
class EthSignalThread:
    """Publishes PHOENIX_ETH_SIGNAL every BLOB_INTERVAL_S seconds.
    v2.4: adds blob_velocity, stall_probability (predictive stall forecaster).
    """
    def __init__(self, broadcast_fn):
        self.bcast         = broadcast_fn
        self.blob_fee      = 0.0
        self._blob_fee_raw_gwei = 0.0
        self.gas_pressure  = 0.5
        self.gas_velocity  = 0.0
        self.blob_velocity = 0.0
        self._gas_history  = []
        self._blob_history = []
        self._lock         = threading.Lock()
        threading.Thread(target=self._loop, daemon=True, name='eth-signals').start()
        print('[ETH-SIG] blob-base-fee + gas-pressure + blob-velocity thread started (' + str(BLOB_INTERVAL_S) + 's)')

    def _rpc(self, method, params=None):
        body = json.dumps({'jsonrpc':'2.0','method':method,'params':params or [],'id':1}).encode()
        for url in ETH_RPC_URLS:
            try:
                req = urllib.request.Request(url, data=body, headers=_RPC_HDR, method='POST')
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    return json.loads(resp.read())
            except Exception:
                continue
        return None

    def _loop(self):
        _register_thread_label("eth_signal")  # kernel chain-attribution
        cycle = 0
        while True:
            try:
                r = self._rpc('eth_blobBaseFee')
                if r and 'result' in r:
                    gwei = int(r['result'], 16) / 1e9
                    with self._lock:
                        bf_new = min(1.0, gwei / 1.0)
                        self._blob_history.append(bf_new)
                        if len(self._blob_history) > 6:
                            self._blob_history.pop(0)
                        self.blob_fee = bf_new
                        self._blob_fee_raw_gwei = gwei
                        if len(self._blob_history) >= 3:
                            self.blob_velocity = round(self._blob_history[-1] - self._blob_history[0], 4)
            except Exception:
                pass

            if cycle % 2 == 0:
                try:
                    r = self._rpc('eth_getBlockByNumber', ['latest', False])
                    if r and r.get('result'):
                        g_used  = int(r['result']['gasUsed'],  16)
                        g_limit = int(r['result']['gasLimit'], 16)
                        if g_limit > 0:
                            gp_new = min(1.0, g_used / g_limit)
                            with self._lock:
                                self.gas_pressure = round(GAS_EMA_ALPHA * gp_new + (1 - GAS_EMA_ALPHA) * self.gas_pressure, 4)
                                self._gas_history.append(self.gas_pressure)
                                if len(self._gas_history) > 6:
                                    self._gas_history.pop(0)
                                if len(self._gas_history) >= 3:
                                    self.gas_velocity = round(self._gas_history[-1] - self._gas_history[0], 4)
                except Exception:
                    pass

            with self._lock:
                bf = self.blob_fee
                gp = self.gas_pressure
                gv = self.gas_velocity
                bv = self.blob_velocity

            sp = stall_forecast(bf, gv, bv, ZK_BASE_TRACKER.zk_p99_last, ZK_BASE_TRACKER.zk_baseline)

            mev_incoming = gv > 0.15 or bf > 0.5
            _LATEST['blob_fee'] = bf
            vol = _volatility_score(_LATEST.get('base_revert'), bf)
            self.bcast({
                'type':               'PHOENIX_ETH_SIGNAL',
                'blob_base_fee':       round(bf, 4),
                'blob_base_fee_gwei':  round(self._blob_fee_raw_gwei, 6),
                'blob_velocity':       round(bv, 4),
                'gas_pressure':        round(gp, 4),
                'gas_velocity':        round(gv, 4),
                'mev_pre_signal':      mev_incoming,
                'stall_probability':   sp,
                'volatility_score':    vol,
                'ts':                  time.time(),
            })
            flag  = ' [MEV-INCOMING]' if mev_incoming else ''
            pflag = ' [STALL-LIKELY:' + str(sp) + ']' if sp > 0.5 else ''
            print('[ETH-SIG] blob=' + str(round(bf, 6)) + ' gas=' + str(round(gp, 4))
                  + ' gas_vel=' + str(round(gv, 4)) + ' blob_vel=' + str(round(bv, 4))
                  + ' stall_prob=' + str(sp) + flag + pflag)
            cycle += 1
            time.sleep(BLOB_INTERVAL_S)


# -- Predictive Stall Forecaster ----------------------------------------------
def stall_forecast(blob_fee, gas_vel, blob_vel, zk_p99, zk_baseline):
    """Combines leading indicators -> stall_probability [0..1] on 2-5 min horizon.
    Weights are conservative starting point; calibrate from history with baseline.json.
    """
    f_blob_lvl = min(1.0, blob_fee)
    f_blob_vel = min(1.0, max(0.0, blob_vel) / 0.10)
    f_gas_vel  = min(1.0, max(0.0, gas_vel)  / 0.30)
    zk_ref     = max(zk_baseline, 50.0)
    f_zk       = min(1.0, zk_p99 / max(2.0 * zk_ref, 500))
    p = 0.30 * f_gas_vel + 0.25 * f_blob_vel + 0.20 * f_blob_lvl + 0.25 * f_zk
    return round(min(1.0, p), 4)


# -- ZKSync Multi-Chain Cross-Chain Leading Indicator -------------------------
class ZkBaseCorrelationTracker:
    """ZKSync P99 spike predicts Base/Arb congestion 2-5 minutes later.
    v2.4: tracks zk_p99_last for stall_forecast(); .update() now called from ChainProbe.
    """
    def __init__(self):
        self._zk_history  = []
        self.mev_forecast = False
        self.zk_baseline  = 100.0
        self.zk_p99_last  = 100.0

    def update(self, zk_p99_ms):
        self.zk_p99_last = zk_p99_ms
        self._zk_history.append(zk_p99_ms)
        if len(self._zk_history) > 30:
            self._zk_history.pop(0)
        if len(self._zk_history) >= 10:
            self.zk_baseline  = sorted(self._zk_history)[len(self._zk_history) // 2]
            self.mev_forecast = zk_p99_ms > max(2.0 * self.zk_baseline, 500)

ZK_BASE_TRACKER = ZkBaseCorrelationTracker()


# -- Silicon DNA: Cross-Chain Correlation Matrix R_xy(τ) -----------------------
class CrossChainCorrelationMatrix:
    """12×12 cross-chain temporal correlation matrix.

    Detects synchronized activity across chains — a single physical source
    (MEV cluster, bot farm) produces correlated RTT spikes across multiple
    chains within microseconds. Legitimate users never transact on 12 chains
    simultaneously with μs-level synchronization.

    R_xy(τ) peak at τ→0 = same physical origin.
    """
    WINDOW = 60

    def __init__(self, chain_names, broadcast_fn):
        self._chains   = list(chain_names)
        self._n        = len(self._chains)
        self._idx      = {c: i for i, c in enumerate(self._chains)}
        self._bcast    = broadcast_fn
        self._lock     = threading.Lock()
        self._ts_buf   = {c: collections.deque(maxlen=self.WINDOW) for c in self._chains}
        self._rtt_buf  = {c: collections.deque(maxlen=self.WINDOW) for c in self._chains}
        self._last_emit = 0.0
        self._emit_interval = 30.0
        print(f'[SILICON-DNA] Cross-chain correlation matrix initialized: {self._n}×{self._n}')

    def feed(self, chain: str, rtt_ms: float):
        """Called by each ChainProbe on every measurement."""
        ts = time.monotonic()
        with self._lock:
            self._ts_buf[chain].append(ts)
            self._rtt_buf[chain].append(rtt_ms)

        now = time.time()
        if now - self._last_emit >= self._emit_interval:
            self._last_emit = now
            self._compute_and_broadcast()

    def _pearson(self, xs, ys):
        n = len(xs)
        if n < 5:
            return 0.0
        mx = sum(xs) / n
        my = sum(ys) / n
        num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        dx  = sum((x - mx) ** 2 for x in xs) ** 0.5
        dy  = sum((y - my) ** 2 for y in ys) ** 0.5
        if dx < 1e-12 or dy < 1e-12:
            return 0.0
        return num / (dx * dy)

    def _compute_and_broadcast(self):
        with self._lock:
            rtt_snap = {c: list(self._rtt_buf[c]) for c in self._chains}

        min_len = min(len(rtt_snap[c]) for c in self._chains)
        if min_len < 10:
            return

        corr_matrix = {}
        max_corr    = 0.0
        sync_pairs  = []

        for i in range(self._n):
            for j in range(i + 1, self._n):
                c1, c2 = self._chains[i], self._chains[j]
                xs = list(rtt_snap[c1])[-min_len:]
                ys = list(rtt_snap[c2])[-min_len:]
                r = self._pearson(xs, ys)
                key = f'{c1}_{c2}'
                corr_matrix[key] = round(r, 4)
                if abs(r) > max_corr:
                    max_corr = abs(r)
                if abs(r) > 0.85:
                    sync_pairs.append((c1, c2, round(r, 4)))

        self._bcast({
            'type':              'SILICON_DNA_CORRELATION',
            'matrix':            corr_matrix,
            'max_correlation':   round(max_corr, 4),
            'sync_pairs':        [(c1, c2, r) for c1, c2, r in sync_pairs],
            'sync_pair_count':   len(sync_pairs),
            'chains_active':     self._n,
            'window_samples':    min_len,
            'ts':                time.time(),
        })

        if sync_pairs:
            pairs_str = ', '.join(f'{c1}-{c2}(r={r})' for c1, c2, r in sync_pairs)
            print(f'[SILICON-DNA] ⚡ SYNC DETECTED: {pairs_str}')


CROSS_CHAIN_MATRIX = None  # initialized in start_multi_chain_probe


# -- L2 Revert Ratio thread ---------------------------------------------------
class RevertRatioThread:
    """Polls eth_getBlockReceipts for Arbitrum + Base every REVERT_INTERVAL_S.
    v2.4: multi-block sampling (REVERT_N_BLOCKS=3), EMA smoothing (alpha=0.4),
          fallback RPCs, confidence score, None (RPC fail) != 0.0 (no reverts).
    """
    def __init__(self, broadcast_fn):
        self.bcast       = broadcast_fn
        self._ratios     = {}
        self._confidence = {}
        self._ema_store  = {}
        self._lock       = threading.Lock()
        threading.Thread(target=self._loop, daemon=True, name='revert-ratio').start()
        print('[REVERT] L2 revert-ratio thread started (' + str(REVERT_INTERVAL_S)
              + 's, ' + str(REVERT_N_BLOCKS) + '-block sample): '
              + ', '.join(L2_REVERT_RPCS.keys()))

    def _get_block_number(self, url):
        body = json.dumps({'jsonrpc':'2.0','method':'eth_blockNumber','params':[],'id':1}).encode()
        req  = urllib.request.Request(url, data=body, headers=_RPC_HDR, method='POST')
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            data = json.loads(r.read())
        res = data.get('result')
        return int(res, 16) if res else None

    def _get_receipts(self, url, block_tag):
        body = json.dumps({'jsonrpc':'2.0','method':'eth_getBlockReceipts',
                           'params':[block_tag],'id':1}).encode()
        req  = urllib.request.Request(url, data=body, headers=_RPC_HDR, method='POST')
        with urllib.request.urlopen(req, timeout=7, context=ctx) as r:
            data = json.loads(r.read())
        return data.get('result')

    def _get_revert_ratio_multi(self, chain, urls):
        """Returns (ratio_or_None, sample_size).
        None  = RPC failure -> keep last known value, do NOT write 0.
        float = real measurement (0.0 legitimately means no reverts this window).
        """
        bn = None
        working_url = None
        for url in urls:
            try:
                bn = self._get_block_number(url)
                if bn is not None:
                    working_url = url
                    break
            except Exception:
                continue
        if bn is None:
            return None, 0

        total = failed = 0
        for off in range(REVERT_N_BLOCKS_BY_CHAIN.get(chain, REVERT_N_BLOCKS)):
            tag      = hex(bn - off)
            receipts = None
            try:
                receipts = self._get_receipts(working_url, tag)
            except Exception:
                pass
            if not receipts:
                for url2 in urls:
                    if url2 == working_url:
                        continue
                    try:
                        receipts = self._get_receipts(url2, tag)
                        if receipts:
                            break
                    except Exception:
                        continue
            if not receipts:
                continue
            total  += len(receipts)
            failed += sum(1 for rx in receipts if rx.get('status') == '0x0')

        if total == 0:
            return None, 0
        return round(failed / total, 4), total

    def _apply_ema(self, chain, raw):
        prev = self._ema_store.get(chain, raw)
        val  = round(REVERT_EMA_ALPHA * raw + (1 - REVERT_EMA_ALPHA) * prev, 4)
        self._ema_store[chain] = val
        return val

    def _loop(self):
        _register_thread_label("revert_ratio")  # kernel chain-attribution
        while True:
            updates = {}
            confs   = {}
            for chain, urls in L2_REVERT_RPCS.items():
                try:
                    ratio, samples = self._get_revert_ratio_multi(chain, urls)
                    if ratio is not None:
                        updates[chain] = self._apply_ema(chain, ratio)
                        confs[chain]   = samples
                except Exception as e:
                    print('[REVERT] ' + chain + ' error: ' + str(e))

            with self._lock:
                self._ratios.update(updates)
                self._confidence.update(confs)
                snap      = dict(self._ratios)
                snap_conf = dict(self._confidence)
                _b = snap.get('base')
                if _b is not None:
                    _LATEST['base_revert'] = _b

            if snap:
                payload = {
                    'type':              'PHOENIX_L2_HEALTH',
                    'arb_revert_ratio':  snap.get('arbitrum'),
                    'base_revert_ratio': snap.get('base'),
                    'arb_revert_conf':   snap_conf.get('arbitrum', 0),
                    'base_revert_conf':  snap_conf.get('base', 0),
                    'ts':                time.time(),
                }
                self.bcast(payload)
                parts = []
                for c, r in snap.items():
                    cf = snap_conf.get(c, 0)
                    parts.append(c[:3].upper() + '=' + str(r) + '(n=' + str(cf) + ')')
                print('[REVERT] ' + ' '.join(parts))
            time.sleep(REVERT_INTERVAL_S)




# -- Volume Delta thread -------------------------------------------------------
# Compares Uniswap V3 WETH/USDC DEX volume (last 5 L1 blocks, ~1 min)
# vs Binance ETHUSDT 1m candle volume.
# Informed-trading signal: DEX volume >> CEX → private order flow detected.

UNISWAP_V3_POOL  = '0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640'   # WETH/USDC 0.05% L1 (liquid; token0=USDC). was 0.3% 0x8ad5
SWAP_TOPIC       = '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67'
DEX_RPC_URLS     = ['https://rpc.mevblocker.io', 'https://eth.drpc.org']   # serve eth_getLogs (publicnode/ankr 403)
# US-friendly CEX APIs (Binance geo-blocked from DO NYC1)
CEX_APIS = [
    ('coinbase', 'https://api.exchange.coinbase.com/products/ETH-USD/candles?granularity=60'),
    ('kraken',   'https://api.kraken.com/0/public/OHLC?pair=ETHUSD&interval=1'),
]
VOL_INTERVAL_S   = 60
VOL_BLOCKS_BACK  = 15  # ~3 min of L1 blocks (12s each) for higher swap count

def _decode_int256(hex32: str) -> int:
    v = int(hex32, 16)
    return v - 2**256 if v >= 2**255 else v

def _rpc_call(url: str, method: str, params: list, timeout: int = 8):
    body = json.dumps({'jsonrpc': '2.0', 'method': method, 'params': params, 'id': 1}).encode()
    req  = urllib.request.Request(url, data=body, headers=_RPC_HDR)
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return json.loads(r.read())['result']

class VolumeDeltaThread:
    def __init__(self, bcast_fn):
        self.bcast  = bcast_fn
        self._last  = {'dex_vol_usd': 0.0, 'cex_vol_usd': 0.0, 'imbalance': 0.0, 'ts': 0}
        t = threading.Thread(target=self._loop, daemon=True, name='volume-delta')
        t.start()
        print('[VOL-DELTA] Uniswap V3 WETH/USDC vs Binance 1m started (' + str(VOL_INTERVAL_S) + 's)')

    def _get_dex_flow(self) -> dict:
        # Signed order flow from Uniswap V3 Swap events over last VOL_BLOCKS_BACK blocks.
        # token0=USDC(6dec): amount0>0 = USDC into pool = WETH BUY (bullish); <0 = WETH SELL.
        # Returns {total,buy,sell,net} USD. MEV/sandwich UNFILTERED (raw physics for JEPA).
        for url in DEX_RPC_URLS:
            try:
                bn   = int(_rpc_call(url, 'eth_blockNumber', []), 16)
                logs = _rpc_call(url, 'eth_getLogs', [{
                    'address':   UNISWAP_V3_POOL,
                    'topics':    [SWAP_TOPIC],
                    'fromBlock': hex(bn - VOL_BLOCKS_BACK),
                    'toBlock':   'latest',
                }])
                if not isinstance(logs, list):
                    continue
                buy = sell = 0.0
                for lg in logs:
                    data = lg.get('data', '0x')[2:]
                    if len(data) < 64:
                        continue
                    a0 = _decode_int256(data[0:64]) / 1e6   # USDC signed
                    if a0 >= 0:
                        buy  += a0
                    else:
                        sell += -a0
                return {'total': round(buy + sell, 2), 'buy': round(buy, 2),
                        'sell': round(sell, 2), 'net': round(buy - sell, 2)}
            except Exception as e:
                print('[VOL-DELTA] DEX error ' + str(e)[:60])
        return {'total': 0.0, 'buy': 0.0, 'sell': 0.0, 'net': 0.0}

    def _get_cex_volume(self) -> float:
        """Returns USD volume from Coinbase (primary) or Kraken (fallback) 1m candle."""
        for name, url in CEX_APIS:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': UA})
                with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
                    data = json.loads(r.read())
                if name == 'coinbase':
                    # [[time, low, high, open, close, volume], ...] newest first
                    if not data:
                        continue
                    # use second entry (previous completed candle)
                    row     = data[1] if len(data) > 1 else data[0]
                    close   = float(row[4])
                    eth_vol = float(row[5])
                    return round(eth_vol * close, 2)
                elif name == 'kraken':
                    # {'error':[], 'result':{'XETHZUSD':[[time,o,h,l,c,vwap,vol,count],...], 'last':N}}
                    result = data.get('result', {})
                    rows   = result.get('XETHZUSD') or result.get('ETHUSD') or []
                    if len(rows) < 2:
                        continue
                    row     = rows[-2]  # last completed candle
                    close   = float(row[4])
                    eth_vol = float(row[6])
                    return round(eth_vol * close, 2)
            except Exception as e:
                print('[VOL-DELTA] CEX ' + name + ' error: ' + str(e)[:60])
        return 0.0

    def _loop(self):
        _register_thread_label("volume_delta")  # kernel chain-attribution
        time.sleep(10)  # let other threads init first
        while True:
            try:
                flow = self._get_dex_flow()
                dex  = flow['total']
                cex  = self._get_cex_volume()
                if dex > 0 or cex > 0:
                    dex_pm     = dex / max(VOL_BLOCKS_BACK * 12.0 / 60.0, 1.0)
                    imb        = round((dex_pm - cex) / max(dex_pm + cex, 1.0), 4)   # bounded [-1,1]
                    level      = ('dex_dominant' if imb > 0.5
                                  else 'cex_dominant' if imb < -0.5
                                  else 'balanced')
                    flow_ratio = round(flow['net'] / max(dex, 1.0), 4)   # [-1,1]: + = net WETH buying
                    self._last = {
                        'dex_vol_usd': dex,
                        'cex_vol_usd': cex,
                        'imbalance':   imb,
                        'level':       level,
                        'ts':          time.time(),
                    }
                    self.bcast({
                        'type':             'PHOENIX_VOLUME_DELTA',
                        'dex_vol_usd':      dex,
                        'cex_vol_usd':      cex,
                        'imbalance':        imb,
                        'level':            level,
                        'dex_buy_usd':      flow['buy'],
                        'dex_sell_usd':     flow['sell'],
                        'dex_net_flow_usd': flow['net'],
                        'dex_flow_ratio':   flow_ratio,
                        'ts':               time.time(),
                    })
                    print('[VOL-DELTA] DEX=${:.0f} CEX=${:.0f} imb={:+.3f} netflow=${:+.0f} ratio={:+.3f} ({})'.format(
                        dex, cex, imb, flow['net'], flow_ratio, level))
            except Exception as e:
                print('[VOL-DELTA] loop error: ' + str(e)[:80])
            time.sleep(VOL_INTERVAL_S)

# -- Entrypoint ---------------------------------------------------------------
def start_multi_chain_probe(broadcast_fn):
    global CROSS_CHAIN_MATRIX
    CROSS_CHAIN_MATRIX = CrossChainCorrelationMatrix(CHAINS.keys(), broadcast_fn)
    for name, url in CHAINS.items():
        ChainProbe(name, url, broadcast_fn)
    EthSignalThread(broadcast_fn)
    RevertRatioThread(broadcast_fn)
    VolumeDeltaThread(broadcast_fn)
    print('[V2.5] Multi-chain probe + ETH signals + L2 revert ratio + Volume Delta + SILICON DNA R_xy: '
          + ', '.join(CHAINS.keys())
          + ' @ ' + str(int(PROBE_SEC*1000)) + 'ms'
          + ' | adaptive stall | blob+gas+velocity | revert(EMA+conf+multi-block)'
          + ' | stall_forecast | cross-chain correlation matrix LIVE')
