import asyncio, websockets, json, time, collections, os, pathlib as _pl
from access_gate import gate
import logging as _logging
_logging.getLogger('websockets.server').setLevel(_logging.CRITICAL)   # suppress HEAD-healthcheck handshake tracebacks

# [RESTORE 2026-07-20 — Oracle of Reality] Автономная подпись каждого среза
# (BLAKE3-хеш + Ed25519). Потребитель может проверить источник и неизменность.
# Мягкий импорт: если модуль/ключ недоступны — фид не падает, просто идёт без подписи.
try:
    from phoenix_integrity import signer as _integrity_signer
    _INTEGRITY_AVAILABLE = True
    print('[WSS] integrity signer ON, pub=' + _integrity_signer.public_key_hex[:16] + '...')
except Exception as _ie:
    print('[WSS] integrity unavailable:', _ie)
    _INTEGRITY_AVAILABLE = False

# [RESTORE 2026-07-20 — anomaly layer] Edge-инференс офлайн-обученного Isolation
# Forest (чистый numpy, БЕЗ scikit-learn — бокс на 957MB, sklearn в живом процессе
# рискует OOM). Модель обучена офлайн на реальной истории feed.jsonl, здесь только
# лёгкий инференс. Мягкий импорт: нет модели -> просто нет поля anomaly_score.
try:
    from anomaly_edge import load_default as _load_anomaly_scorer
    _anomaly_scorer = _load_anomaly_scorer()
    _ANOMALY_AVAILABLE = _anomaly_scorer is not None and _anomaly_scorer.loaded_ok
    if _ANOMALY_AVAILABLE:
        print('[WSS] anomaly scorer ON (offline Isolation Forest, numpy-only)')
    else:
        print('[WSS] anomaly scorer OFF: no model file yet')
except Exception as _ae:
    print('[WSS] anomaly scorer unavailable:', _ae)
    _ANOMALY_AVAILABLE = False

# [RESTORE 2026-07-20 — kernel sensor] phoenix_rtt_loader: CO-RE eBPF (libbpf),
# built off-box in an isolated container, ships as a precompiled .bpf.o + native
# loader binary — no compiler on this box (build toolchain purged after build).
# Measures SSL_write->SSL_read latency AT THE KERNEL, independent of Python's own
# event-loop/GIL jitter. Runs unprivileged via file capabilities (cap_bpf,
# cap_perfmon, cap_sys_admin, cap_sys_ptrace, cap_dac_read_search — set once via
# setcap, no root/SUID). Autonomous sensor: emits timing only, no payload
# content, no Moltbot schema dependency. Soft: if the binary/caps are missing,
# the rest of the probe is entirely unaffected.
EBPF_LOADER_BIN = os.environ.get('PHOENIX_EBPF_LOADER', '/opt/phoenix_zero/ebpf/phoenix_rtt_loader')
EBPF_OBJ_PATH   = os.environ.get('PHOENIX_EBPF_OBJ',    '/opt/phoenix_zero/ebpf/phoenix_rtt.bpf.o')
EBPF_ENABLED    = os.environ.get('PHOENIX_EBPF_ENABLED', 'true').lower() == 'true'

async def _run_ebpf_kernel_sensor(bcast_fn):
    """Launches the precompiled eBPF loader as a subprocess and forwards each
    stdout JSON line into the same broadcast() path signing/anomaly already use."""
    if not (EBPF_ENABLED and os.path.exists(EBPF_LOADER_BIN) and os.path.exists(EBPF_OBJ_PATH)):
        print('[EBPF] kernel sensor not started (binary/object missing or disabled)')
        return
    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                EBPF_LOADER_BIN, EBPF_OBJ_PATH,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            print('[EBPF] kernel sensor started, pid=' + str(proc.pid))
            async def _drain_stderr():
                async for line in proc.stderr:
                    print('[EBPF]', line.decode(errors='replace').rstrip())
            asyncio.create_task(_drain_stderr())
            async for line in proc.stdout:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                bcast_fn(ev)
            ret = await proc.wait()
            print('[EBPF] kernel sensor exited (code ' + str(ret) + '), restarting in 5s')
        except Exception as e:
            print('[EBPF] kernel sensor error:', e)
        await asyncio.sleep(5)

PUBLIC_DELAY_S  = int(os.environ.get('PUBLIC_DELAY_S',   '300'))
DEMO_INTERVAL_S = float(os.environ.get('DEMO_INTERVAL_S', '30'))
FEED_LOG_PATH   = os.environ.get('FEED_LOG_PATH', '/opt/phoenix_zero/data/feed.jsonl')
HTTP_PORT       = int(os.environ.get('HTTP_PORT', '8766'))

_delay_buf: collections.deque = collections.deque(maxlen=2000)
_metrics_buf: collections.deque = collections.deque(maxlen=65)
HISTORY_FILE = '/opt/phoenix_zero/metrics_history.jsonl'
_cur_bk: dict = {}


# ── Baseline cache (for z-score broadcast) ───────────────────────────────────

_BL_FILE = _pl.Path('/opt/phoenix_zero/baseline.json')
_bl_cache: dict = {}
_bl_ts    = 0.0
_BL_TTL   = 600.0

def _bl_load():
    global _bl_cache, _bl_ts
    try:
        import json as _j
        _bl_cache = _j.loads(_BL_FILE.read_text()).get('_metrics', {})
        _bl_ts    = time.time()
        print('[WSS] baseline loaded', len(_bl_cache), 'metrics')
    except Exception as _e:
        print('[WSS] baseline load error:', _e)

def _zscore(val, metric: str, hod: str) -> float | None:
    """Robust z-score: (val - p50) / (p95 - p50).  0 = median, 1 = p95."""
    if val is None:
        return None
    if time.time() - _bl_ts > _BL_TTL:
        _bl_load()
    slot = _bl_cache.get(metric, {}).get(hod)
    if not slot:
        return None
    p50 = slot.get('p50', 0) or 0
    p95 = slot.get('p95', 0) or 0
    denom = p95 - p50
    if denom <= 0:
        return None
    return round((val - p50) / denom, 3)

def _bk_ts(ts: float) -> int:
    return int(ts // 60) * 60

def _flush_bucket():
    if not _cur_bk or not _cur_bk.get('ts'):
        return
    import sys
    print(f"[FLUSH-DEBUG] volatility_score items: {len(_cur_bk.get('volatility_score', []))}, values: {_cur_bk.get('volatility_score', [])[-3:]}", file=sys.stderr)
    def avg(lst): return round(sum(lst) / len(lst), 4) if lst else None
    bkt = {
        'ts':          _cur_bk['ts'],
        'arb_p99':     avg(_cur_bk['arb_p99']),
        'op_p99':      avg(_cur_bk['op_p99']),
        'base_p99':    avg(_cur_bk['base_p99']),
        'zk_p99':      avg(_cur_bk['zk_p99']),
        'mantle_p99':  avg(_cur_bk['mantle_p99']),
        'casper_p99':  avg(_cur_bk.get('casper_p99', [])),
        'blob_fee':    avg(_cur_bk['blob_fee']),
        'gas_pres':    avg(_cur_bk['gas_pres']),
        'gas_vel':     avg(_cur_bk.get('gas_vel', [])),
        'blob_vel':    avg(_cur_bk.get('blob_vel', [])),
        'stall_prob':  avg(_cur_bk.get('stall_prob', [])),
        'arb_revert':  avg(_cur_bk['arb_revert']),
        'base_revert': avg(_cur_bk['base_revert']),
        'arb_conf':    avg(_cur_bk.get('arb_conf', [])),
        'base_conf':   avg(_cur_bk.get('base_conf', [])),
        'rtt_min_ms':    avg(_cur_bk.get('rtt_min_ms', [])),
        'rtt_spread_ms': avg(_cur_bk.get('rtt_spread_ms', [])),
        'volatility_score': avg(_cur_bk.get('volatility_score', [])),
        'volume_delta':  avg(_cur_bk.get('volume_delta', [])),
    }
    # ── z-scores (relative to hour-of-day baseline) ─────────────────────────
    hod = str(time.gmtime(int(_cur_bk['ts'])).tm_hour)
    for _m, _k in [
        ('arb_p99',     'arb_p99'),
        ('base_p99',    'base_p99'),
        ('zk_p99',      'zk_p99'),
        ('op_p99',      'op_p99'),
        ('arb_revert',  'arb_revert'),
        ('base_revert', 'base_revert'),
        ('stall_prob',  'stall_prob'),
    ]:
        z = _zscore(bkt.get(_k), _m, hod)
        if z is not None:
            bkt[_k + '_z'] = z

    _metrics_buf.append(bkt)
    try:
        with open(HISTORY_FILE, 'a') as _hf:
            _hf.write(json.dumps(bkt) + '\n')
    except Exception as _he:
        print(f'[HISTORY] write error: {_he}')

def _update_metrics(metric: dict, ts: float):
    t = metric.get('type', '')
    if t in ['PHOENIX_ETH_SIGNAL', 'PHOENIX_METRIC', 'PHOENIX_VOLUME_DELTA']:
        if 'rtt_min_ms' in metric or 'volatility_score' in metric or 'dex_flow_ratio' in metric:
            import sys
            print(f'[DEBUG] type={t} keys={list(metric.keys())}', file=sys.stderr)
    global _cur_bk
    bk = _bk_ts(ts)
    if _cur_bk.get('ts') != bk:
        _flush_bucket()
        _cur_bk = {
            'ts': bk,
            'arb_p99': [], 'op_p99': [], 'base_p99': [], 'zk_p99': [], 'mantle_p99': [],
            'casper_p99': [], 'blob_fee': [], 'gas_pres': [], 'gas_vel': [],
            'blob_vel': [], 'stall_prob': [], 'arb_revert': [], 'base_revert': [],
            'arb_conf': [], 'base_conf': [],
            'rtt_min_ms': [], 'rtt_spread_ms': [], 'volatility_score': [], 'volume_delta': [],
        }
    t = metric.get('type', '')
    if t == 'PHOENIX_METRIC':
        v = metric.get('p99_ms')
        if v is not None:
            key = {'arbitrum': 'arb_p99', 'optimism': 'op_p99',
                   'base': 'base_p99', 'zksync': 'zk_p99', 'mantle': 'mantle_p99',
                   'casper': 'casper_p99', 'scroll': 'scroll_p99',
                   'blast': 'blast_p99', 'linea': 'linea_p99', 'mode': 'mode_p99',
                   'polygon_zkevm': 'pgzk_p99', 'taiko': 'taiko_p99'}.get(metric.get('chain', ''))
            if key:
                _cur_bk[key].append(float(v))
        rtt_min = metric.get('rtt_min_ms')
        if rtt_min is not None:
            _cur_bk['rtt_min_ms'].append(float(rtt_min))
        rtt_spread = metric.get('rtt_spread_ms')
        if rtt_spread is not None:
            _cur_bk['rtt_spread_ms'].append(float(rtt_spread))
    elif t == 'PHOENIX_ETH_SIGNAL':
        if metric.get('blob_base_fee') is not None:
            _cur_bk['blob_fee'].append(float(metric['blob_base_fee']))
        if metric.get('gas_pressure') is not None:
            _cur_bk['gas_pres'].append(float(metric['gas_pressure']))
        if metric.get('gas_velocity') is not None:
            _cur_bk['gas_vel'].append(float(metric['gas_velocity']))
        if metric.get('blob_velocity') is not None:
            _cur_bk['blob_vel'].append(float(metric['blob_velocity']))
        if metric.get('stall_probability') is not None:
            _cur_bk['stall_prob'].append(float(metric['stall_probability']))
        if metric.get('volatility_score') is not None:
            _cur_bk['volatility_score'].append(float(metric['volatility_score']))
    elif t == 'PHOENIX_VOLUME_DELTA':
        vol_delta = metric.get('dex_flow_ratio')
        if vol_delta is not None:
            _cur_bk['volume_delta'].append(float(vol_delta))
    elif t == 'PHOENIX_L2_HEALTH':
        arb = metric.get('arb_revert_ratio')
        if arb is not None and arb >= 0:
            _cur_bk['arb_revert'].append(float(arb))
        base_rv = metric.get('base_revert_ratio')
        if base_rv is not None and base_rv >= 0:
            _cur_bk['base_revert'].append(float(base_rv))
        arb_c = metric.get('arb_revert_conf')
        if arb_c is not None:
            _cur_bk['arb_conf'].append(float(arb_c))
        base_c = metric.get('base_revert_conf')
        if base_c is not None:
            _cur_bk['base_conf'].append(float(base_c))

def _get_public_feed() -> list:
    now    = time.time()
    min_ts = now - 3900
    max_ts = now - PUBLIC_DELAY_S
    return [b for b in _metrics_buf if min_ts <= b['ts'] <= max_ts]

async def _http_handler(reader, writer):
    try:
        req = await asyncio.wait_for(reader.read(512), timeout=3.0)
        if b'GET /feed' in req:
            data = _get_public_feed()
            body = json.dumps({
                'data':      data,
                'count':     len(data),
                'delay_s':   PUBLIC_DELAY_S,
                'probe':     'DO_NYC1',
                'generated': int(time.time()),
            }).encode()
            hdr = (
                b'HTTP/1.1 200 OK\r\n'
                b'Content-Type: application/json\r\n'
                b'Access-Control-Allow-Origin: *\r\n'
                b'Cache-Control: max-age=60\r\n'
                b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
            )
            writer.write(hdr + body)
        else:
            writer.write(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def _start_http():
    srv = await asyncio.start_server(_http_handler, '127.0.0.1', HTTP_PORT)
    print('[HTTP] Public feed on 127.0.0.1:' + str(HTTP_PORT) + '/feed')
    async with srv:
        await srv.serve_forever()

os.makedirs(os.path.dirname(FEED_LOG_PATH), exist_ok=True)
_log_file = open(FEED_LOG_PATH, 'a', buffering=1)

def _log(msg_str: str):
    try:
        _log_file.write(msg_str + '\n')
    except Exception:
        pass

REALTIME_TIERS = {'searcher', 'professional', 'enterprise'}



def _enrich_with_zscores(metric: dict, hod: str):
    """Mutates metric in-place: adds _z fields based on message type."""
    t = metric.get('type', '')
    if t == 'PHOENIX_METRIC':
        chain = metric.get('chain', '')
        key_map = {
            'arbitrum': 'arb_p99',
            'base':     'base_p99',
            'optimism': 'op_p99',
            'zksync':   'zk_p99',
            'mantle':   'mantle_p99',
            'casper':   'casper_p99',
            'scroll':   'scroll_p99',
            'blast':    'blast_p99',
            'linea':    'linea_p99',
            'mode':     'mode_p99',
            'polygon_zkevm': 'pgzk_p99',
            'taiko':    'taiko_p99',
        }
        m = key_map.get(chain)
        if m:
            z = _zscore(metric.get('p99_ms'), m, hod)
            if z is not None:
                metric['p99_z'] = z
    elif t == 'PHOENIX_VOLUME_DELTA':
        vol_delta = metric.get('dex_flow_ratio')
        if vol_delta is not None:
            _cur_bk['volume_delta'].append(float(vol_delta))
    elif t == 'PHOENIX_L2_HEALTH':
        arb_z = _zscore(metric.get('arb_revert_ratio'),  'arb_revert',  hod)
        bas_z = _zscore(metric.get('base_revert_ratio'), 'base_revert', hod)
        if arb_z is not None: metric['arb_revert_z']  = arb_z
        if bas_z is not None: metric['base_revert_z'] = bas_z
    elif t == 'PHOENIX_ETH_SIGNAL':
        sp_z = _zscore(metric.get('stall_probability'), 'stall_prob', hod)
        bf_z = _zscore(metric.get('blob_base_fee'),     'blob_fee',   hod)
        if sp_z is not None: metric['stall_prob_z'] = sp_z
        if bf_z is not None: metric['blob_fee_z']   = bf_z

class PhoenixWSSDistributor:
    def __init__(self, host='127.0.0.1', port=8765):
        self.host        = host
        self.port        = port
        self.clients: dict = {}
        self.loop        = None
        self._bcast_cnt  = 0

    def broadcast_sync(self, metric: dict):
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(metric), self.loop)

    async def handle_client(self, websocket):
        client_ip = websocket.remote_address[0]
        api_key   = None
        tier      = 'public'
        try:
            try:
                raw     = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                data    = json.loads(raw)
                api_key = data.get('api_key', '').strip()
            except asyncio.TimeoutError:
                api_key = ''
            if api_key:
                is_ok, reason = gate.is_authorized(api_key, client_ip)
                if not is_ok:
                    print('[WSS] Denied ' + client_ip + ': ' + reason)
                    await websocket.send(json.dumps({'error': reason}))
                    return
                tier = gate.get_tier(api_key)
                gate.register_session(api_key, client_ip)
            self.clients[websocket] = {'tier': tier, 'last_sent': 0.0}
            print('[WSS] Auth OK ' + client_ip + ' tier=' + tier +
                  ' total=' + str(len(self.clients)))
            await websocket.send(json.dumps({
                'type':    'AUTH_OK',
                'probe':   'DO_NYC1',
                'tier':    tier,
                'delay_s': PUBLIC_DELAY_S if tier == 'public' else 0,
            }))
            if tier == 'public':
                await self._replay_public(websocket)
            await websocket.wait_closed()
        except Exception as e:
            print('[WSS] Session error ' + client_ip + ': ' + str(e))
        finally:
            self.clients.pop(websocket, None)
            if api_key:
                gate.unregister_session(api_key, client_ip)
            print('[WSS] Disconnected ' + client_ip +
                  ' total=' + str(len(self.clients)))

    async def _replay_public(self, websocket):
        now    = time.time()
        cutoff = now - PUBLIC_DELAY_S
        for ts, msg_str in list(_delay_buf):
            if ts > cutoff:
                break
            try:
                await asyncio.wait_for(websocket.send(msg_str), timeout=1.0)
                if websocket in self.clients:
                    self.clients[websocket]['last_sent'] = ts
            except Exception:
                return

    async def broadcast(self, metric: dict):
        now     = time.time()
        hod     = str(time.gmtime(int(now)).tm_hour)
        _enrich_with_zscores(metric, hod)
        # [RESTORE 2026-07-20 — anomaly layer] Нелинейный скор поверх линейных z-score
        # (ловит комбинации: rtt+spread+p99 вместе, которые z-score по одной метрике
        # пропускает). Только для PHOENIX_METRIC — там нужные фичи. Ошибка скоринга
        # не роняет фид (тот же принцип мягкой деградации, что и у подписи).
        if _ANOMALY_AVAILABLE and metric.get('type') == 'PHOENIX_METRIC':
            try:
                is_anom, ascore = _anomaly_scorer.is_anomaly(metric)
                metric['anomaly_score'] = ascore
                metric['is_anomaly']    = is_anom
            except Exception:
                pass
        # [RESTORE 2026-07-20 v2] Подписываем ПОЛНЫЙ срез вместе с _ts — ровно то, что
        # уходит на провод, чтобы verify() у потребителя проходил на сыром сообщении.
        # (v1 подписывал без _ts → on-wire verify=False. Поймано верификацией живого фида.)
        # metric оставляем чистым для _update_metrics. Ошибка подписи не роняет фид.
        _wire = {**metric, '_ts': now}
        if _INTEGRITY_AVAILABLE:
            try:
                _wire = _integrity_signer.sign(_wire)
            except Exception:
                pass
        msg_str = json.dumps(_wire)
        _log(msg_str)
        _update_metrics(metric, now)
        _delay_buf.append((now, msg_str))
        if not self.clients:
            return
        dead = set()
        for ws, info in list(self.clients.items()):
            tier      = info['tier']
            last_sent = info['last_sent']
            if tier == 'public':
                continue
            if tier == 'demo':
                if (now - last_sent) < DEMO_INTERVAL_S:
                    continue
            try:
                await asyncio.wait_for(ws.send(msg_str), timeout=1.0)
                self.clients[ws]['last_sent'] = now
                self._bcast_cnt += 1
                if self._bcast_cnt % 500 == 0:
                    print('[WSS] Broadcast #' + str(self._bcast_cnt) +
                          ' clients=' + str(len(self.clients)))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.clients.pop(ws, None)

    async def _push_public_delayed(self):
        while True:
            await asyncio.sleep(2.0)
            now    = time.time()
            cutoff = now - PUBLIC_DELAY_S
            dead   = set()
            pub = [(ws, info) for ws, info in list(self.clients.items())
                   if info['tier'] == 'public']
            if not pub:
                continue
            for ws, info in pub:
                last    = info['last_sent']
                to_send = [(ts, m) for ts, m in list(_delay_buf)
                           if last < ts <= cutoff]
                for ts, msg_str in to_send:
                    try:
                        await asyncio.wait_for(ws.send(msg_str), timeout=1.0)
                        self.clients[ws]['last_sent'] = ts
                    except Exception:
                        dead.add(ws)
                        break
            for ws in dead:
                self.clients.pop(ws, None)

    async def start_server(self):
        self.loop = asyncio.get_running_loop()
        print('[WSS] Server on ' + self.host + ':' + str(self.port))
        print('[WSS] Tiers: public(' + str(PUBLIC_DELAY_S) + 's delay) |'
              ' demo(' + str(int(DEMO_INTERVAL_S)) + 's) | searcher | professional | enterprise')
        print('[WSS] Feed log: ' + FEED_LOG_PATH)
        asyncio.create_task(self._push_public_delayed())
        asyncio.create_task(_start_http())
        asyncio.create_task(_run_ebpf_kernel_sensor(self.broadcast_sync))
        async with websockets.serve(self.handle_client, self.host, self.port,
                                    ping_interval=20, ping_timeout=15):
            await asyncio.Future()


_bl_load()
distributor = PhoenixWSSDistributor()

if __name__ == '__main__':
    from multi_chain_probe import start_multi_chain_probe
    start_multi_chain_probe(distributor.broadcast_sync)
    try:
        from phy_stats_collector import PhyStatsCollector
        PhyStatsCollector(distributor.broadcast_sync)
    except Exception as e:
        print(f'[PHY-STATS] skipped (not Linux or no ethtool): {e}')
    asyncio.run(distributor.start_server())