import json, time, threading, hashlib, os, urllib.request, ssl, ctypes

# [2026-07-21 — chain attribution] Same self-registration mechanism as
# multi_chain_probe.py: lets the eBPF kernel-RTT sensor label this thread's
# SSL calls (Supabase key sync) instead of leaving them unattributed.
#
# os.gettid() (3.9+) is unavailable on this box's Python 3.10.12 build
# (confirmed empirically) — fall back to the raw gettid(2) syscall via ctypes.
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

def _register_thread_label(label: str) -> None:
    tid = _real_tid()
    if tid in _registered_tids:
        return
    with _tid_label_lock:
        if tid in _registered_tids:
            return
        try:
            os.makedirs(os.path.dirname(_TID_LABELS_PATH), exist_ok=True)
            with open(_TID_LABELS_PATH, "a") as f:
                f.write(f"{tid} {label}\n")
            _registered_tids.add(tid)
        except Exception:
            pass

class AccessGate:
    MAX_FAILS   = 5
    BLOCK_SEC   = 3600
    RELOAD_SEC  = 60

    def __init__(self):
        self.keys_path = '/opt/phoenix_zero/authorized_keys.json'
        self.blacklist = {}
        self.fail_count = {}
        self.active_sessions = {}
        self._lock = threading.Lock()
        self.keys = {}
        self._sb_url = os.getenv('SUPABASE_URL', '').rstrip('/')
        self._sb_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY', '')
        self._load_keys()
        threading.Thread(target=self._reload_loop, daemon=True).start()

    def _fetch_from_supabase(self):
        if not self._sb_url or not self._sb_key:
            return None
        try:
            ctx = ssl.create_default_context()
            url = self._sb_url + '/rest/v1/api_keys?is_active=eq.true&select=key_hash,client_name,tier,expiry'
            req = urllib.request.Request(url, headers={
                'apikey': self._sb_key,
                'Authorization': 'Bearer ' + self._sb_key,
            })
            with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
                rows = json.loads(r.read())
            now = time.time()
            result = {}
            for row in rows:
                if row.get('expiry', 0) > now:
                    result[row['key_hash']] = {
                        'client_name': row['client_name'],
                        'tier': row['tier'],
                        'expiry': row['expiry'],
                    }
            print(f'[GATE] Supabase sync: {len(result)} active keys')
            return result
        except Exception as e:
            print(f'[GATE] Supabase sync failed: {e}')
            return None

    def _load_keys(self):
        sb = self._fetch_from_supabase()
        if sb is not None:
            with self._lock:
                self.keys = sb
            self._save_json(sb)
        else:
            try:
                with open(self.keys_path) as f:
                    with self._lock:
                        self.keys = json.load(f)
                print('[GATE] Loaded keys from local JSON (fallback)')
            except Exception as e:
                print(f'[GATE] JSON load error: {e}')

    def _save_json(self, data):
        try:
            with open(self.keys_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _reload_loop(self):
        _register_thread_label("gate_sync")  # kernel chain-attribution
        while True:
            time.sleep(self.RELOAD_SEC)
            self._load_keys()

    def _hash(self, api_key: str) -> str:
        return hashlib.sha256(api_key.encode()).hexdigest()

    def is_authorized(self, api_key: str, client_ip: str):
        now = time.time()
        unblock = self.blacklist.get(client_ip, 0)
        if unblock > now:
            return False, 'blacklisted'
        elif unblock:
            self.blacklist.pop(client_ip, None)
            self.fail_count.pop(client_ip, None)

        key_hash = self._hash(api_key)
        with self._lock:
            k = self.keys.get(key_hash)

        if not k or k.get('expiry', 0) < now:
            fails = self.fail_count.get(client_ip, 0) + 1
            self.fail_count[client_ip] = fails
            if fails >= self.MAX_FAILS:
                self.blacklist[client_ip] = now + self.BLOCK_SEC
                print(f'[GATE] BLACKLISTED {client_ip} after {fails} fails')
                return False, 'blacklisted'
            return False, f'invalid_key ({fails}/{self.MAX_FAILS})'

        self.fail_count.pop(client_ip, None)
        return True, 'ok'

    def get_tier(self, api_key: str) -> str:
        key_hash = self._hash(api_key)
        with self._lock:
            return self.keys.get(key_hash, {}).get('tier', 'demo')

    def register_session(self, api_key: str, client_ip: str):
        key_hash = self._hash(api_key)
        self.active_sessions.setdefault(key_hash, set()).add(client_ip)

    def unregister_session(self, api_key: str, client_ip: str):
        key_hash = self._hash(api_key)
        if key_hash in self.active_sessions:
            self.active_sessions[key_hash].discard(client_ip)

gate = AccessGate()
