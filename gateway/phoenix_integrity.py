"""
Phoenix Zero — Integrity & Provenance layer (Oracle of Reality).

Каждый срез телеметрии подписывается: BLAKE3-хеш канонической формы + Ed25519-подпись.
Потребитель (JARVIS, любой покупатель данных) может МАТЕМАТИЧЕСКИ проверить, что срез:
  1) пришёл именно от этого зонда (Ed25519 pubkey), а не выдуман;
  2) не был изменён ни in-flight, ни задним числом в базе (BLAKE3 hash).

Автономность: этот слой НЕ зависит от Moltbot или любой высокоуровневой схемы.
Чистый сенсорный примитив — подписать/проверить произвольный dict телеметрии.
"""
import json
import os
import threading
import time

import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

ALG = "blake3+ed25519"
_DEFAULT_KEY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "phoenix_signing.key"
)

_RAW = serialization.Encoding.Raw


def _canonical(payload: dict) -> bytes:
    """
    Детерминированные байты для хеширования: отсортированные ключи, без пробелов,
    поле 'integrity' исключено (чтобы verify считал ровно то, что было подписано).
    """
    body = {k: v for k, v in payload.items() if k != "integrity"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _pub_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(_RAW, serialization.PublicFormat.Raw)


class PhoenixSigner:
    """
    Ed25519-подписант с персистентным ключом. Потокобезопасен (sign вызывается из
    broadcast-пути зонда из разных потоков). Ключ генерится один раз и лежит в файле
    с правами 0600 — pubkey стабильный, потребители доверяют одному отпечатку.
    """

    def __init__(self, key_path: str | None = None):
        self.key_path = key_path or os.getenv("PHOENIX_SIGNING_KEY_PATH", _DEFAULT_KEY_PATH)
        self._lock = threading.Lock()
        self._priv = self._load_or_create_key()
        self._pub_hex = _pub_raw(self._priv.public_key()).hex()

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        try:
            with open(self.key_path, "rb") as f:
                raw = f.read()
            if len(raw) == 32:
                return Ed25519PrivateKey.from_private_bytes(raw)
        except FileNotFoundError:
            pass
        # Ключа нет (или он битый) — генерируем и сохраняем.
        priv = Ed25519PrivateKey.generate()
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        raw = priv.private_bytes(_RAW, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        with open(self.key_path, "wb") as f:
            f.write(raw)
        try:
            os.chmod(self.key_path, 0o600)  # best-effort (POSIX)
        except OSError:
            pass
        return priv

    @property
    def public_key_hex(self) -> str:
        return self._pub_hex

    def sign(self, payload: dict) -> dict:
        """Вернуть КОПИЮ payload с добавленным блоком 'integrity'."""
        digest = blake3.blake3(_canonical(payload)).digest()   # 32 байта
        with self._lock:
            sig = self._priv.sign(digest)
        out = dict(payload)
        out["integrity"] = {
            "alg":       ALG,
            "hash":      digest.hex(),
            "sig":       sig.hex(),
            "pub":       self._pub_hex,
            "signed_ns": time.time_ns(),
        }
        return out


def verify(signed_payload: dict) -> bool:
    """
    Проверить подписанный срез. Пересчитывает BLAKE3-хеш по канонической форме тела
    (без 'integrity') и проверяет Ed25519-подпись поверх хеша. True — только если
    данные целы И подпись совпадает со встроенным публичным ключом.
    """
    integ = signed_payload.get("integrity")
    if not isinstance(integ, dict) or integ.get("alg") != ALG:
        return False
    try:
        stored_hash = bytes.fromhex(integ["hash"])
        sig = bytes.fromhex(integ["sig"])
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(integ["pub"]))
    except (KeyError, ValueError, TypeError):
        return False
    # 1) данные целы?
    if blake3.blake3(_canonical(signed_payload)).digest() != stored_hash:
        return False
    # 2) подпись валидна поверх этого хеша?
    try:
        pub.verify(sig, stored_hash)
    except InvalidSignature:
        return False
    return True


# Синглтон для emit-пути зонда.
signer = PhoenixSigner()
