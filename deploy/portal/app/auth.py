"""Usuario único del portal: contraseña con scrypt (biblioteca estándar) y sesiones en memoria.

Mismo esquema que el portal hermano Bledeagle. Las sesiones viven en memoria (1 worker; la BD del portal es
de solo lectura): reiniciar el portal obliga a volver a entrar.

Generar el hash para PORTAL_PASSWORD_HASH:
    python -m app.auth
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import secrets
import time

# scrypt con N=2^15, r=8: 32 MiB y unos 100 ms por intento. Formato sin «$» (Compose lo interpolaría en .env).
N, R, P = 2**15, 8, 1
MAXMEM = 64 * 1024 * 1024
SESSION_HOURS = 12
COOKIE = "sur_session"

_sessions: dict[str, float] = {}          # sha256(token) → caducidad (epoch)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, maxmem=MAXMEM, dklen=32)
    return f"scrypt:{N}:{R}:{P}:{_b64(salt)}:{_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split(":")
        if algo != "scrypt":
            return False
        expected = _unb64(dk)
        got = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=MAXMEM, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def check_credentials(user: str, password: str, expected_user: str, stored_hash: str) -> bool:
    ok_user = hmac.compare_digest(user.encode(), expected_user.encode())
    ok_pass = verify_password(password, stored_hash)   # siempre se calcula (tiempo constante)
    return ok_user and ok_pass


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session() -> str:
    now = time.time()
    for key in [k for k, exp in _sessions.items() if exp <= now]:   # purgar caducadas
        del _sessions[key]
    token = secrets.token_urlsafe(32)
    _sessions[_token_hash(token)] = now + SESSION_HOURS * 3600
    return token


def valid_session(token: str | None) -> bool:
    if not token:
        return False
    expires = _sessions.get(_token_hash(token))
    return expires is not None and expires > time.time()


def delete_session(token: str | None) -> None:
    if token:
        _sessions.pop(_token_hash(token), None)


if __name__ == "__main__":
    pw = getpass.getpass("Contraseña del portal: ")
    if len(pw) < 12:
        raise SystemExit("Mínimo 12 caracteres")
    if pw != getpass.getpass("Repítela: "):
        raise SystemExit("No coinciden")
    print(hash_password(pw))
