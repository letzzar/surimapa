"""App FastAPI: API /api/* + panel estático en /."""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hmac
import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from .api import router, warm_loop

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Autenticación HTTP Basic para todo el portal (panel, API y SSE). Sin credenciales no arranca:
# mejor fallar que quedar abierto por un .env incompleto.
PORTAL_USER = os.environ.get("PORTAL_USER", "")
PORTAL_PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
if not PORTAL_USER or not PORTAL_PASSWORD:
    raise RuntimeError("Definir PORTAL_USER y PORTAL_PASSWORD en .env")
AUTH_FAIL_DELAY_S = 1.0
_UNAUTHORIZED = {"WWW-Authenticate": 'Basic realm="Surimapa", charset="UTF-8"'}


def authorized(header: str | None) -> bool:
    if not header or header[:6].lower() != "basic ":      # el esquema no distingue mayúsculas (RFC 7617)
        return False
    try:
        user, sep, password = base64.b64decode(header[6:], validate=True).decode("utf-8").partition(":")
    except (binascii.Error, UnicodeDecodeError):
        return False
    # Comparar ambos siempre (tiempo constante, sin atajos).
    ok_user = hmac.compare_digest(user.encode(), PORTAL_USER.encode())
    ok_pass = hmac.compare_digest(password.encode(), PORTAL_PASSWORD.encode())
    return bool(sep) and ok_user and ok_pass


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(warm_loop())           # caché de 30d/90d (api.warm_long_ranges)
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# Sin /docs ni /openapi.json: Swagger UI carga recursos de un CDN (el panel no hace peticiones externas).
app = FastAPI(title="Surimapa", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

# El frontend no usa scripts ni estilos en línea: CSP estricta.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    header = request.headers.get("authorization")
    if authorized(header):
        response = await call_next(request)
    else:
        if header:                                   # intento fallido: frenar la fuerza bruta
            await asyncio.sleep(AUTH_FAIL_DELAY_S)
        response = Response("Autenticación requerida", status_code=401, headers=_UNAUTHORIZED,
                            media_type="text/plain; charset=utf-8")
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    else:
        # Estáticos: revalidar siempre (ETag → 304). Evita mezclar HTML nuevo con JS/CSS viejo tras desplegar.
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


app.include_router(router)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
