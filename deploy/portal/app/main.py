"""App FastAPI: API /api/* + panel estático en /."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import auth
from .api import router, warm_loop

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Autenticación con formulario y cookie de sesión para todo el portal (panel, API y SSE), como en Bledeagle.
# Sin credenciales no arranca: mejor fallar que quedar abierto por un .env incompleto.
PORTAL_USER = os.environ.get("PORTAL_USER", "")
PORTAL_PASSWORD_HASH = os.environ.get("PORTAL_PASSWORD_HASH", "")
if not PORTAL_USER or not PORTAL_PASSWORD_HASH.startswith("scrypt:"):
    raise RuntimeError("Definir PORTAL_USER y PORTAL_PASSWORD_HASH (python -m app.auth) en .env")
AUTH_FAIL_DELAY_S = 1.0
MAX_LOGIN_BODY = 1024
# Lo único accesible sin sesión: el login, lo que carga y el healthcheck de Docker.
PUBLIC_PATHS = {"/login", "/healthz", "/css/app.css", "/js/theme.js"}
LOGIN_HTML = (STATIC_DIR / "login.html").read_text(encoding="utf-8")
_ERROR_HIDDEN = '<p class="login-error" role="alert" hidden>'


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True                                   # navegadores sin Origin: queda SameSite=Strict
    return urlsplit(origin).netloc == request.headers.get("host", "")


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
    # same-origin (no no-referrer): con no-referrer Chrome envía «Origin: null» en los POST del login y _same_origin los rechaza.
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    # CSRF: además de SameSite=Strict, las peticiones que cambian estado deben venir de este mismo origen.
    if request.method not in ("GET", "HEAD") and not _same_origin(request):
        response: Response = Response("Origen no permitido", status_code=403, media_type="text/plain; charset=utf-8")
    elif path in PUBLIC_PATHS or auth.valid_session(request.cookies.get(auth.COOKIE)):
        response = await call_next(request)
    elif path.startswith("/api/"):                   # el panel (api.js) redirige a /login al ver el 401
        response = Response("Sesión requerida", status_code=401, media_type="text/plain; charset=utf-8")
    else:
        response = RedirectResponse("/login", status_code=303)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if path.startswith("/api/") or path in ("/login", "/logout"):
        response.headers.setdefault("Cache-Control", "no-store")
    else:
        # Estáticos: revalidar siempre (ETag → 304). Evita mezclar HTML nuevo con JS/CSS viejo tras desplegar.
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/login")
def login_form() -> HTMLResponse:
    return HTMLResponse(LOGIN_HTML)


@app.post("/login")
async def login(request: Request) -> Response:
    # Formulario urlencoded leído a mano: evita la dependencia python-multipart solo para dos campos.
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_LOGIN_BODY:
            break
    form = parse_qs(body.decode("utf-8", "replace")) if len(body) <= MAX_LOGIN_BODY else {}
    username = form.get("username", [""])[0][:64]
    password = form.get("password", [""])[0][:256]
    ok = await asyncio.to_thread(auth.check_credentials, username, password, PORTAL_USER, PORTAL_PASSWORD_HASH)
    if not ok:
        await asyncio.sleep(AUTH_FAIL_DELAY_S)       # frenar la fuerza bruta
        return HTMLResponse(LOGIN_HTML.replace(_ERROR_HIDDEN, _ERROR_HIDDEN.replace(" hidden", "")), status_code=401)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(auth.COOKIE, auth.create_session(), max_age=auth.SESSION_HOURS * 3600, path="/",
                        secure=True, httponly=True, samesite="strict")
    return response


@app.post("/logout")
def logout(request: Request) -> Response:
    auth.delete_session(request.cookies.get(auth.COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return response


app.include_router(router)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
