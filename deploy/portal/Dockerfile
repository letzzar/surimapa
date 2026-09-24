FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt

# --chmod: no depender de los permisos del recurso SMB/ACL del NAS.
COPY --chmod=0755 app/ ./app/
COPY --chmod=0755 static/ ./static/

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import base64,os,sys,urllib.request as u; t=base64.b64encode(f\"{os.environ['PORTAL_USER']}:{os.environ['PORTAL_PASSWORD']}\".encode()).decode(); sys.exit(u.urlopen(u.Request('http://127.0.0.1:8000/api/health', headers={'Authorization': 'Basic ' + t}), timeout=4).status != 200)"
# 1 worker basta. El cierre corto evita que las conexiones SSE retrasen la parada.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--no-server-header", "--timeout-graceful-shutdown", "3"]
