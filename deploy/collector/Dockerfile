FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# --chmod: no depender de los permisos del recurso SMB/ACL del NAS.
COPY --chmod=0755 surimapa_collector/ ./surimapa_collector/

USER 10001:10001
# Sano si el último heartbeat con Redis (cada 30 s) tiene menos de 120 s.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import os,sys,time; sys.exit(time.time() - os.stat('/tmp/surimapa-heartbeat').st_mtime > 120)"
CMD ["python", "-m", "surimapa_collector.main"]
