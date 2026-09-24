import json
import os
import sys
from pathlib import Path

# Credenciales del portal para los tests (el portal no arranca sin ellas).
os.environ.setdefault("PORTAL_USER", "tester")
os.environ.setdefault("PORTAL_PASSWORD", "clave-de-prueba")

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deploy" / "collector"))
sys.path.insert(0, str(ROOT / "deploy" / "portal"))

FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def real_alert() -> dict:
    """Alerta real de pfSense (2026-09-23), anonimizada."""
    return json.loads((FIXTURES / "eve_alert_01.json").read_text(encoding="utf-8"))
