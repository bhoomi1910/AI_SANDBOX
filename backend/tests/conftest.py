"""Test fixtures: isolated temp database, uploads and report dirs.

Environment is configured BEFORE the app package is imported so that
settings/engine bind to the temp paths, never the dev database.
"""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="sandbox-tests-"))

os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'test.db'}"
os.environ["UPLOAD_DIR"] = str(_TMP / "uploads")
os.environ["REPORT_DIR"] = str(_TMP / "reports")
os.environ["MAX_UPLOAD_SIZE"] = str(1 * 1024 * 1024)  # 1 MiB

# Create directories before app imports
(_TMP / "uploads").mkdir(exist_ok=True)
(_TMP / "reports").mkdir(exist_ok=True)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
