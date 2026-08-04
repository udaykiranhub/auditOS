"""Shared API fixtures.

Lives here rather than in one test module so every file in `tests/api/` can use the same
client, pointed at an isolated run root.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from engine.api.routes import app


@pytest.fixture
def client(tmp_path: Path, monkeypatch) -> TestClient:
    # `AUDITOS_RUN_DIR` is read per call by `default_run_root()`, so setting it here keeps
    # every test's runs inside its own tmp_path instead of the real ./run directory.
    monkeypatch.setenv("AUDITOS_RUN_DIR", str(tmp_path / "run"))
    return TestClient(app)
