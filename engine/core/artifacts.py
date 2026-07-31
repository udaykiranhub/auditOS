"""Artifact persistence, hashing and run directories (SPEC §7.1).

The four artifact rules this module enforces mechanically:

1. Every artifact is a Pydantic v2 model with a ``schema_version``.
2. Every artifact serializes to ``run/<run_id>/artifacts/<name>.json``.
3. Every artifact has a ``content_hash`` derived from its **inputs** — this is what makes
   caching and resume possible.
4. Artifacts are append-only within a run: a module never mutates an upstream artifact.

Serialization is canonical (sorted keys, fixed separators, UTF-8) so that the same input
produces a byte-identical file on every run and on every machine. Nothing in here may
introduce a timestamp, a random value, or an absolute path into a hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

M = TypeVar("M", bound=BaseModel)

ARTIFACTS_DIRNAME = "artifacts"
REPO_DIRNAME = "repo"


# ── Canonical serialization ────────────────────────────────────────────────────

def canonical_json(payload: Any) -> str:
    """Serialize to the one canonical form used for hashing.

    Sorted keys and no incidental whitespace: two structurally equal payloads always
    produce the same string, so they always produce the same hash.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def content_hash(payload: Any) -> str:
    """SHA-256 of the canonical serialization of ``payload``."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def sha256_bytes(payload: bytes) -> str:
    """SHA-256 of raw bytes — never of decoded text, so line endings are content."""
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path, *, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of a file's raw bytes (never of its decoded text)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ── Run directories ────────────────────────────────────────────────────────────

def new_run_id() -> str:
    """A human-sortable, unique run identifier.

    The timestamp lives in the *directory name*, never in an artifact — artifacts must
    stay byte-identical across runs (SPEC §9.4).
    """
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


def default_run_root() -> Path:
    """Where per-run directories live. ``AUDITOS_RUN_DIR`` overrides; default ``./run``."""
    return Path(os.environ.get("AUDITOS_RUN_DIR", "run")).expanduser().resolve()


def create_run_dir(run_root: Path | None = None, run_id: str | None = None) -> Path:
    """Create ``<run_root>/<run_id>/{repo,artifacts}/`` and return the run directory."""
    root = (run_root or default_run_root()).resolve()
    run_dir = root / (run_id or new_run_id())
    (run_dir / REPO_DIRNAME).mkdir(parents=True, exist_ok=True)
    (run_dir / ARTIFACTS_DIRNAME).mkdir(parents=True, exist_ok=True)
    return run_dir


# ── Save / load ────────────────────────────────────────────────────────────────

def artifact_path(run_dir: Path, name: str) -> Path:
    return run_dir / ARTIFACTS_DIRNAME / f"{name}.json"


def save_artifact(model: BaseModel, run_dir: Path, name: str) -> Path:
    """Write an artifact to ``run/<run_id>/artifacts/<name>.json``.

    Uses ``indent=2`` + sorted keys: readable in a diff, still deterministic. Append-only
    (rule 4) is a discipline, not a lock — this will happily overwrite, so don't.
    """
    path = artifact_path(run_dir, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = model.model_dump(mode="json")
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def load_artifact(model_cls: type[M], path: Path) -> M:
    """Read an artifact back into its Pydantic model."""
    return model_cls.model_validate_json(path.read_text(encoding="utf-8"))
