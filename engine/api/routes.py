"""FastAPI app (SPEC §6) — **Phase 1 slice only.**

The full contract in `api/README.md` is four endpoints backed by a running pipeline. Only
the Repository Reader exists, so only its slice is exposed: start a run, get a `RepoModel`
back, synchronously. No job state, no SSE, no report — those arrive with the stages that
produce them.

Every endpoint is something a human could `curl`; the frontend adds nothing the CLI can't
already do (SPEC §4 hard rule).

```
POST /audits/upload   multipart: a .zip, or a folder's files with relative paths
POST /audits/remote   json: {"source": "<git url | local path>", "ref": "...", ...}
GET  /audits/{run_id}/repo   the persisted RepoModel
```
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException

from engine.core.artifacts import default_run_root, load_artifact
from engine.core.errors import FatalError
from engine.core.models.repo import RepoModel, ScopeOverride
from engine.ingest.reader import ARTIFACT_NAME, ingest

# Matches MAX_ARCHIVE_ENTRIES in ingest/materialize.py — an upload is a repo either way.
MAX_UPLOAD_FILES = 20_000

app = FastAPI(
    title="AuditOS",
    version="0.1.0",
    description="AI smart-contract security engine — Phase 1: Repository Reader.",
)

# The Vite dev server proxies /audits, so same-origin covers normal use. CORS is here for
# the case where the frontend is opened directly against the API port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class RemoteRequest(BaseModel):
    """Ingest something the server can reach itself: a git URL or a local path."""

    source: str
    ref: str | None = None
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class IngestResponse(BaseModel):
    run_id: str
    artifact_path: str
    counts: dict[str, int]
    repo: RepoModel


def _respond(model: RepoModel, artifact: Path) -> IngestResponse:
    return IngestResponse(
        run_id=artifact.parent.parent.name,
        artifact_path=str(artifact),
        counts=model.counts,
        repo=model,
    )


def _fatal(exc: FatalError) -> HTTPException:
    """A `FatalError` is a clean 4xx with a machine-readable code, never a stack trace."""
    return HTTPException(
        status_code=422,
        detail={"code": exc.code, "message": exc.message, "hint": exc.hint},
    )


@app.get("/audits/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "1", "stage": "repository-reader"}


@app.post("/audits/upload", response_model=IngestResponse)
async def upload(request: Request) -> IngestResponse:
    """Ingest an uploaded `.zip`, or a whole folder sent as files + relative paths.

    Browsers cannot hand over a directory path, only its files. So a dropped folder
    arrives as many parts whose filenames carry the relative path, and is reassembled
    into a staging directory before the reader sees it — which keeps the reader's three
    origins intact rather than inventing a fourth.

    The form is parsed by hand because Starlette caps multipart uploads at 1000 files by
    default, and a real protocol folder is far past that. Worse, the cap trips *during*
    the upload: the connection is torn down mid-stream, so the browser sees a network
    error rather than the 400. The limit here matches the ZIP entry limit (§9.1).
    """
    try:
        form = await request.form(max_files=MAX_UPLOAD_FILES, max_fields=64)
    except MultiPartException as exc:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "UPLOAD_TOO_LARGE",
                "message": str(exc),
                "hint": f"At most {MAX_UPLOAD_FILES} files per upload. Zip the project instead.",
            },
        ) from exc

    files = [part for part in form.getlist("files") if isinstance(part, UploadFile)]
    include = str(form.get("include") or "")
    exclude = str(form.get("exclude") or "")

    if not files:
        raise HTTPException(
            status_code=400,
            detail={"code": "UPLOAD_EMPTY", "message": "No files were uploaded."},
        )

    staging = Path(tempfile.mkdtemp(prefix="auditos-upload-"))
    try:
        single_zip = len(files) == 1 and (files[0].filename or "").lower().endswith(".zip")

        if single_zip:
            target = staging / "upload.zip"
            with target.open("wb") as handle:
                shutil.copyfileobj(files[0].file, handle)
            source: Path = target
        else:
            source = staging / "repo"
            for item in files:
                relative = _safe_relative(item.filename or "")
                if relative is None:
                    continue
                destination = source / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("wb") as handle:
                    shutil.copyfileobj(item.file, handle)
            if not source.exists():
                raise HTTPException(
                    status_code=400,
                    detail={"message": "The upload contained no usable files."},
                )

        model, artifact = ingest(source, scope_override=_override(include, exclude))
        return _respond(model, artifact)
    except FatalError as exc:
        raise _fatal(exc) from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)


@app.post("/audits/remote", response_model=IngestResponse)
def remote(request: RemoteRequest) -> IngestResponse:
    """Ingest a git URL, or a folder path on the machine running the engine."""
    try:
        model, artifact = ingest(
            request.source.strip(),
            ref=request.ref or None,
            scope_override=_override(request.include, request.exclude),
        )
        return _respond(model, artifact)
    except FatalError as exc:
        raise _fatal(exc) from exc


@app.get("/audits/{run_id}/repo", response_model=RepoModel)
def get_repo(run_id: str) -> RepoModel:
    """Re-read a previous run's artifact from disk."""
    artifact = default_run_root() / run_id / "artifacts" / f"{ARTIFACT_NAME}.json"
    if not artifact.is_file():
        raise HTTPException(status_code=404, detail={"message": f"No such run: {run_id}"})
    return load_artifact(RepoModel, artifact)


# ── helpers ───────────────────────────────────────────────────────────────────

def _override(include: str | list[str], exclude: str | list[str]) -> ScopeOverride:
    """Accept both the form encoding (comma-separated) and the JSON encoding (lists)."""
    def split(value: str | list[str]) -> list[str]:
        if isinstance(value, list):
            return [item for item in value if item]
        return [part.strip() for part in value.split(",") if part.strip()]

    return ScopeOverride(include=split(include), exclude=split(exclude))


def _safe_relative(filename: str) -> Path | None:
    """Same traversal rules as the ZIP reader — an upload is no more trusted than a zip."""
    normalized = filename.replace("\\", "/").lstrip("/")
    if not normalized:
        return None
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts) or (len(parts[0]) > 1 and parts[0][1] == ":"):
        return None
    # Browsers prefix webkitRelativePath with the dropped folder's own name; dropping it
    # keeps repo-relative paths honest, exactly like flattening a GitHub zip wrapper.
    if len(parts) > 1:
        parts = parts[1:]
    return Path(*parts) if parts else None
