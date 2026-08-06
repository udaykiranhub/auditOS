"""FastAPI app (SPEC §6) — the stages that exist so far.

The full contract in `api/README.md` assumes a complete pipeline. Only ingest, build and
parse are implemented, so only their slice is exposed. No SSE, no report — those arrive
with the stages that produce them.

Every endpoint is something a human could `curl`; the frontend adds nothing the CLI cannot
already do (SPEC §4 hard rule).

```
POST /audits/upload           multipart: a .zip, or a folder's files with relative paths
POST /audits/remote           json: {"source": "<git url | local path>", "ref": …}
GET  /audits/{run_id}/repo    the persisted RepoModel
POST /audits/{run_id}/build   start compilation (202); poll /build/status
POST /audits/{run_id}/parse   RepoModel (+ BuildModel) -> CodeModel
GET  /audits/{run_id}/code    the persisted CodeModel
POST /audits/{run_id}/graph   CodeModel -> GraphModel (the code property graph)
GET  /audits/{run_id}/graph   the persisted GraphModel
GET  /audits/{run_id}/graph/query   the SPEC §13.5 queries, one call each
```
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException

from engine.core.artifacts import default_run_root, load_artifact
from engine.core.errors import FatalError
from engine.core.models.build import BuildModel
from engine.core.models.code import CodeModel
from engine.core.models.graph import GraphModel
from engine.core.models.repo import RepoModel, ScopeOverride
from engine.graphs.build import ARTIFACT_NAME as GRAPH_ARTIFACT
from engine.graphs.build import build_and_save as build_and_save_graph
from engine.graphs.query import GraphQuery
from engine.ingest.build.pipeline import ARTIFACT_NAME as BUILD_ARTIFACT
from engine.ingest.build.pipeline import build_and_save
from engine.ingest.reader import ARTIFACT_NAME, ingest
from engine.parse.pipeline import ARTIFACT_NAME as CODE_ARTIFACT
from engine.parse.pipeline import parse_and_save

# Matches MAX_ARCHIVE_ENTRIES in ingest/materialize.py — an upload is a repo either way.
MAX_UPLOAD_FILES = 20_000

#: Contracts returned by the centrality query. Enough to rank "core contracts"; short
#: enough that the answer stays readable.
CENTRALITY_TOP = 25

app = FastAPI(
    title="AuditOS",
    version="0.1.0",
    description="AI smart-contract security engine.",
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


class BuildRequest(BaseModel):
    """`allow_hardhat` permits `npx hardhat compile`, which EXECUTES the target's config."""

    allow_hardhat: bool = False


class BuildJobStatus(BaseModel):
    """A build's progress. `model` is populated once `state` is `done`."""

    run_id: str
    state: Literal["running", "done", "error"]
    elapsed_seconds: float
    model: BuildModel | None = None
    error: str | None = None


class BuildJob:
    """One background compilation.

    In-process and deliberately not persisted: V1 has no job persistence across restarts
    (SPEC §2.2 non-goals). The `BuildModel` on disk is the durable record; this is only
    how a caller watches a build that is still running.
    """

    def __init__(self, run_id: str, allow_hardhat: bool | None = None):
        self.run_id = run_id
        self.allow_hardhat = allow_hardhat
        self.state: Literal["running", "done", "error"] = "running"
        self.model: BuildModel | None = None
        self.error: str | None = None
        self.started = time.monotonic()
        self.finished: float | None = None
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"build-{run_id}")

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            repo = _load_repo(self.run_id)
            model, _ = build_and_save(
                repo, default_run_root() / self.run_id, allow_hardhat=self.allow_hardhat
            )
            self.model = model
            self.state = "done"
        except Exception as exc:  # a crashed builder must not take the server with it
            self.error = f"{type(exc).__name__}: {exc}"
            self.state = "error"
        finally:
            self.finished = time.monotonic()

    def status(self) -> BuildJobStatus:
        end = self.finished if self.finished is not None else time.monotonic()
        return BuildJobStatus(
            run_id=self.run_id,
            state=self.state,
            elapsed_seconds=round(end - self.started, 1),
            model=self.model,
            error=self.error,
        )


_BUILD_JOBS: dict[str, BuildJob] = {}


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
    return {"status": "ok", "stages": "repository-reader,build,parse,graph"}


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
    payload = [(item.filename or "", item.file) for item in files]

    try:
        # Off the event loop. Writing thousands of files and then reading the repository
        # is seconds-to-minutes of blocking work; doing it inline froze the whole server —
        # every other request, including `/audits/health`, simply hung until it finished,
        # which reads from the browser as an unexplained timeout rather than a slow upload.
        model, artifact = await run_in_threadpool(
            _ingest_upload, payload, staging, _override(include, exclude)
        )
        return _respond(model, artifact)
    except FatalError as exc:
        raise _fatal(exc) from exc
    finally:
        await run_in_threadpool(shutil.rmtree, staging, True)


def _ingest_upload(
    files: list[tuple[str, BinaryIO]],
    staging: Path,
    scope_override: ScopeOverride,
) -> tuple[RepoModel, Path]:
    """Write the uploaded parts to disk, then read them. Runs on a worker thread."""
    single_zip = len(files) == 1 and files[0][0].lower().endswith(".zip")

    if single_zip:
        source = staging / "upload.zip"
        with source.open("wb") as handle:
            shutil.copyfileobj(files[0][1], handle)
    else:
        source = staging / "repo"
        for filename, stream in files:
            relative = _safe_relative(filename)
            if relative is None:
                continue
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as handle:
                shutil.copyfileobj(stream, handle)
        if not source.exists():
            raise FatalError(
                "The upload contained no usable files.",
                code="UPLOAD_NO_USABLE_FILES",
                hint="Every part was rejected as unsafe or empty.",
            )

    return ingest(source, scope_override=scope_override)


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
    return _load_repo(run_id)


@app.post("/audits/{run_id}/build", status_code=202, response_model=BuildJobStatus)
def start_build(run_id: str, request: BuildRequest | None = None) -> BuildJobStatus:
    """Start compiling a run's repository (SPEC §10). Returns immediately.

    Compilation of a real protocol takes minutes, which is longer than any sensible HTTP
    timeout — holding the request open turned a slow build into a client-side error that
    looked like a failure. The build runs on a worker thread and the caller polls
    `GET /audits/{run_id}/build/status`.

    A compilation failure is never an error here: a repository that does not compile still
    produces a `BuildModel`, with `build_available=False` and the diagnostics explaining
    why. Losing the storage layout must not cost the audit.
    """
    _load_repo(run_id)  # 404 now rather than inside the worker

    existing = _BUILD_JOBS.get(run_id)
    if existing and existing.state == "running":
        return existing.status()

    job = BuildJob(run_id, allow_hardhat=(request.allow_hardhat if request else None))
    _BUILD_JOBS[run_id] = job
    job.start()
    return job.status()


@app.get("/audits/{run_id}/build/status", response_model=BuildJobStatus)
def build_status(run_id: str) -> BuildJobStatus:
    """Poll a build. `state` is one of `running` | `done` | `error`."""
    job = _BUILD_JOBS.get(run_id)
    if job is None:
        artifact = default_run_root() / run_id / "artifacts" / f"{BUILD_ARTIFACT}.json"
        if artifact.is_file():
            # A build from a previous server process: the artifact outlives the job table.
            return BuildJobStatus(
                run_id=run_id,
                state="done",
                elapsed_seconds=0.0,
                model=load_artifact(BuildModel, artifact),
            )
        raise HTTPException(
            status_code=404, detail={"message": f"No build has been started for run {run_id}."}
        )
    return job.status()


@app.post("/audits/{run_id}/parse", response_model=CodeModel)
def parse(run_id: str) -> CodeModel:
    """Parse a run's repository into a `CodeModel` (SPEC §12).

    Synchronous: parsing a 3,700-file protocol takes a couple of minutes, but unlike a
    build it cannot be skipped, so there is no partial result worth streaming. If this
    grows past the request timeout it should adopt the same job/poll shape as the build.

    Uses the run's `BuildModel` when one exists — storage slots and canonical selectors
    are enrichment (§12.1), never a precondition.
    """
    repo = _load_repo(run_id)
    run_dir = default_run_root() / run_id

    build: BuildModel | None = None
    build_artifact = run_dir / "artifacts" / f"{BUILD_ARTIFACT}.json"
    if build_artifact.is_file():
        build = load_artifact(BuildModel, build_artifact)

    try:
        code, _ = parse_and_save(repo, run_dir, build)
    except FatalError as exc:
        raise _fatal(exc) from exc
    return code


@app.get("/audits/{run_id}/code", response_model=CodeModel)
def get_code(run_id: str) -> CodeModel:
    artifact = default_run_root() / run_id / "artifacts" / f"{CODE_ARTIFACT}.json"
    if not artifact.is_file():
        raise HTTPException(
            status_code=404, detail={"message": f"Run {run_id} has not been parsed."}
        )
    return load_artifact(CodeModel, artifact)


@app.post("/audits/{run_id}/graph", response_model=GraphModel)
def graph(run_id: str) -> GraphModel:
    """Build the code property graph from a run's `CodeModel` (SPEC §13).

    Fast — the graph is pure computation over an artifact already on disk, so unlike the
    build there is nothing to poll. Parse first; there is no implicit re-parse here,
    because silently redoing an expensive stage hides which artifact you are looking at.
    """
    run_dir = default_run_root() / run_id
    code_artifact = run_dir / "artifacts" / f"{CODE_ARTIFACT}.json"
    if not code_artifact.is_file():
        raise HTTPException(
            status_code=409,
            detail={
                "code": "GRAPH_NEEDS_PARSE",
                "message": f"Run {run_id} has not been parsed.",
                "hint": f"POST /audits/{run_id}/parse first.",
            },
        )

    code = load_artifact(CodeModel, code_artifact)
    try:
        model, _ = build_and_save_graph(code, run_dir)
    except FatalError as exc:
        raise _fatal(exc) from exc
    return model


@app.get("/audits/{run_id}/graph", response_model=GraphModel)
def get_graph(run_id: str) -> GraphModel:
    return _load_graph(run_id)


@app.get("/audits/{run_id}/graph/query")
def graph_query(run_id: str, q: str, target: str = "") -> dict[str, object]:
    """One SPEC §13.5 query per call — `?q=reaching_entrypoints&target=<SolidityID>`.

    The graph itself is already served whole; this exists so the UI (and `curl`) can ask
    the questions the Context Builder will ask, without reimplementing traversal in
    TypeScript. Whatever answers here is exactly what an agent would receive.
    """
    query = GraphQuery(_load_graph(run_id))
    handlers: dict[str, object] = {
        "entrypoints": lambda: query.entrypoints(),
        "reaching_entrypoints": lambda: query.reaching_entrypoints(target),
        "entrypoint_paths": lambda: query.entrypoint_paths(target),
        "neighborhood": lambda: sorted(query.neighborhood(target)),
        "callers": lambda: query.callers(target),
        "callees": lambda: query.callees(target),
        "writers_of": lambda: query.writers_of(target),
        "readers_of": lambda: query.readers_of(target),
        "state_reads": lambda: query.state_reads(target),
        "state_writes": lambda: query.state_writes(target),
        "privileged_writes": lambda: query.privileged_writes(),
        "privileged_variables": lambda: query.privileged_variables(),
        "permissions": lambda: query.permissions(target),
        "external_call_paths": lambda: query.external_call_paths(target),
        "external_calls": lambda: query.external_calls(),
        "delegatecall_targets": lambda: query.delegatecall_targets(),
        "reentrancy_candidates": lambda: query.reentrancy_candidates(),
        "token_flows": lambda: query.token_flows(target or None),
        "inheritance": lambda: query.inheritance(target),
        "override_chain": lambda: query.override_chain(target),
        "program_slice": lambda: query.program_slice(target),
        "function_dependencies": lambda: query.function_dependencies(target),
        "variable_dependencies": lambda: query.variable_dependencies(target),
        "centrality": lambda: query.contract_centrality(CENTRALITY_TOP),
        "view": lambda: query.view(target),
    }

    handler = handlers.get(q)
    if handler is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "GRAPH_UNKNOWN_QUERY",
                "message": f"No such query: {q}",
                "hint": f"Known queries: {', '.join(sorted(handlers))}",
            },
        )
    try:
        return {"query": q, "target": target, "result": handler()}  # type: ignore[operator]
    except KeyError as exc:
        raise HTTPException(
            status_code=400, detail={"code": "GRAPH_BAD_TARGET", "message": str(exc)}
        ) from exc


def _load_graph(run_id: str) -> GraphModel:
    artifact = default_run_root() / run_id / "artifacts" / f"{GRAPH_ARTIFACT}.json"
    if not artifact.is_file():
        raise HTTPException(
            status_code=404,
            detail={
                "message": f"Run {run_id} has no graph.",
                "hint": f"POST /audits/{run_id}/graph first.",
            },
        )
    return load_artifact(GraphModel, artifact)


@app.get("/audits/{run_id}/build", response_model=BuildModel)
def get_build(run_id: str) -> BuildModel:
    artifact = default_run_root() / run_id / "artifacts" / f"{BUILD_ARTIFACT}.json"
    if not artifact.is_file():
        raise HTTPException(
            status_code=404, detail={"message": f"Run {run_id} has not been built."}
        )
    return load_artifact(BuildModel, artifact)


@app.get("/audits/{run_id}/ast")
def get_ast(run_id: str, path: str) -> dict:
    """Serve one AST that the build wrote to disk (they are too large to inline)."""
    run_dir = (default_run_root() / run_id).resolve()
    target = (run_dir / path).resolve()
    if not target.is_relative_to(run_dir / "build" / "ast") or not target.is_file():
        raise HTTPException(status_code=404, detail={"message": f"No such AST: {path}"})
    return json.loads(target.read_text(encoding="utf-8"))


def _load_repo(run_id: str) -> RepoModel:
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
