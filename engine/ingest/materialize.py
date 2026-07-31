"""Step 1 of the Repository Reader: get the input onto disk, safely (SPEC §9.1).

```
ZIP bytes | local folder | git URL (+ optional ref)  →  run/<run_id>/repo/
```

Three rules that are not negotiable:

* **ZIP** — extract with zip-slip protection. Reject any entry whose resolved path escapes
  the extraction root. Reject oversized or entry-bombed archives with a ``FatalError``,
  never a raw traceback.
* **Git** — shallow clone. Foundry dependencies *are* git submodules, so they must be
  initialized — but only after the project kind is known, which is why submodule init is a
  separate function the reader calls post-detection.
* **Folder** — copy, never symlink. The run must be immutable against user edits mid-run.
"""

from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from engine.core.errors import FatalError, IngestCode
from engine.core.models.repo import Origin

# ── Limits (SPEC §9.1) ────────────────────────────────────────────────────────
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024  # 200 MB, compressed *and* uncompressed
MAX_ARCHIVE_ENTRIES = 20_000

# Directories never worth copying: regenerable build output or VCS metadata.
# NOTE: node_modules is deliberately NOT here — Hardhat projects import Solidity
# from it, so dropping it would break compilation and inheritance resolution.
COPY_IGNORE = shutil.ignore_patterns(
    ".git",
    ".venv",
    "__pycache__",
    "out",
    "cache",
    "artifacts",
    ".vite",
    "dist",
    "coverage",
    ".DS_Store",
)

GIT_URL_PREFIXES = ("http://", "https://", "git://", "ssh://", "file://", "git@")


def classify_source(source: str | Path) -> Origin:
    """Return the origin (``zip`` | ``folder`` | ``git``) for a raw user input."""
    text = str(source).strip()
    if text.startswith(GIT_URL_PREFIXES) or text.endswith(".git"):
        return "git"
    path = Path(text)
    if path.is_dir():
        return "folder"
    if path.is_file() and path.suffix.lower() == ".zip":
        return "zip"
    if not path.exists():
        raise FatalError(
            f"Input not found: {text}",
            code=IngestCode.SOURCE_NOT_FOUND,
            hint="Pass a directory, a .zip file, or a git URL.",
        )
    raise FatalError(
        f"Unsupported input: {text}",
        code=IngestCode.UNSUPPORTED_SOURCE,
        hint="Supported origins are: folder, .zip archive, git URL.",
    )


# ── Folder ────────────────────────────────────────────────────────────────────

def materialize_folder(source: Path, dest: Path) -> None:
    """Copy a local folder into the run directory. Copy — never symlink."""
    source = source.resolve()
    dest_resolved = dest.resolve()
    if dest_resolved == source or dest_resolved.is_relative_to(source):
        raise FatalError(
            "The run directory is inside the source folder; that would recurse.",
            code=IngestCode.COPY_FAILED,
            hint="Set AUDITOS_RUN_DIR to a location outside the project being audited.",
        )
    try:
        # symlinks=True copies links as links rather than following them, which avoids
        # both symlink loops and accidentally pulling in gigabytes from outside the repo.
        shutil.copytree(source, dest, dirs_exist_ok=True, symlinks=True, ignore=COPY_IGNORE)
    except OSError:
        # Windows refuses to create symlinks without developer mode / elevation. Fall
        # back to following them; repos containing symlinks are rare on this platform.
        shutil.copytree(source, dest, dirs_exist_ok=True, symlinks=False, ignore=COPY_IGNORE)


# ── ZIP ───────────────────────────────────────────────────────────────────────

def _is_unsafe_member(name: str) -> bool:
    """Reject absolute paths, drive letters, and any ``..`` traversal before extracting."""
    normalized = name.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        return True
    if len(normalized) > 1 and normalized[1] == ":":  # C:/... on a Windows-authored zip
        return True
    return any(part == ".." for part in PurePosixPath(normalized).parts)


def materialize_zip(source: Path, dest: Path) -> None:
    """Extract a ZIP with zip-slip, size and entry-count protection."""
    archive_size = source.stat().st_size
    if archive_size > MAX_ARCHIVE_BYTES:
        raise FatalError(
            f"Archive is {archive_size / 1e6:.1f} MB; the limit is "
            f"{MAX_ARCHIVE_BYTES / 1e6:.0f} MB.",
            code=IngestCode.ZIP_TOO_LARGE,
        )

    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()

    try:
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()

            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise FatalError(
                    f"Archive has {len(infos)} entries; the limit is "
                    f"{MAX_ARCHIVE_ENTRIES}.",
                    code=IngestCode.ZIP_TOO_MANY_ENTRIES,
                )

            # Uncompressed total, checked *before* writing a single byte. The compressed
            # size check above is not enough on its own — that is exactly what a zip bomb
            # defeats.
            uncompressed = sum(info.file_size for info in infos)
            if uncompressed > MAX_ARCHIVE_BYTES:
                raise FatalError(
                    f"Archive expands to {uncompressed / 1e6:.1f} MB; the limit is "
                    f"{MAX_ARCHIVE_BYTES / 1e6:.0f} MB.",
                    code=IngestCode.ZIP_TOO_LARGE,
                )

            for info in infos:
                if _is_unsafe_member(info.filename):
                    raise FatalError(
                        f"Archive entry escapes the extraction root: {info.filename!r}",
                        code=IngestCode.ZIP_SLIP,
                        hint="The archive is malformed or malicious; it was not extracted.",
                    )

                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise FatalError(
                        f"Archive contains a symlink entry: {info.filename!r}",
                        code=IngestCode.ZIP_UNSAFE_ENTRY,
                        hint="Symlinks in archives can redirect writes outside the run dir.",
                    )

                target = (dest_resolved / info.filename).resolve()
                if not target.is_relative_to(dest_resolved):
                    # Belt to the brace above: catches traversal that only appears once
                    # the path is resolved (e.g. via a preceding component).
                    raise FatalError(
                        f"Archive entry escapes the extraction root: {info.filename!r}",
                        code=IngestCode.ZIP_SLIP,
                    )

            archive.extractall(dest_resolved)
    except zipfile.BadZipFile as exc:
        raise FatalError(
            f"Not a readable ZIP archive: {source.name}",
            code=IngestCode.ZIP_INVALID,
        ) from exc

    _flatten_single_root(dest_resolved)


def _flatten_single_root(dest: Path) -> None:
    """Unwrap the ubiquitous ``project-main/`` wrapper directory GitHub ZIPs contain.

    Without this, every repo-relative path is prefixed with a directory name that is an
    artifact of the download, not of the project — which would break scope heuristics
    that key on the first path component.
    """
    children = list(dest.iterdir())
    if len(children) != 1 or not children[0].is_dir():
        return
    wrapper = children[0]
    for item in list(wrapper.iterdir()):
        shutil.move(str(item), str(dest / item.name))
    wrapper.rmdir()


# ── Git ───────────────────────────────────────────────────────────────────────

def materialize_git(url: str, dest: Path, ref: str | None = None) -> list[str]:
    """Shallow-clone a repository. Returns any notes worth recording on the model."""
    from git import GitCommandError, Repo  # imported lazily — keeps folder/zip paths free of it

    notes: list[str] = []
    dest.mkdir(parents=True, exist_ok=True)

    try:
        if ref:
            try:
                Repo.clone_from(url, dest, depth=1, branch=ref, single_branch=True)
            except GitCommandError:
                # `--depth 1 --branch` only works for branch/tag names. A commit SHA needs
                # real history, so pay for a full clone and check it out.
                notes.append(f"ref {ref!r} is not a branch or tag; performed a full clone")
                repo = Repo.clone_from(url, dest)
                repo.git.checkout(ref)
        else:
            Repo.clone_from(url, dest, depth=1)
    except GitCommandError as exc:
        raise FatalError(
            f"git clone failed for {url}",
            code=IngestCode.GIT_CLONE_FAILED,
            hint=(exc.stderr or "").strip() or None,
        ) from exc

    return notes


def init_submodules(repo_root: Path) -> list[str]:
    """Initialize submodules — called only after the project is known to be Foundry.

    Foundry dependencies *are* submodules, so skipping this breaks the build. It runs
    post-detection because you cannot know the project kind until the repo is on disk.
    Failure is degraded, not fatal: a missing dependency costs compilation, not the audit.
    """
    from git import Repo

    if not (repo_root / ".gitmodules").exists():
        return []
    try:
        Repo(repo_root).git.submodule("update", "--init", "--recursive", "--depth", "1")
        return ["initialized git submodules (Foundry dependencies)"]
    except Exception as exc:  # GitPython raises a wide family; degradation is the point
        return [f"submodule init failed ({type(exc).__name__}); dependencies may be missing"]


def strip_git_metadata(repo_root: Path) -> None:
    """Remove ``.git`` after cloning. The run is a snapshot, not a working copy."""
    for git_dir in sorted(repo_root.rglob(".git")):
        if git_dir.is_file():  # submodule pointer file
            git_dir.unlink(missing_ok=True)
            continue
        # Git packs objects read-only; Windows refuses to unlink those until chmod'd.
        for child in git_dir.rglob("*"):
            try:
                child.chmod(stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
        shutil.rmtree(git_dir, ignore_errors=True)


def materialize(
    source: str | Path,
    repo_dest: Path,
    ref: str | None = None,
) -> tuple[Origin, list[str]]:
    """Dispatch on origin. Returns ``(origin, notes)``; the repo lands in ``repo_dest``."""
    origin = classify_source(source)
    notes: list[str] = []

    if origin == "folder":
        materialize_folder(Path(source), repo_dest)
    elif origin == "zip":
        materialize_zip(Path(source), repo_dest)
    else:
        notes += materialize_git(str(source), repo_dest, ref)

    return origin, notes
