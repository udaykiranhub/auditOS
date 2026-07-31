"""Step 6: documentation discovery (SPEC §9.1).

Locate `README*`, `docs/**/*.md`, `SPEC*` and whitepaper PDFs. For V1 the rule is narrow
and deliberate:

* record **paths** only — PDF parsing is out of scope;
* read the root README's **text**, because Protocol Understanding takes it as a direct
  input (SPEC §8 module contract registry);
* never walk into dependency directories — otherwise a Hardhat project contributes a few
  hundred `node_modules/**/README.md` files that are documentation for someone else's code.
"""

from __future__ import annotations

from pathlib import Path

from engine.ingest.classify import DEFAULT_DEPENDENCY_ROOTS, is_dependency_path

# The README is an LLM input, not an archive. Cap it so a generated 5 MB file cannot
# dominate the artifact or a downstream context budget.
MAX_README_BYTES = 100 * 1024

README_STEMS = ("readme",)
SPEC_STEMS = ("spec", "specification", "whitepaper", "litepaper")
DOC_SUFFIXES = (".md", ".markdown", ".rst", ".txt", ".pdf")


def _is_doc_candidate(rel_path: str) -> bool:
    path = Path(rel_path)
    suffix = path.suffix.lower()
    stem = path.stem.lower()
    parts = [part.lower() for part in path.parts[:-1]]

    if suffix not in DOC_SUFFIXES:
        return False
    if "docs" in parts or "doc" in parts:
        return suffix != ".txt"  # docs/*.txt is usually a licence or a lockfile dump
    if len(path.parts) == 1:  # root level
        return stem.startswith(README_STEMS) or stem.startswith(SPEC_STEMS)
    return False


def discover_docs(
    repo_root: Path,
    dependency_roots: tuple[str, ...] = DEFAULT_DEPENDENCY_ROOTS,
) -> tuple[str | None, list[str]]:
    """Return ``(readme_text, doc_paths)``.

    ``doc_paths`` is sorted and repo-relative; ``readme_text`` is the content of the
    root README, or ``None`` if there isn't one.
    """
    doc_paths: list[str] = []

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if is_dependency_path(rel, dependency_roots):
            continue
        if any(part.startswith(".") for part in Path(rel).parts):
            continue
        if _is_doc_candidate(rel):
            doc_paths.append(rel)

    doc_paths.sort()
    return _read_root_readme(repo_root), doc_paths


def _read_root_readme(repo_root: Path) -> str | None:
    candidates = sorted(
        path
        for path in repo_root.glob("*")
        if path.is_file()
        and path.stem.lower().startswith(README_STEMS)
        and path.suffix.lower() in (".md", ".markdown", ".rst", ".txt", "")
    )
    if not candidates:
        return None

    text = candidates[0].read_text(encoding="utf-8", errors="replace")
    if len(text) > MAX_README_BYTES:
        return text[:MAX_README_BYTES] + "\n\n[... README truncated by AuditOS ...]"
    return text
