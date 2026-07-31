"""AuditOS CLI.

```
python -m engine ingest <path | zip | git-url>
```

Phase 1 exposes exactly one subcommand: `ingest`, the Repository Reader. The engine must
be usable entirely from a CLI with no frontend running (SPEC §4, hard rule).

`argparse` rather than Typer: the Repository Reader has no third-party dependencies beyond
Pydantic and GitPython, and this keeps it that way. Typer stays the declared choice for
the full CLI once there is more than one subcommand to justify it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from engine.core.errors import AuditOSError
from engine.core.models.repo import ScopeOverride
from engine.ingest.reader import ingest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m engine",
        description="AuditOS — AI smart-contract security engine.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ingest_cmd = sub.add_parser(
        "ingest",
        help="Read a Solidity repository into a RepoModel.",
        description="ZIP | folder | git URL → run/<run_id>/artifacts/repo.json",
    )
    ingest_cmd.add_argument("source", help="a folder, a .zip archive, or a git URL")
    ingest_cmd.add_argument("--ref", help="git branch, tag or commit (git sources only)")
    ingest_cmd.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="GLOB",
        help="force these paths in scope (repeatable)",
    )
    ingest_cmd.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="force these paths out of scope (repeatable); wins over --include",
    )
    ingest_cmd.add_argument("--run-root", type=Path, help="where run dirs live (default ./run)")
    ingest_cmd.add_argument("--run-id", help="use a fixed run id instead of a generated one")
    return parser


def _cmd_ingest(args: argparse.Namespace) -> int:
    model, artifact = ingest(
        args.source,
        ref=args.ref,
        scope_override=ScopeOverride(include=args.include, exclude=args.exclude),
        run_root=args.run_root,
        run_id=args.run_id,
    )
    counts = model.counts

    print(f"Project: {model.kind.value}   (origin: {model.origin})")
    if model.solidity_version:
        print(f"Solidity: {model.solidity_version}  [{model.solidity_version_source}]")
    print()
    print(f"Solidity files: {counts['total']}")
    print(f"In scope:       {counts['in_scope']}")
    print(f"Tests:          {counts['tests']}")
    print(f"Mocks:          {counts['mocks']}")
    print(f"Dependencies:   {counts['dependencies']}")
    print(f"Interfaces:     {counts['interfaces']}")
    if model.remappings:
        print(f"Remappings:     {len(model.remappings)}")
    if model.docs:
        print(f"Docs:           {len(model.docs)}")

    if model.notes:
        print("\nNotes:")
        for note in model.notes:
            print(f"  - {note}")

    print(f"\ncontent_hash: {model.content_hash}")
    print(f"RepoModel written to:\n  {artifact}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "ingest":
            return _cmd_ingest(args)
    except AuditOSError as exc:
        # P6: fail loud, but as a clean message — never a traceback in the user's face.
        print(str(exc), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
