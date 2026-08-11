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

from engine.core.artifacts import save_artifact
from engine.core.errors import AuditOSError
from engine.core.models.repo import ScopeOverride
from engine.graphs.build import build_and_save as build_and_save_graph
from engine.graphs.query import GraphQuery
from engine.ingest.build.pipeline import build_and_save
from engine.ingest.reader import ingest, read_repository
from engine.parse.pipeline import parse_and_save
from engine.protocol.assemble import finalize
from engine.protocol.assemble import save as save_protocol
from engine.protocol.understand import understand


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

    build_cmd = sub.add_parser(
        "build",
        help="Read a repository, then compile it.",
        description="ZIP | folder | git URL → repo.json + build.json",
    )
    build_cmd.add_argument("source", help="a folder, a .zip archive, or a git URL")
    build_cmd.add_argument("--ref", help="git branch, tag or commit (git sources only)")
    build_cmd.add_argument("--run-root", type=Path, help="where run dirs live (default ./run)")
    build_cmd.add_argument("--run-id", help="use a fixed run id instead of a generated one")
    build_cmd.add_argument(
        "--allow-hardhat",
        action="store_true",
        help="permit `npx hardhat compile`, which EXECUTES the target's hardhat.config.js",
    )

    parse_cmd = sub.add_parser(
        "parse",
        help="Read, optionally compile, then parse into a CodeModel.",
        description="ZIP | folder | git URL → repo.json + code.json",
    )
    parse_cmd.add_argument("source", help="a folder, a .zip archive, or a git URL")
    parse_cmd.add_argument("--ref", help="git branch, tag or commit (git sources only)")
    parse_cmd.add_argument("--run-root", type=Path, help="where run dirs live (default ./run)")
    parse_cmd.add_argument("--run-id", help="use a fixed run id instead of a generated one")
    parse_cmd.add_argument(
        "--build",
        action="store_true",
        help="compile first, so storage slots and selectors enrich the CodeModel",
    )

    graph_cmd = sub.add_parser(
        "graph",
        help="Read, parse, then build the code property graph.",
        description="ZIP | folder | git URL → repo.json + code.json + graph.json",
    )
    graph_cmd.add_argument("source", help="a folder, a .zip archive, or a git URL")
    graph_cmd.add_argument("--ref", help="git branch, tag or commit (git sources only)")
    graph_cmd.add_argument("--run-root", type=Path, help="where run dirs live (default ./run)")
    graph_cmd.add_argument("--run-id", help="use a fixed run id instead of a generated one")
    graph_cmd.add_argument(
        "--build",
        action="store_true",
        help="compile first, so storage slots and selectors enrich the graph",
    )

    protocol_cmd = sub.add_parser(
        "protocol",
        help="Read, parse, graph, then interpret into a ProtocolModel.",
        description="ZIP | folder | git URL → repo.json + code.json + graph.json + "
        "protocol.json (no API key required)",
    )
    protocol_cmd.add_argument("source", help="a folder, a .zip archive, or a git URL")
    protocol_cmd.add_argument("--ref", help="git branch, tag or commit (git sources only)")
    protocol_cmd.add_argument("--run-root", type=Path, help="where run dirs live (default ./run)")
    protocol_cmd.add_argument("--run-id", help="use a fixed run id instead of a generated one")
    protocol_cmd.add_argument(
        "--build",
        action="store_true",
        help="compile first, so storage slots and selectors enrich the model",
    )
    protocol_cmd.add_argument(
        "--enrich",
        action="store_true",
        help="answer semantic gaps with an LLM (requires ANTHROPIC_API_KEY or OPENAI_API_KEY); "
        "the model is complete without this",
    )
    protocol_cmd.add_argument(
        "--verify",
        action="store_true",
        help="generate and run Forge invariant tests (requires forge on PATH)",
    )
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


def _cmd_build(args: argparse.Namespace) -> int:
    model, run_dir = read_repository(
        args.source, ref=args.ref, run_root=args.run_root, run_id=args.run_id
    )
    save_artifact(model, run_dir, "repo")
    build, artifact = build_and_save(model, run_dir, allow_hardhat=args.allow_hardhat)
    counts = build.counts

    print(f"Project:  {model.kind.value}   ({model.counts['in_scope']} files in scope)")
    print(f"Builder:  {build.builder}")
    print(f"Status:   {build.status}   (build_available={build.build_available})")
    if build.solc_version_resolved:
        print(f"Compiler: solc {build.solc_version_resolved}")
    print()
    print(f"Sources compiled: {counts['sources']}   (AST: {counts['with_ast']})")
    print(f"Contracts:        {counts['contracts']}   (storage layout: {counts['with_storage']})")
    print(f"Errors:           {counts['errors']}")
    print(f"Warnings:         {counts['warnings']}")
    if counts["oversize"]:
        print(f"Over EIP-170:     {counts['oversize']}")

    for diagnostic in build.errors[:5]:
        location = f"{diagnostic.path}:{diagnostic.line}" if diagnostic.path else "—"
        print(f"\n  error {location}\n    {diagnostic.message.splitlines()[0]}")

    if build.notes:
        print("\nNotes:")
        for note in build.notes:
            print(f"  - {note}")

    print(f"\nBuildModel written to:\n  {artifact}")
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    repo, run_dir = read_repository(
        args.source, ref=args.ref, run_root=args.run_root, run_id=args.run_id
    )
    save_artifact(repo, run_dir, "repo")

    build = None
    if args.build:
        build, _ = build_and_save(repo, run_dir)

    code, artifact = parse_and_save(repo, run_dir, build)
    counts = code.counts

    print(f"Project:  {repo.kind.value}   ({counts['in_scope_contracts']} contracts in scope)")
    print(f"Enriched: {'yes' if code.enriched else 'no (tree-sitter only)'}")
    print()
    print(f"Sources parsed:   {counts['sources']}")
    print(f"Contracts:        {counts['contracts']}"
          f"   (interfaces: {counts['interfaces']}, libraries: {counts['libraries']})")
    print(f"Functions:        {counts['functions']}   (entrypoints: {counts['entrypoints']})")
    print(f"State variables:  {counts['state_vars']}")
    print(f"Modifiers:        {counts['modifiers']}")
    print(f"Parse errors:     {counts['parse_errors']}")

    candidates = [
        f
        for contract in code.in_scope_contracts
        for f in contract.functions
        if f.writes_after_external_call
    ]
    if candidates:
        print(f"\nState written after an external call: {len(candidates)} in-scope functions")
        for function in candidates[:5]:
            print(f"  - {function.id}")
        if len(candidates) > 5:
            print(f"  … and {len(candidates) - 5} more")

    if code.notes:
        print("\nNotes:")
        for note in code.notes:
            print(f"  - {note}")

    print(f"\nCodeModel written to:\n  {artifact}")
    return 0


def _cmd_graph(args: argparse.Namespace) -> int:
    repo, run_dir = read_repository(
        args.source, ref=args.ref, run_root=args.run_root, run_id=args.run_id
    )
    save_artifact(repo, run_dir, "repo")

    build = None
    if args.build:
        build, _ = build_and_save(repo, run_dir)

    code, _ = parse_and_save(repo, run_dir, build)
    graph, artifact = build_and_save_graph(code, run_dir)
    counts = graph.counts
    query = GraphQuery(graph)

    print(f"Nodes: {counts['nodes']}   Edges: {counts['edges']}")
    print(f"Entrypoints: {counts['entrypoints']}")
    print()
    print("Views:")
    for name, summary in graph.views.items():
        print(f"  {name:<12} {summary.edges:>6} edges over {summary.nodes:>5} nodes")

    if graph.reentrancy_candidates:
        print(f"\nReentrancy candidates: {len(graph.reentrancy_candidates)}")
        for candidate in graph.reentrancy_candidates[:5]:
            guard = f"  [guarded by {candidate.guard}]" if candidate.guard else ""
            print(f"  - {candidate.function}{guard}")
            print(f"      via {candidate.external_call} (line {candidate.external_line})")
            print(f"      then writes {', '.join(candidate.writes_after)}")
        if len(graph.reentrancy_candidates) > 5:
            print(f"  … and {len(graph.reentrancy_candidates) - 5} more")

    ranked = list(query.contract_centrality(5).items())
    if ranked:
        print("\nMost central contracts:")
        for contract_id, rank in ranked:
            print(f"  {rank:.4f}  {contract_id}")

    if graph.import_cycles:
        print(f"\nImport cycles: {len(graph.import_cycles)}")

    if graph.notes:
        print("\nNotes:")
        for note in graph.notes:
            print(f"  - {note}")

    print(f"\nGraphModel written to:\n  {artifact}")
    return 0


def _cmd_protocol(args: argparse.Namespace) -> int:
    repo, run_dir = read_repository(
        args.source, ref=args.ref, run_root=args.run_root, run_id=args.run_id
    )
    save_artifact(repo, run_dir, "repo")

    build = None
    if args.build:
        build, _ = build_and_save(repo, run_dir)

    code, _ = parse_and_save(repo, run_dir, build)
    graph, _ = build_and_save_graph(code, run_dir)
    model = understand(code, graph, repo)

    if args.enrich:
        from engine.protocol.enrich import default_provider, enrich

        provider = default_provider()
        if not provider.available:
            print("No LLM provider configured — skipping enrichment.", file=sys.stderr)
        model = finalize(enrich(model, code, provider), code)

    verification = None
    if args.verify:
        from engine.protocol.verify import verify as run_forge

        model, verification = run_forge(model, Path(repo.root), run_dir)
        model = finalize(model, code)

    _, artifact = save_protocol(model, run_dir)
    counts = model.counts

    print(f"Protocol: {model.identity.name}")
    print(f"Archetype: {', '.join(model.archetype) or 'unknown'}")
    print()
    print(f"Contracts classified: {model.coverage.contracts_classified}"
          f"/{model.coverage.contracts_total}")
    print(f"Contracts profiled:   {model.coverage.contracts_profiled}"
          f"/{model.coverage.contracts_total}"
          f"   ({model.coverage.functions_described} function bodies described)")
    print(f"Operations modelled:  {counts['operations']}"
          f"/{model.coverage.entrypoints_total} entrypoints"
          f"   ({len(model.privileged)} privileged)")
    print(f"Actors:               {counts['actors']}")
    print(f"Assets / flows:       {counts['assets']} / {counts['asset_flows']}")
    print(f"State explained:      {model.coverage.state_vars_explained}"
          f"/{model.coverage.state_vars_total}")
    print(f"Dependencies:         {counts['dependencies']}")
    print(f"Candidate invariants: {counts['invariants']}")
    print(f"Risk surfaces:        {counts['risk_surfaces']}")
    print(f"Open questions:       {counts['gaps']}")

    if model.contracts:
        print("\nContract roles:")
        for classification in sorted(model.contracts, key=lambda c: -c.centrality)[:8]:
            print(f"  {classification.role.value:<18} {classification.name}")

    if model.conflicts:
        print(f"\nDocumentation conflicts: {len(model.conflicts)}")
        for rule in model.conflicts[:3]:
            print(f"  - {rule.statement[:90]}")
            print(f"    → {rule.finding[:90]}")

    top = sorted(model.risk_surfaces, key=lambda s: -s.priority)[:5]
    if top:
        print("\nHighest-priority risk surfaces:")
        for surface in top:
            print(f"  {surface.priority:.2f}  {surface.kind.value:<22} {surface.title[:60]}")

    if verification is not None:
        print(
            f"\nForge verification: {verification.passed} passed, "
            f"{verification.failed} REFUTED, {verification.errored} errored, "
            f"{verification.skipped} not mechanically checkable"
        )

    if model.enrichment.applied or model.enrichment.provider not in ("", "none"):
        print(
            f"\nEnrichment ({model.enrichment.provider}): "
            f"{model.enrichment.gaps_answered} answered, "
            f"{model.enrichment.gaps_rejected} rejected"
        )

    histogram = model.confidence_histogram()
    print("\nClaim confidence: " + "  ".join(
        f"{level}={count}" for level, count in histogram.items() if count
    ))

    if model.notes:
        print("\nNotes:")
        for note in model.notes:
            print(f"  - {note}")

    print(f"\nProtocolModel written to:\n  {artifact}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a legacy codepage, which mangles the en/em dashes and
    # arrows in notes and diagnostics into "?". The artifacts are UTF-8 regardless; this
    # just stops the terminal from lying about them.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    args = _build_parser().parse_args(argv)
    try:
        if args.command == "ingest":
            return _cmd_ingest(args)
        if args.command == "build":
            return _cmd_build(args)
        if args.command == "parse":
            return _cmd_parse(args)
        if args.command == "graph":
            return _cmd_graph(args)
        if args.command == "protocol":
            return _cmd_protocol(args)
    except AuditOSError as exc:
        # P6: fail loud, but as a clean message — never a traceback in the user's face.
        print(str(exc), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
