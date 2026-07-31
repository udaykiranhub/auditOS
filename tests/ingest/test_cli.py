"""The `python -m engine ingest` entry point (SPEC §4: the engine runs without a frontend)."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.__main__ import main


def test_ingest_prints_a_summary_and_writes_the_artifact(
    foundry_project: Path, run_root: Path, capsys
):
    exit_code = main(["ingest", str(foundry_project), "--run-root", str(run_root)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Project: FOUNDRY" in out
    assert "Solidity files: 8" in out
    assert "In scope:       3" in out
    assert "repo.json" in out

    artifacts = list(run_root.rglob("repo.json"))
    assert len(artifacts) == 1


def test_scope_override_flags_are_wired_through(foundry_project: Path, run_root: Path, capsys):
    main(
        [
            "ingest",
            str(foundry_project),
            "--run-root",
            str(run_root),
            "--exclude",
            "src/ERC20.sol",
        ]
    )
    assert "In scope:       2" in capsys.readouterr().out


def test_a_fatal_error_prints_a_clean_message_not_a_traceback(
    empty_project: Path, run_root: Path, capsys
):
    exit_code = main(["ingest", str(empty_project), "--run-root", str(run_root)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "INGEST_NO_SOLIDITY_FILES" in captured.err
    assert "Traceback" not in captured.err


def test_unknown_source_exits_with_the_argparse_error(run_root: Path):
    with pytest.raises(SystemExit):
        main(["nonsense"])
