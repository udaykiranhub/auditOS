"""The `graph` CLI command (SPEC §4 hard rule: the engine runs without the frontend)."""

from __future__ import annotations

from pathlib import Path

from engine.__main__ import main


def test_graph_prints_a_summary_and_writes_the_artifact(
    foundry_project: Path, run_root: Path, capsys
):
    exit_code = main(["graph", str(foundry_project), "--run-root", str(run_root)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Nodes:" in out
    assert "Views:" in out
    assert "Most central contracts:" in out
    assert "GraphModel written to:" in out

    written = list(run_root.glob("*/artifacts/graph.json"))
    assert len(written) == 1


def test_graph_reports_reentrancy_candidates(foundry_project: Path, run_root: Path, capsys):
    """The fixture vault writes state after a low-level call — the canonical CEI shape."""
    main(["graph", str(foundry_project), "--run-root", str(run_root)])
    assert "Reentrancy candidates:" in capsys.readouterr().out


def test_a_fatal_error_prints_a_clean_message_not_a_traceback(
    empty_project: Path, run_root: Path, capsys
):
    exit_code = main(["graph", str(empty_project), "--run-root", str(run_root)])
    assert exit_code == 1
    assert "Traceback" not in capsys.readouterr().err
