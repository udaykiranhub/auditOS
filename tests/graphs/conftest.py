"""Source → `GraphModel`, in one call.

The graph is only as good as the parse behind it, so these tests run the real pipeline
(reader → parser → graph) rather than hand-assembling a `CodeModel`. A hand-built input
would let the graph pass on assumptions the parser does not actually satisfy — which is
precisely the failure mode SPEC warns about for the call graph.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.core.models.graph import GraphModel
from engine.graphs import build_graph
from engine.graphs.query import GraphQuery
from engine.ingest.reader import read_repository
from engine.parse.pipeline import parse_repository


def build_from_sources(
    tmp_path: Path, sources: dict[str, str], *, name: str = "protocol"
) -> GraphModel:
    root = tmp_path / name
    for rel, text in sources.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    if not (root / "foundry.toml").exists():
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n', encoding="utf-8"
        )

    repo, _ = read_repository(root, run_root=tmp_path / f"{name}-run")
    return build_graph(parse_repository(repo))


@pytest.fixture
def graph_of(tmp_path: Path):
    """`graph_of({"src/A.sol": "..."})` → GraphModel."""
    counter = {"n": 0}

    def factory(sources: dict[str, str]) -> GraphModel:
        counter["n"] += 1
        return build_from_sources(tmp_path, sources, name=f"protocol{counter['n']}")

    return factory


@pytest.fixture
def query_of(graph_of):
    def factory(sources: dict[str, str]) -> GraphQuery:
        return GraphQuery(graph_of(sources))

    return factory


# ── Shared sources ────────────────────────────────────────────────────────────

PRAGMA = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"

VAULT = (
    PRAGMA
    + """
import {Ownable} from "./Ownable.sol";
import {IERC20} from "./IERC20.sol";

contract Vault is Ownable {
    IERC20 public token;
    mapping(address => uint256) public balance;
    uint256 public total;
    address public oracle;

    event Withdrawn(address who, uint256 amount);
    error TooMuch();

    modifier nonReentrant() { _; }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balance[msg.sender] += amount;
        _bump(amount);
    }

    function withdraw(uint256 amount) external {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balance[msg.sender] -= amount;
        total -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function safeWithdraw(uint256 amount) external nonReentrant {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        total -= amount;
    }

    function setOracle(address o) external onlyOwner { oracle = o; }

    function _bump(uint256 amount) internal { total += amount; }

    function unreachable() private { total = 0; }
}
"""
)

OWNABLE = (
    PRAGMA
    + """
contract Ownable {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function transferOwnership(address n) public virtual onlyOwner { owner = n; }
}
"""
)

IERC20 = (
    PRAGMA
    + """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address f, address t, uint256 a) external returns (bool);
}
"""
)

PROTOCOL = {"src/Vault.sol": VAULT, "src/Ownable.sol": OWNABLE, "src/IERC20.sol": IERC20}

VAULT_ID = "src/Vault.sol:Vault"
WITHDRAW = f"{VAULT_ID}.withdraw(uint256)"
DEPOSIT = f"{VAULT_ID}.deposit(uint256)"
BUMP = f"{VAULT_ID}._bump(uint256)"
TOTAL = f"{VAULT_ID}#total"
