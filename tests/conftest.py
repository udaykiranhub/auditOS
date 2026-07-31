"""Shared test fixtures.

`pythonpath = [".."]` in `engine/pyproject.toml` puts the repository root on `sys.path`;
the block below adds a belt to that brace so the suite also runs when invoked from
elsewhere.

Protocols are built on disk rather than checked in, so each test states exactly the
structure it depends on and nothing else. Living at the root of `tests/` makes them
available to every subdirectory without duplication.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def run_root(tmp_path: Path) -> Path:
    """An isolated run root, so tests never write into the real ./run directory."""
    root = tmp_path / "run"
    root.mkdir()
    return root


VAULT_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "./IERC20.sol";

/// @notice A vault. The comment mentions the word contract on purpose.
contract Vault {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "contract");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balance[msg.sender] -= amount;
    }
}
"""

IERC20_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}
"""

TEST_SOL = """\
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

contract VaultTest is Test {
    function testDeposit() public {}
}
"""

MOCK_SOL = """\
pragma solidity ^0.8.20;

contract MockOracle {
    function price() external pure returns (uint256) { return 1e18; }
}
"""

OZ_ERC20_SOL = """\
pragma solidity ^0.8.20;

contract ERC20 {
    function totalSupply() external view returns (uint256) {}
}
"""

FOUNDRY_TOML = """\
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.28"
remappings = ["forge-std/=lib/forge-std/src/"]
"""

HARDHAT_CONFIG_JS = """\
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  paths: { sources: "contracts" },
};
"""


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


@pytest.fixture
def foundry_project(tmp_path: Path) -> Path:
    """A representative Foundry protocol: source, interface, test, mock, dependency."""
    root = tmp_path / "foundry-protocol"
    write(root, "foundry.toml", FOUNDRY_TOML)
    write(root, "remappings.txt", "@openzeppelin/=lib/openzeppelin-contracts/\n")
    write(root, "README.md", "# Vault\n\nAn ERC4626-ish vault.\n")
    write(root, "docs/architecture.md", "# Architecture\n")
    write(root, "src/Vault.sol", VAULT_SOL)
    write(root, "src/IERC20.sol", IERC20_SOL)
    write(root, "src/ERC20.sol", OZ_ERC20_SOL)  # a *modified* library copy — in scope
    write(root, "test/Vault.t.sol", TEST_SOL)
    write(root, "test/mocks/MockOracle.sol", MOCK_SOL)
    write(root, "script/Deploy.s.sol", "pragma solidity ^0.8.20;\ncontract Deploy {}\n")
    write(root, "lib/forge-std/src/Test.sol", "pragma solidity ^0.8.20;\ncontract Test {}\n")
    write(
        root,
        "lib/openzeppelin-contracts/contracts/token/ERC20.sol",
        OZ_ERC20_SOL,
    )
    write(root, "lib/openzeppelin-contracts/README.md", "# OpenZeppelin\n")
    return root


@pytest.fixture
def hardhat_project(tmp_path: Path) -> Path:
    root = tmp_path / "hardhat-protocol"
    write(root, "hardhat.config.js", HARDHAT_CONFIG_JS)
    write(root, "package.json", '{"devDependencies": {"hardhat": "^2.22.0"}}\n')
    write(root, "contracts/Vault.sol", VAULT_SOL)
    write(root, "contracts/IERC20.sol", IERC20_SOL)
    write(root, "test/Vault.test.sol", TEST_SOL)
    write(
        root,
        "node_modules/@openzeppelin/contracts/token/ERC20.sol",
        OZ_ERC20_SOL,
    )
    return root


@pytest.fixture
def raw_project(tmp_path: Path) -> Path:
    root = tmp_path / "raw-protocol"
    write(root, "Vault.sol", VAULT_SOL)
    write(root, "IERC20.sol", IERC20_SOL)
    return root


@pytest.fixture
def empty_project(tmp_path: Path) -> Path:
    root = tmp_path / "not-solidity"
    write(root, "README.md", "# No contracts here\n")
    write(root, "main.py", "print('hello')\n")
    return root
