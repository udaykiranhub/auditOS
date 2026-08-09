"""Solidity fixtures the detector tests run against.

Real sources rather than hand-built `CodeModel`s, for the same reason the graph tests use
the real pipeline: a hand-assembled input lets a detector pass on assumptions the parser
does not actually satisfy, which is precisely the failure the Protocol Model exists to
prevent.
"""

from __future__ import annotations

IERC20 = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

#: The worked example from the Protocol Model design note. Intentionally *not* ERC-4626:
#: it has deposit and withdraw and nothing else, which is the "looks similar ≠ compliant"
#: case the standards detector must refuse.
SIMPLE_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "./IERC20.sol";

/// @notice A minimal vault. Every share must represent a proportional claim on assets.
contract SimpleVault {
    IERC20 public asset;

    uint256 public totalAssets;
    uint256 public totalShares;

    mapping(address => uint256) public shares;

    address public owner;

    event Deposited(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(IERC20 _asset) {
        asset = _asset;
        owner = msg.sender;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        asset.transferFrom(msg.sender, address(this), amount);

        shares[msg.sender] += amount;
        totalAssets += amount;
        totalShares += amount;

        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");

        shares[msg.sender] -= amount;
        totalShares -= amount;
        totalAssets -= amount;

        asset.transfer(msg.sender, amount);
    }

    function convertToAssets(uint256 shareAmount) public view returns (uint256) {
        return shareAmount * totalAssets / totalShares;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"""

#: A lending market with an oracle dependency, a liquidator path and an admin-set parameter.
#: Exercises the actor ladder (untrusted / semi-trusted / trusted) in one file.
LENDING = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "./IERC20.sol";

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract LendingMarket {
    IERC20 public collateralToken;
    IPriceOracle public oracle;

    uint256 public totalBorrows;
    uint256 public borrowIndex;
    uint256 public liquidationThreshold;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function supply(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice(address(collateralToken));
        require(collateral[msg.sender] * price >= amount * liquidationThreshold, "unhealthy");
        debt[msg.sender] += amount;
        totalBorrows += amount;
        collateralToken.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        debt[msg.sender] -= amount;
        totalBorrows -= amount;
    }

    function liquidate(address user, uint256 amount) external {
        uint256 price = oracle.getPrice(address(collateralToken));
        require(collateral[user] * price < debt[user] * liquidationThreshold, "healthy");
        debt[user] -= amount;
        collateral[user] -= amount;
        collateralToken.transfer(msg.sender, amount);
    }

    function setLiquidationThreshold(uint256 value) external onlyAdmin {
        liquidationThreshold = value;
    }
}
"""

#: A token that is genuinely ERC-20 compliant, so the detector has a positive case — and one
#: whose `transfer` returns nothing, so it has a DIVERGENT case.
GOOD_TOKEN = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GoodToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

BAD_TOKEN = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SloppyToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    // No return value — the USDT-style divergence.
    function transfer(address to, uint256 amount) public {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

VAULT_PROJECT = {
    "src/IERC20.sol": IERC20,
    "src/SimpleVault.sol": SIMPLE_VAULT,
}

LENDING_PROJECT = {
    "src/IERC20.sol": IERC20,
    "src/LendingMarket.sol": LENDING,
}

TOKEN_PROJECT = {
    "src/GoodToken.sol": GOOD_TOKEN,
    "src/SloppyToken.sol": BAD_TOKEN,
}
