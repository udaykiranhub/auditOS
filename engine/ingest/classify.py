"""Step 4: scope classification — the highest-leverage heuristic in the system (SPEC §9.3).

```
is_dependency     ← lib/, node_modules/, vendor/, external/, or a known library package
is_test           ← test/, tests/, script/, *.t.sol, *Test.sol, *.s.sol
is_mock           ← mock/, Mock*, Fake*, Stub*, Harness*  (path or contract name)
is_interface_only ← the file declares only `interface`s

in_scope = NOT dependency AND NOT test AND NOT mock
```

Two rules that this module exists to get right:

**Classify by path first, name second — never by name alone.** A *modified* OpenZeppelin
ERC20 pasted into `src/` is in scope. `src/ERC20.sol` is not a dependency just because of
what it is called.

**Scope is metadata, not a filter.** Nothing here deletes a file. Out-of-scope code is
still parsed and graphed — it is just never audited.

No Solidity parser is used at this phase. Comment- and string-stripping plus conservative
regexes are enough, and they work on code that does not compile.
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

# ── Path signals ──────────────────────────────────────────────────────────────

# Dependency roots, matched against the FIRST path component only. Restricting `lib` to
# the top level is deliberate: `src/lib/Math.sol` is very often the protocol's own helper
# library, not a vendored dependency. Foundry's `libs = [...]` overrides this list.
DEFAULT_DEPENDENCY_ROOTS = ("lib", "node_modules", "vendor", "external")

# These are dependency directories at *any* depth — nested node_modules are real, and a
# `vendor/` folder anywhere means vendored code by definition.
NESTED_DEPENDENCY_DIRS = ("node_modules",)

# Known third-party packages, matched against the first path component or any `@scope`
# component — never against a file name. See the `src/ERC20.sol` rule above.
KNOWN_LIBRARY_TOKENS = (
    "openzeppelin",
    "solmate",
    "solady",
    "forge-std",
    "ds-test",
    "chainlink",
    "uniswap",
    "permit2",
    "layerzero",
    "create3",
    "prb-math",
    "safe-contracts",
    "aave",
)

TEST_DIRS = ("test", "tests", "script", "scripts")
TEST_FILE_GLOBS = ("*.t.sol", "*.s.sol")  # Foundry's naming convention
TEST_AFFIXES = ("test", "script")

MOCK_DIRS = ("mock", "mocks")
MOCK_AFFIXES = ("mock", "fake", "stub", "harness")

# ── Source signals ────────────────────────────────────────────────────────────

_DECLARATION_RE = re.compile(
    r"\b(abstract\s+contract|contract|library|interface)\s+([A-Za-z_$][\w$]*)"
)

# Splits an identifier into CamelCase / snake_case / digit tokens:
# "ERC20Mock" → ERC, 20, Mock   |   "StubbornVault" → Stubborn, Vault
_TOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|\d+")


def strip_comments_and_strings(source: str) -> str:
    """Blank out comments and string literals while preserving line structure.

    Preserving newlines means the result can still be counted for LOC, and it stops
    ``// contract Foo`` or ``"contract Foo"`` from being read as a declaration.
    """
    out: list[str] = []
    i, n = 0, len(source)
    state = "code"

    while i < n:
        char = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if state == "code":
            if char == "/" and nxt == "/":
                state = "line"
                i += 2
            elif char == "/" and nxt == "*":
                state = "block"
                i += 2
            elif char in ('"', "'"):
                state = "dq" if char == '"' else "sq"
                out.append(" ")
                i += 1
            else:
                out.append(char)
                i += 1
        elif state == "line":
            if char == "\n":
                state = "code"
                out.append("\n")
            i += 1
        elif state == "block":
            if char == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                out.append("\n" if char == "\n" else " ")
                i += 1
        else:  # inside a string literal
            quote = '"' if state == "dq" else "'"
            if char == "\\":
                i += 2
            elif char == quote:
                state = "code"
                i += 1
            elif char == "\n":  # unterminated literal — recover at the line break
                state = "code"
                out.append("\n")
                i += 1
            else:
                i += 1

    return "".join(out)


def count_loc(stripped: str) -> int:
    """Lines of *code*: non-blank lines of the comment-stripped source."""
    return sum(1 for line in stripped.splitlines() if line.strip())


def declarations(stripped: str) -> list[tuple[str, str]]:
    """``[(kind, name), ...]`` for every top-level declaration in stripped source.

    ``kind`` is one of ``contract`` | ``abstract`` | ``library`` | ``interface``.
    """
    result: list[tuple[str, str]] = []
    for match in _DECLARATION_RE.finditer(stripped):
        raw = match.group(1)
        kind = "abstract" if raw.startswith("abstract") else raw
        result.append((kind, match.group(2)))
    return result


def has_affix(identifier: str, affixes: tuple[str, ...]) -> bool:
    """Token-aware affix test, in either position.

    ``ERC20Mock`` and ``MockVault`` hit ``mock``; ``StubbornVault`` and ``Testament`` do
    not. Naive prefix/substring matching would classify both of those, which is exactly
    the kind of silent, name-only misclassification SPEC §9.3 warns about.
    """
    return any(token.lower() in affixes for token in _TOKEN_RE.findall(identifier))


def is_interface_only(stripped: str) -> bool:
    """True when the file declares at least one interface and nothing else.

    Conservative on purpose: a file with no recognizable declaration is not an interface.
    """
    decls = declarations(stripped)
    if not decls:
        return False
    kinds = {kind for kind, _ in decls}
    return kinds == {"interface"}


# ── Path helpers ──────────────────────────────────────────────────────────────

def _normalize_component(component: str) -> str:
    return component.lower().lstrip("@").replace("_", "-")


def _matches_known_library(component: str) -> bool:
    normalized = _normalize_component(component)
    return any(token in normalized for token in KNOWN_LIBRARY_TOKENS)


def is_dependency_path(
    rel_path: str,
    dependency_roots: tuple[str, ...] = DEFAULT_DEPENDENCY_ROOTS,
) -> bool:
    """Path-only dependency test — used by scope classification and docs discovery."""
    parts = PurePosixPath(rel_path).parts
    if not parts:
        return False
    directories = parts[:-1]

    if directories and _normalize_component(directories[0]) in {
        _normalize_component(root) for root in dependency_roots
    }:
        return True

    if any(directory in NESTED_DEPENDENCY_DIRS for directory in directories):
        return True

    # A known package name counts only at the top level or as an @scope — never as a
    # sub-directory of the project's own source tree.
    if directories and _matches_known_library(directories[0]):
        return True
    return any(d.startswith("@") and _matches_known_library(d) for d in directories)


def is_test_path(rel_path: str) -> bool:
    path = PurePosixPath(rel_path)
    if any(part.lower() in TEST_DIRS for part in path.parts[:-1]):
        return True
    if any(fnmatchcase(path.name, pattern) for pattern in TEST_FILE_GLOBS):
        return True
    return has_affix(path.name.removesuffix(".sol"), TEST_AFFIXES)


def is_mock_path(rel_path: str) -> bool:
    path = PurePosixPath(rel_path)
    if any(part.lower() in MOCK_DIRS for part in path.parts[:-1]):
        return True
    # `MockERC20.sol` and `ERC20Mock.sol` are equally common; missing either one lets
    # deliberately-broken code into the audit.
    return has_affix(path.name.removesuffix(".sol"), MOCK_AFFIXES)


def has_mock_contract_name(stripped: str) -> bool:
    """Contract-name mock signal, per SPEC §9.3 ('path *or* contract name')."""
    return any(has_affix(name, MOCK_AFFIXES) for _, name in declarations(stripped))


# ── The classification itself ─────────────────────────────────────────────────

def classify(
    rel_path: str,
    stripped_source: str,
    dependency_roots: tuple[str, ...] = DEFAULT_DEPENDENCY_ROOTS,
) -> dict[str, bool]:
    """Classify one Solidity file. Path signals first, source signals second."""
    is_dependency = is_dependency_path(rel_path, dependency_roots)
    is_test = is_test_path(rel_path)
    is_mock = is_mock_path(rel_path) or has_mock_contract_name(stripped_source)

    return {
        "is_dependency": is_dependency,
        "is_test": is_test,
        "is_mock": is_mock,
        "is_interface_only": is_interface_only(stripped_source),
        "in_scope": not (is_dependency or is_test or is_mock),
    }


def scope_reason(flags: dict[str, bool]) -> str:
    """A short, deterministic explanation of the scope decision."""
    reasons = [
        key.removeprefix("is_")
        for key in ("is_dependency", "is_test", "is_mock")
        if flags[key]
    ]
    return "excluded: " + ", ".join(reasons) if reasons else "in scope"


def apply_scope_override(
    rel_path: str,
    in_scope: bool,
    include: list[str],
    exclude: list[str],
) -> tuple[bool, str | None]:
    """Apply the user's escape hatch. ``exclude`` wins over ``include`` (SPEC §9.3).

    Patterns are case-sensitive fnmatch globs over the repo-relative POSIX path.
    ``fnmatchcase`` — not ``fnmatch`` — because ``fnmatch`` normalizes case on Windows,
    which would make classification differ between machines and break determinism.
    """
    if any(fnmatchcase(rel_path, pattern) for pattern in exclude):
        return False, "excluded: scope_override"
    if any(fnmatchcase(rel_path, pattern) for pattern in include):
        return True, "in scope: scope_override"
    return in_scope, None
