"""solc enrichment — semantics only, never structure (SPEC §12.1).

| | Tree-sitter | solc |
|---|---|---|
| Works on broken code | ✅ | ❌ |
| Precise types | ❌ | ✅ |
| Storage slots | ❌ | ✅ |

**Rule: tree-sitter is the source of truth for structure; solc enriches semantics.** Never
invert it. If solc becomes primary, the engine breaks on exactly the protocols most likely
to contain bugs — the ones that do not cleanly build.

What is taken from a `BuildModel` here:

* **storage slots and offsets** — the one thing no parser can derive, since packing depends
  on declaration order, inheritance linearization and type sizes;
* **canonical selectors** — `evm.methodIdentifiers` keys are already canonical solc
  signatures, so they confirm that a parsed signature agrees with the compiler's.

A contract solc knows about that tree-sitter missed (or vice versa) is kept as a union and
flagged in `parse_errors`, never silently dropped (SPEC §12.1).
"""

from __future__ import annotations

from engine.core.models.build import BuildModel
from engine.core.models.code import CodeModel, ParseError
from engine.core.models.ids import make_function_id_from_signature


def enrich(code: CodeModel, build: BuildModel | None) -> CodeModel:
    """Apply compiler knowledge to a tree-sitter `CodeModel`. Structure is never changed."""
    if build is None or not build.build_available or not build.contracts:
        code.notes.append("no compiler enrichment: storage slots and selectors unavailable")
        return code

    artifacts = {artifact.id: artifact for artifact in build.contracts}
    slots_applied = 0
    selectors_confirmed = 0

    for contract in code.contracts:
        artifact = artifacts.get(contract.id)
        if artifact is None:
            continue

        # ── Storage slots ────────────────────────────────────────────────────
        by_name = {slot.label: slot for slot in artifact.storage}
        for state_var in contract.state_vars:
            slot = by_name.get(state_var.name)
            if slot is not None:
                state_var.slot = slot.slot
                state_var.offset = slot.offset
                slots_applied += 1

        # ── Selector agreement ───────────────────────────────────────────────
        compiler_ids = {
            make_function_id_from_signature(contract.path, contract.name, signature)
            for signature in artifact.method_identifiers
        }
        parsed_ids = {f.id for f in contract.functions if f.visibility in ("public", "external")}
        selectors_confirmed += len(compiler_ids & parsed_ids)

        for missing in sorted(compiler_ids - parsed_ids):
            # solc sees inherited functions on the derived contract; tree-sitter does not,
            # and should not — SPEC §7.2 addresses a function by its *defining* contract.
            # Only a mismatch on a locally-defined name is worth reporting.
            name = missing.rsplit(".", 1)[-1].split("(")[0]
            if any(f.name == name for f in contract.functions):
                code.parse_errors.append(
                    ParseError(
                        path=contract.path,
                        message=(
                            f"signature mismatch for {name}: the compiler reports "
                            f"{missing.rsplit('.', 1)[-1]}"
                        ),
                        severity="warning",
                    )
                )

    for artifact in build.contracts:
        if artifact.in_scope and code.contract(artifact.id) is None:
            code.parse_errors.append(
                ParseError(
                    path=artifact.path,
                    message=(
                        f"the compiler produced {artifact.name} but the parser did not; "
                        "keeping the union"
                    ),
                    severity="warning",
                )
            )

    code.enriched = True
    code.build_content_hash = build.content_hash
    code.notes.append(
        f"compiler enrichment: {slots_applied} storage slots, "
        f"{selectors_confirmed} selectors confirmed"
    )
    return code
