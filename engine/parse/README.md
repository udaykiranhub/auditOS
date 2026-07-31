# parse/ — Parsing Engine (SPEC §12)

`RepoModel (+ solc AST) → CodeModel`. Makes code **addressable, sliceable, graphable** — not interpretable.

| File           | Purpose |
|----------------|---------|
| `treesitter.py`| source → `CodeModel`. **Primary. Source of truth for structure.** Works on broken code. |
| `solc_ast.py`  | enrichment pass. **Secondary. Source of truth for types + storage slots.** Only if build succeeded. |
| `normalize.py` | merge + canonicalize the two sources into one `CodeModel`. |

## The rule you must never invert (§12.1)

```
CodeModel = normalize( treesitter_parse(files) ⊕ solc_enrich(ast) )
```

**Tree-sitter wins on structure; solc wins on types/slots.** If you make solc primary, the engine
breaks on exactly the protocols most likely to have bugs (the ones that don't cleanly build). If
you skip solc, you lose storage slots and type resolution. Merge conflicts → log WARNING, keep the
union, flag in `parse_errors`. Never silently drop.

## The single biggest scope trap in the project (§12.2)

**Do not attempt full expression-level AST modeling in `CodeModel`.** You will be tempted. Resist.
The LLM reads the raw source; you do not need a symbolic representation of every expression, and
building one is a multi-month detour. Extract only: per-contract name/kind/parents/NatSpec;
per-function signature/visibility/mutability/modifiers/params/returns/**raw text**/line span/`body_hash`;
per-state-var name/type/constant/immutable/visibility/slot(solc only).

## Acceptance (§12.3)

- Golden-file: contract/function counts match hand-labels for the 5 reference protocols.
- Every `Function.id` round-trips through `make_id()` unchanged.
- A deliberately broken `.sol` (missing brace) yields a partial `CodeModel` + a `ParseError`, and does not raise.
