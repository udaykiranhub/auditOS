"""Stage 12a — the semantic graph: contracts, functions, quantities and their relations.

Built AST-first from what the compiler enrichment stage already produced, degrading to
`CodeModel` and source text when a repository does not compile.
"""

from engine.protocol.semantic.solc_ast import AstIndex, load

__all__ = ["AstIndex", "load"]
