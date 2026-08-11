"""Protocol Understanding — the semantic layer (SPEC §7.6, §8).

```
RepoModel + CodeModel + GraphModel + docs  →  ProtocolModel
```

**Phase A (this commit) is the foundation only.** The schema, the evidence and confidence
model, the ID scheme, canonical ordering, validation and serialization — everything the
seventeen stages need in order to have somewhere to put their answers. The detectors that
produce those answers land in Phase B onward, in `heuristics/`.

The deliberate architectural bet, stated once here: **V1 produces a complete
`ProtocolModel` with no API key.** Stages 1–15 are deterministic heuristics over
`CodeModel` and `GraphModel`; what they cannot answer becomes a `SemanticGap` rather than a
guess, and Phase H answers those specific questions with small contexts and validated
evidence. That ordering is what makes it possible to measure whether the model helps —
a deterministic model and an enriched one can be diffed. Building AI in at the root would
make that comparison impossible and every regression unattributable.
"""

from __future__ import annotations

from engine.core.models.protocol import ARTIFACT_NAME, ProtocolModel
from engine.protocol.assemble import finalize, load, measure, new_model, save
from engine.protocol.order import canonicalize
from engine.protocol.query import ProtocolQuery, ProtocolSlice
from engine.protocol.validate import ProtocolCode, validate

__all__ = [
    "ARTIFACT_NAME",
    "ProtocolCode",
    "ProtocolModel",
    "ProtocolQuery",
    "ProtocolSlice",
    "canonicalize",
    "finalize",
    "load",
    "measure",
    "new_model",
    "save",
    "validate",
]
