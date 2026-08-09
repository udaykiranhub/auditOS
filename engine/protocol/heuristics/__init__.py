"""Deterministic detectors — one module per stage, no LLM anywhere in this package.

```
signatures.py   the shared index every detector reads from
standards.py    3   ERC-20 / 4626 / 721 / proxies / access control
roles.py        2+1 contract roles → protocol archetype → components
actors.py       4   who can act, and with what authority
boundaries.py   5   where trust domains meet
assets.py       6   what has value
flows.py        7   who sends what to whom
operations.py   8   externally callable actions in protocol terms
state.py        9+10 what storage means, and how each operation moves it
dependencies.py 11  what outside this repo correctness rests on
accounting.py   12  the numbers, and how they relate
economics.py    13  where value is created, lost, or redistributed
docs.py         14  what the documentation claims, and whether code agrees
invariants.py   15  candidate invariants and the assumptions under them
gaps.py         16  the questions this pass could not answer
summary.py          the model rendered as prose
```

Every detector is a pure function of its inputs and emits `Claim`s carrying evidence. None
of them may raise on unusual input: a protocol we understand poorly must produce a sparse
model, never a crash, because `Coverage` is how that outcome is reported honestly.
"""

from __future__ import annotations

from engine.protocol.heuristics.signatures import ProtocolIndex

__all__ = ["ProtocolIndex"]
