"""The `SimpleVault` from the Protocol Model design note, hand-assembled.

Phase A ships no detectors, so there is nothing yet that can *produce* a populated
`ProtocolModel`. Building one by hand is therefore the only way to test the foundation —
and it doubles as the worked example the schema was designed against: if expressing this
vault is awkward, the schema is wrong.

```solidity
contract SimpleVault {
    IERC20 public asset;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit(uint256 amount) external { ... }
    function withdraw(uint256 amount) external { ... }
}
```
"""

from __future__ import annotations

import pytest

from engine.core.models.evidence import (
    Confidence,
    graph_evidence,
    heuristic_evidence,
    source_evidence,
)
from engine.core.models.ids import (
    make_contract_id,
    make_function_id,
    make_state_var_id,
)
from engine.core.models.protocol import (
    Accounting,
    AccountingQuantity,
    AccountingRelation,
    Actor,
    ActorKind,
    Archetype,
    ArchetypeClaim,
    Asset,
    AssetFlow,
    AssetKind,
    Capability,
    ContractClassification,
    ContractRole,
    RoleAssignment,
    FlowKind,
    Invariant,
    InvariantKind,
    Operation,
    OperationKind,
    ProtocolIdentity,
    ProtocolModel,
    RelationKind,
    StateItem,
    StateRole,
    StateTransition,
    TransitionEffect,
    TrustBoundary,
    TrustLevel,
)
from engine.protocol import ids

PATH = "src/SimpleVault.sol"
VAULT = make_contract_id(PATH, "SimpleVault")
DEPOSIT = make_function_id(PATH, "SimpleVault", "deposit", ["uint256"])
WITHDRAW = make_function_id(PATH, "SimpleVault", "withdraw", ["uint256"])
TOTAL_ASSETS = make_state_var_id(PATH, "SimpleVault", "totalAssets")
TOTAL_SHARES = make_state_var_id(PATH, "SimpleVault", "totalShares")
USER_SHARES = make_state_var_id(PATH, "SimpleVault", "shares")


def simple_vault_model() -> ProtocolModel:
    """A small but *complete* protocol model: every stage 1–15 represented at least once."""
    user = Actor(
        id=ids.make_actor_id("user"),
        kind=ActorKind.USER,
        trust=TrustLevel.UNTRUSTED,
        confidence=Confidence.DERIVED,
        evidence=[source_evidence(DEPOSIT, "external, unguarded")],
        capabilities=[
            Capability(
                function_id=DEPOSIT,
                description="supply assets, receive shares",
                confidence=Confidence.DERIVED,
                evidence=[source_evidence(DEPOSIT)],
            ),
            Capability(
                function_id=WITHDRAW,
                description="burn shares, receive assets",
                confidence=Confidence.DERIVED,
                evidence=[source_evidence(WITHDRAW)],
            ),
        ],
    )

    role = ContractClassification(
        id=ids.make_role_id(VAULT),
        contract_id=VAULT,
        name="SimpleVault",
        roles=[
            RoleAssignment(
                role=ContractRole.VAULT,
                score=0.85,
                confidence=Confidence.INFERRED,
                evidence=[
                    heuristic_evidence("vault_deposit_withdraw", "deposit + withdraw + totals")
                ],
            )
        ],
        holds_funds=True,
        is_entry_contract=True,
        confidence=Confidence.INFERRED,
        evidence=[heuristic_evidence("vault_deposit_withdraw", "deposit + withdraw + totals")],
    )

    underlying = Asset(
        id=ids.make_asset_id("asset", ref=VAULT),
        symbol="asset",
        kind=AssetKind.ERC20,
        is_external=True,
        confidence=Confidence.DERIVED,
        evidence=[source_evidence(make_state_var_id(PATH, "SimpleVault", "asset"))],
    )
    shares = Asset(
        id=ids.make_asset_id("shares", ref=VAULT),
        symbol="shares",
        kind=AssetKind.SHARE,
        is_protocol_issued=True,
        backing_asset_id=underlying.id,
        state_var_ids=[USER_SHARES, TOTAL_SHARES],
        confidence=Confidence.DERIVED,
        evidence=[source_evidence(USER_SHARES)],
    )

    state = [
        StateItem(
            id=ids.make_state_id(TOTAL_ASSETS),
            state_var_id=TOTAL_ASSETS,
            contract_id=VAULT,
            name="totalAssets",
            type="uint256",
            role=StateRole.ACCOUNTING_TOTAL,
            asset_id=underlying.id,
            writers=[DEPOSIT, WITHDRAW],
            is_critical=True,
            confidence=Confidence.DERIVED,
            evidence=[graph_evidence(DEPOSIT, "writes", TOTAL_ASSETS)],
        ),
        StateItem(
            id=ids.make_state_id(TOTAL_SHARES),
            state_var_id=TOTAL_SHARES,
            contract_id=VAULT,
            name="totalShares",
            type="uint256",
            role=StateRole.SHARE_SUPPLY,
            asset_id=shares.id,
            writers=[DEPOSIT, WITHDRAW],
            is_critical=True,
            confidence=Confidence.DERIVED,
            evidence=[graph_evidence(DEPOSIT, "writes", TOTAL_SHARES)],
        ),
        StateItem(
            id=ids.make_state_id(USER_SHARES),
            state_var_id=USER_SHARES,
            contract_id=VAULT,
            name="shares",
            type="mapping(address => uint256)",
            role=StateRole.USER_BALANCE,
            asset_id=shares.id,
            writers=[DEPOSIT, WITHDRAW],
            confidence=Confidence.DERIVED,
            evidence=[graph_evidence(DEPOSIT, "writes", USER_SHARES)],
        ),
    ]

    deposit = Operation(
        id=ids.make_operation_id(DEPOSIT),
        function_id=DEPOSIT,
        contract_id=VAULT,
        name="deposit",
        kind=OperationKind.DEPOSIT,
        actor_ids=[user.id],
        inputs=[underlying.id],
        outputs=[shares.id],
        reads=[],
        writes=[item.id for item in state],
        confidence=Confidence.INFERRED,
        evidence=[heuristic_evidence("operation_by_name", "deposit(uint256)", ref=DEPOSIT)],
    )
    withdraw = Operation(
        id=ids.make_operation_id(WITHDRAW),
        function_id=WITHDRAW,
        contract_id=VAULT,
        name="withdraw",
        kind=OperationKind.WITHDRAW,
        actor_ids=[user.id],
        inputs=[shares.id],
        outputs=[underlying.id],
        writes=[item.id for item in state],
        confidence=Confidence.INFERRED,
        evidence=[heuristic_evidence("operation_by_name", "withdraw(uint256)", ref=WITHDRAW)],
    )

    flow_in = AssetFlow(
        id=ids.make_flow_id(user.id, role.id, underlying.id, deposit.id),
        source=user.id,
        target=role.id,
        asset_id=underlying.id,
        operation_id=deposit.id,
        kind=FlowKind.TRANSFER_FROM,
        amount_expr="amount",
        call_site=DEPOSIT,
        confidence=Confidence.DERIVED,
        evidence=[graph_evidence(DEPOSIT, "transfers_from", VAULT)],
    )
    flow_out = AssetFlow(
        id=ids.make_flow_id(role.id, user.id, underlying.id, withdraw.id),
        source=role.id,
        target=user.id,
        asset_id=underlying.id,
        operation_id=withdraw.id,
        kind=FlowKind.TRANSFER,
        amount_expr="amount",
        call_site=WITHDRAW,
        confidence=Confidence.DERIVED,
        evidence=[graph_evidence(WITHDRAW, "transfers", "@UNKNOWN_EXTERNAL")],
    )
    deposit.flow_ids = [flow_in.id]
    withdraw.flow_ids = [flow_out.id]

    transitions = [
        StateTransition(
            id=ids.make_transition_id(deposit.id, state[0].id),
            operation_id=deposit.id,
            state_id=state[0].id,
            effect=TransitionEffect.INCREASE,
            delta_expr="totalAssets += amount",
            order=1,
            confidence=Confidence.DERIVED,
            evidence=[graph_evidence(DEPOSIT, "writes", TOTAL_ASSETS)],
        ),
        StateTransition(
            id=ids.make_transition_id(withdraw.id, state[0].id),
            operation_id=withdraw.id,
            state_id=state[0].id,
            effect=TransitionEffect.DECREASE,
            delta_expr="totalAssets -= amount",
            order=2,
            confidence=Confidence.DERIVED,
            evidence=[graph_evidence(WITHDRAW, "writes", TOTAL_ASSETS)],
        ),
    ]
    deposit.transition_ids = [transitions[0].id]
    withdraw.transition_ids = [transitions[1].id]

    quantity_assets = AccountingQuantity(
        id=ids.make_quantity_id(TOTAL_ASSETS),
        name="totalAssets",
        state_id=state[0].id,
        asset_id=underlying.id,
        unit="asset",
        increased_by=[deposit.id],
        decreased_by=[withdraw.id],
        confidence=Confidence.DERIVED,
        evidence=[source_evidence(TOTAL_ASSETS)],
    )
    quantity_shares = AccountingQuantity(
        id=ids.make_quantity_id(TOTAL_SHARES),
        name="totalShares",
        state_id=state[1].id,
        asset_id=shares.id,
        unit="shares",
        increased_by=[deposit.id],
        decreased_by=[withdraw.id],
        confidence=Confidence.DERIVED,
        evidence=[source_evidence(TOTAL_SHARES)],
    )
    relation = AccountingRelation(
        id=ids.make_relationship_id("ratio", [quantity_assets.id, quantity_shares.id]),
        kind=RelationKind.RATIO,
        expression="pricePerShare == totalAssets / totalShares",
        quantity_ids=[quantity_assets.id, quantity_shares.id],
        rounding="unspecified",
        confidence=Confidence.INFERRED,
        evidence=[heuristic_evidence("vault_share_accounting", "totals move together")],
    )

    statement = (
        "A user's redeemable assets must not exceed their proportional claim on vault assets."
    )
    invariant = Invariant(
        id=ids.make_invariant_id(statement, [WITHDRAW, TOTAL_ASSETS, TOTAL_SHARES]),
        statement=statement,
        kind=InvariantKind.ACCOUNTING,
        targets=[WITHDRAW, TOTAL_ASSETS, TOTAL_SHARES, USER_SHARES],
        quantity_ids=[quantity_assets.id, quantity_shares.id],
        operation_ids=[withdraw.id],
        relation_id=relation.id,
        confidence=Confidence.INFERRED,
        evidence=[source_evidence(WITHDRAW, "burns shares and pays out assets 1:1")],
    )

    boundary = TrustBoundary(
        id=ids.make_boundary_id(role.id, user.id),
        inner=role.id,
        outer=user.id,
        inner_trust=TrustLevel.TRUSTED,
        outer_trust=TrustLevel.UNTRUSTED,
        crosses=[DEPOSIT, WITHDRAW],
        confidence=Confidence.DERIVED,
        evidence=[source_evidence(DEPOSIT, "external entrypoint")],
    )

    return ProtocolModel(
        identity=ProtocolIdentity(id=ids.make_protocol_id("SimpleVault"), name="SimpleVault"),
        archetypes=[
            ArchetypeClaim(
                archetype=Archetype.VAULT,
                weight=0.9,
                confidence=Confidence.INFERRED,
                evidence=[heuristic_evidence("archetype_vault", "deposit/withdraw + totals")],
            )
        ],
        contracts=[role],
        actors=[user],
        trust_boundaries=[boundary],
        assets=[underlying, shares],
        asset_flows=[flow_in, flow_out],
        operations=[deposit, withdraw],
        entrypoints=[DEPOSIT, WITHDRAW],
        state=state,
        state_transitions=transitions,
        accounting=Accounting(
            quantities=[quantity_assets, quantity_shares], relations=[relation]
        ),
        invariants=[invariant],
        core_contracts=[VAULT],
    )


@pytest.fixture
def vault_model() -> ProtocolModel:
    return simple_vault_model()


# ── Real-pipeline fixtures ────────────────────────────────────────────────────
# The detectors are tested against actual Solidity run through reader → parser → graph,
# for the same reason the graph tests are: a hand-built CodeModel lets a detector pass on
# assumptions the parser does not satisfy.


def build_from_sources(tmp_path, sources: dict[str, str], *, name: str = "protocol"):
    """`{"src/A.sol": "..."} → (CodeModel, GraphModel, RepoModel)`."""
    from pathlib import Path

    from engine.graphs import build_graph
    from engine.ingest.reader import read_repository
    from engine.parse.pipeline import parse_repository

    root = Path(tmp_path) / name
    for rel, text in sources.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nlibs = ["lib"]\n', encoding="utf-8"
    )

    repo, _ = read_repository(root, run_root=Path(tmp_path) / f"{name}-run")
    code = parse_repository(repo)
    return code, build_graph(code), repo


@pytest.fixture
def understand_of(tmp_path):
    """`understand_of(SOURCES)` → a fully built ProtocolModel."""
    from engine.protocol.understand import understand

    counter = {"n": 0}

    def factory(sources: dict[str, str], readme: str | None = None) -> ProtocolModel:
        counter["n"] += 1
        code, graph, repo = build_from_sources(
            tmp_path, sources, name=f"protocol{counter['n']}"
        )
        if readme is not None:
            repo = repo.model_copy(update={"readme": readme})
        return understand(code, graph, repo)

    return factory


@pytest.fixture
def index_of(tmp_path):
    """`index_of(SOURCES)` → the shared ProtocolIndex the detectors read from."""
    from engine.protocol.heuristics.signatures import ProtocolIndex

    counter = {"n": 0}

    def factory(sources: dict[str, str]) -> ProtocolIndex:
        counter["n"] += 1
        code, graph, _ = build_from_sources(tmp_path, sources, name=f"index{counter['n']}")
        return ProtocolIndex(code, graph)

    return factory


@pytest.fixture
def understand_with_ast(tmp_path):
    """`understand_with_ast(SOURCES)` → a ProtocolModel built *with* the solc AST.

    Compiles for real, because the signals this exercises — the direction of a write, what
    constrains a variable, what a value derives from — exist only in the compiler's output.
    A hand-built AST would test the reader against a shape we invented rather than the one
    solc emits.

    Skipped rather than failed where no toolchain is present: the engine is designed to
    degrade to text fidelity without one, and a missing `forge` is an environment fact, not
    a defect in the code under test.
    """
    import shutil

    if shutil.which("forge") is None:
        pytest.skip("forge is not on PATH; the AST-backed signals cannot be exercised")

    from pathlib import Path

    from engine.ingest.build.pipeline import build_and_save
    from engine.protocol.understand import understand

    counter = {"n": 0}

    def factory(sources: dict[str, str]):
        counter["n"] += 1
        name = f"ast{counter['n']}"
        code, graph, repo = build_from_sources(tmp_path, sources, name=name)
        run_dir = Path(tmp_path) / f"{name}-run" / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        build, _ = build_and_save(repo, run_dir)
        return understand(code, graph, repo, build, run_dir)

    return factory
