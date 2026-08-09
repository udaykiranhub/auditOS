"""`ProtocolModel` — what the code *means* (SPEC §7.6, Protocol Model stages 1–17).

```
RepoModel + CodeModel + GraphModel + docs  →  Protocol Understanding  →  ProtocolModel
```

Everything upstream is syntax. `CodeModel` knows `deposit(uint256)` exists, writes
`totalAssets`, and calls `transferFrom`. It does not know that this is a **vault**, that
`totalAssets` is an **accounting total**, that the caller is an **untrusted user**, or that
`shares × totalAssets / totalShares` is the relationship an attacker will try to break.
That gap is this artifact, and it is why SPEC §8 marks Protocol Understanding **Fatal**:
an agent handed raw Solidity re-derives all of it, badly, once per agent, at inference cost.

**Three rules govern every field below.**

1. **Interpretation is labelled as such.** Every semantic record inherits
   :class:`~engine.core.models.evidence.Claim`, so it carries a `confidence` and a list of
   `evidence` pointers. A vault that is "probably ERC-4626 because it has `deposit` and
   `withdraw`" is `INFERRED`; one whose full interface matches is `DERIVED`. Looks similar
   ≠ compliant, and the schema refuses to let those two be written the same way.

2. **Candidates, never verdicts.** `Invariant.status` starts at `CANDIDATE` and
   `RiskSurface` says *where to look*, not *what is wrong*. This artifact does not contain
   findings. Naming a vulnerability here would let a `PROPOSED` guess arrive at the report
   with none of the validation a `Finding` must survive (SPEC §7.7, P5).

3. **The deterministic pass must be able to fill this in alone.** V1 produces a complete
   `ProtocolModel` with no API key: stages 1–15 are heuristics over `CodeModel` and
   `GraphModel`. What the deterministic pass cannot answer becomes a :class:`SemanticGap`
   — a small, specific, cache-keyed question for the Phase H enrichment call. Enrichment
   raises quality; it is never load-bearing for the artifact to exist.

Every reference to code is a `SolidityID` (§7.2); every reference within this artifact is a
`ProtocolID` (`engine/protocol/ids.py`). Nothing here is addressed by name.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from engine.core.models.evidence import Claim, Confidence, Evidence, EvidenceKind

SCHEMA_VERSION = "1.0.0"

ARTIFACT_NAME = "protocol"


# ══ 1. Protocol discovery ══════════════════════════════════════════════════════


class Archetype(StrEnum):
    """What kind of protocol this is. Multi-valued: a lending market with its own
    staking module is both, and forcing a single label loses the half that gets exploited."""

    VAULT = "vault"
    LENDING = "lending"
    AMM = "amm"
    ORDERBOOK = "orderbook"
    STAKING = "staking"
    LIQUID_STAKING = "liquid_staking"
    YIELD_AGGREGATOR = "yield_aggregator"
    STABLECOIN = "stablecoin"
    DERIVATIVES = "derivatives"
    PERPETUALS = "perpetuals"
    OPTIONS = "options"
    INSURANCE = "insurance"
    BRIDGE = "bridge"
    GOVERNANCE = "governance"
    TOKEN = "token"
    NFT = "nft"
    MARKETPLACE = "marketplace"
    LAUNCHPAD = "launchpad"
    AIRDROP = "airdrop"
    ESCROW = "escrow"
    ORACLE = "oracle"
    REGISTRY = "registry"
    ACCOUNT_ABSTRACTION = "account_abstraction"
    UNKNOWN = "unknown"


class ArchetypeClaim(Claim):
    """One archetype, with the evidence that produced it and how strongly it holds."""

    model_config = ConfigDict(extra="forbid")

    archetype: Archetype
    weight: float = 0.0
    """0..1, the detector's own score. Used to *order* archetypes, never to gate them —
    a threshold here would silently drop the secondary archetype that carries the bug."""

    rationale: str = ""


class ProtocolIdentity(BaseModel):
    """Name and provenance. Facts about the repository, not interpretations of it."""

    model_config = ConfigDict(extra="forbid")

    id: str = ""
    name: str = ""
    origin: str = ""  # git URL, archive name, or folder — as recorded by the Reader
    commit: str | None = None
    solidity_version: str | None = None
    description: str = ""  # first meaningful paragraph of the README, verbatim


class Component(Claim):
    """A named subsystem: "the lending market", "the reward distributor".

    Coarser than a contract and finer than the protocol. This is the unit a human auditor
    reasons in, and the unit the Context Builder slices on when a request is scoped to a
    feature rather than to a file.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    archetype: Archetype = Archetype.UNKNOWN
    purpose: str = ""
    contract_ids: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)


# ══ 2. Contract role classification ════════════════════════════════════════════


class ContractRole(StrEnum):
    VAULT = "vault"
    TOKEN = "token"
    SHARE_TOKEN = "share_token"
    ORACLE = "oracle"
    PRICE_FEED_ADAPTER = "price_feed_adapter"
    ROUTER = "router"
    POOL = "pool"
    LENDING_MARKET = "lending_market"
    COLLATERAL_MANAGER = "collateral_manager"
    LIQUIDATION_ENGINE = "liquidation_engine"
    INTEREST_RATE_MODEL = "interest_rate_model"
    STRATEGY = "strategy"
    REWARD_DISTRIBUTOR = "reward_distributor"
    STAKING = "staking"
    GOVERNANCE = "governance"
    TIMELOCK = "timelock"
    ACCESS_CONTROL = "access_control"
    BRIDGE = "bridge"
    MESSENGER = "messenger"
    FACTORY = "factory"
    REGISTRY = "registry"
    PROXY = "proxy"
    IMPLEMENTATION = "implementation"
    ESCROW = "escrow"
    TREASURY = "treasury"
    MATH_LIBRARY = "math_library"
    UTILITY_LIBRARY = "utility_library"
    INTERFACE = "interface"
    MOCK = "mock"
    TEST_HELPER = "test_helper"
    UNKNOWN = "unknown"


class ContractClassification(Claim):
    """What one contract *is*, plus the handful of derived facts every agent asks for first.

    `is_upgradeable` and `holds_funds` live here rather than being recomputed per agent
    because both are cheap to derive once and easy to get wrong six times.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: role:<contract_id>
    contract_id: str
    name: str = ""
    role: ContractRole = ContractRole.UNKNOWN
    secondary_roles: list[ContractRole] = Field(default_factory=list)
    component_id: str | None = None
    purpose: str = ""

    is_upgradeable: bool = False
    is_pausable: bool = False
    is_entry_contract: bool = False
    """A contract users interact with directly, as opposed to one reached only internally."""
    holds_funds: bool = False
    """Can custody value: receives ETH, or is the `to` of a `transferFrom`."""
    centrality: float = 0.0
    """PageRank over the call graph. Drives `core_contracts` and context ranking (SPEC §7.6)."""


# ══ 3. Standard detection ══════════════════════════════════════════════════════


class Standard(StrEnum):
    ERC20 = "erc20"
    ERC20_PERMIT = "erc20_permit"  # EIP-2612
    ERC721 = "erc721"
    ERC1155 = "erc1155"
    ERC4626 = "erc4626"
    ERC165 = "erc165"
    ERC2981 = "erc2981"
    ERC3156 = "erc3156"  # flash loans
    ERC777 = "erc777"
    EIP712 = "eip712"
    EIP1271 = "eip1271"
    ERC1967 = "erc1967"
    UUPS = "uups"
    TRANSPARENT_PROXY = "transparent_proxy"
    BEACON_PROXY = "beacon_proxy"
    DIAMOND = "diamond"  # EIP-2535
    MINIMAL_PROXY = "minimal_proxy"  # EIP-1167
    OWNABLE = "ownable"
    ACCESS_CONTROL = "access_control"
    PAUSABLE = "pausable"
    REENTRANCY_GUARD = "reentrancy_guard"
    MULTICALL = "multicall"
    ERC4337 = "erc4337"


class Compliance(StrEnum):
    """The distinction this whole stage exists to preserve: **looks similar ≠ compliant.**

    Claiming ERC-4626 on a contract that merely has `deposit`/`withdraw` sends every
    downstream agent hunting for ERC-4626 inflation attacks in a protocol that never
    promised those semantics — and, worse, silently *suppresses* the checks that a
    `DIVERGENT` label would have triggered.
    """

    COMPLIANT = "compliant"
    """Every required member is present with the right signature and mutability."""

    PARTIAL = "partial"
    """Most of the interface is present; `missing` says exactly what is not."""

    DECLARED_ONLY = "declared_only"
    """The contract inherits or names the standard but does not implement it here."""

    DIVERGENT = "divergent"
    """Implements the shape and breaks a documented requirement of the standard. The most
    security-relevant status in this enum, and the one worth reporting loudest."""

    ABSENT = "absent"


class StandardClaim(Claim):
    """One contract measured against one standard, member by member."""

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: std:<contract_id>:<standard>
    contract_id: str
    standard: Standard
    compliance: Compliance = Compliance.ABSENT

    satisfied: list[str] = Field(default_factory=list)
    """Required members found, as canonical signatures — the receipts for the claim."""

    missing: list[str] = Field(default_factory=list)
    divergences: list[str] = Field(default_factory=list)
    """Where the implementation contradicts the standard: wrong return, wrong revert,
    missing event, rounding in the wrong direction."""

    via_inheritance: str | None = None  # the parent that supplies the implementation


# ══ 4. Actor model ═════════════════════════════════════════════════════════════


class ActorKind(StrEnum):
    USER = "user"
    ANYONE = "anyone"
    ADMIN = "admin"
    OWNER = "owner"
    GOVERNOR = "governor"
    TIMELOCK = "timelock"
    GUARDIAN = "guardian"
    PAUSER = "pauser"
    MINTER = "minter"
    KEEPER = "keeper"
    LIQUIDATOR = "liquidator"
    ORACLE = "oracle"
    RELAYER = "relayer"
    STRATEGIST = "strategist"
    TREASURY = "treasury"
    DEPLOYER = "deployer"
    PROTOCOL = "protocol"  # the protocol's own contracts acting on themselves
    EXTERNAL_PROTOCOL = "external_protocol"


class TrustLevel(StrEnum):
    """How much the protocol's safety depends on this actor behaving.

    The ladder, not the label, is what agents consume: a privileged function reachable by
    an `UNTRUSTED` actor is an access-control finding; the same function reachable only by
    `FULLY_TRUSTED` is a centralization note. Same code, different report.
    """

    UNTRUSTED = "untrusted"  # arbitrary EOA or contract; assume maximal adversarial behaviour
    SEMI_TRUSTED = "semi_trusted"  # incentivized but permissionless: keepers, liquidators
    TRUSTED = "trusted"  # privileged key; compromise is in scope but not assumed
    FULLY_TRUSTED = "fully_trusted"  # governance/timelock; treated as correct by assumption


class Capability(Claim):
    """One thing an actor can do, and what stops them doing more.

    `gated_by` is the load-bearing field: it lists the modifiers and require-checks that
    stand between the actor and the function. Empty on a privileged operation is exactly
    the shape of a missing access-control check.
    """

    model_config = ConfigDict(extra="forbid")

    function_id: str
    description: str = ""
    gated_by: list[str] = Field(default_factory=list)
    is_privileged: bool = False


class Actor(Claim):
    """Who can act on this protocol, and with what authority."""

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: actor:<kind>[.<qualifier>]
    kind: ActorKind
    name: str = ""
    trust: TrustLevel = TrustLevel.UNTRUSTED
    description: str = ""

    roles: list[str] = Field(default_factory=list)
    """On-chain role identifiers this actor holds: `DEFAULT_ADMIN_ROLE`, `owner`."""

    capabilities: list[Capability] = Field(default_factory=list)
    controlled_contracts: list[str] = Field(default_factory=list)

    @property
    def privileged_functions(self) -> list[str]:
        return sorted({c.function_id for c in self.capabilities if c.is_privileged})


# ══ 5. Trust boundaries ════════════════════════════════════════════════════════


class TrustBoundary(Claim):
    """A directed crossing where control or value passes between trust domains.

    Every exploit is something crossing one of these in a way it was not meant to. Modelling
    them explicitly is what lets an agent ask "what crosses here, and what is checked?"
    instead of reading every function hoping to notice.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: boundary:<inner>-><outer>
    inner: str
    """The side being entered — a `ProtocolID` (actor / role / component)."""
    outer: str
    """The side being left."""

    description: str = ""
    crosses: list[str] = Field(default_factory=list)
    """What passes: `SolidityID`s of the functions or calls that traverse the boundary."""

    inner_trust: TrustLevel = TrustLevel.TRUSTED
    outer_trust: TrustLevel = TrustLevel.UNTRUSTED
    checks: list[str] = Field(default_factory=list)
    """Validation applied at the crossing: modifiers, `require`s, allowlists."""

    hands_over_control: bool = False
    """A call out that lets the other side re-enter — the reentrancy precondition."""


# ══ 6. Asset model ═════════════════════════════════════════════════════════════


class AssetKind(StrEnum):
    NATIVE = "native"  # ETH
    ERC20 = "erc20"
    ERC721 = "erc721"
    ERC1155 = "erc1155"
    SHARE = "share"  # a claim on a pool: vault shares, LP tokens
    DEBT = "debt"  # a liability recorded against an account
    COLLATERAL = "collateral"
    REWARD = "reward"
    FEE = "fee"
    SYNTHETIC = "synthetic"
    POINTS = "points"  # non-transferable accounting units
    UNKNOWN = "unknown"


class Asset(Claim):
    """Something of value the protocol moves or accounts for.

    Deliberately wider than "token": vault shares, recorded debt and accrued rewards are all
    assets here, because they are all things a user can gain or lose. An asset model limited
    to `IERC20` addresses cannot express the accounting bugs that make up most vault
    findings.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: asset:<symbol>[@<ref>]
    symbol: str = ""
    name: str = ""
    kind: AssetKind = AssetKind.UNKNOWN

    contract_id: str | None = None
    """The token contract, when it lives in this repository."""
    state_var_ids: list[str] = Field(default_factory=list)
    """Storage this asset is accounted in — the join to the state model."""

    decimals: int | None = None
    is_protocol_issued: bool = False
    """Minted by this protocol (shares, debt tokens) rather than merely held."""
    is_external: bool = False
    is_rebasing: bool = False
    is_fee_on_transfer: bool = False
    """Both flags default to False and both are frequently *unknown* for an external token.
    Where the deterministic pass cannot tell, it must emit a `SemanticGap` rather than let
    the default read as a finding of fact."""

    backing_asset_id: str | None = None
    """For a share or debt asset: what it is a claim on. `shares → USDC`."""


# ══ 7. Asset flow ══════════════════════════════════════════════════════════════


class FlowKind(StrEnum):
    TRANSFER = "transfer"
    TRANSFER_FROM = "transfer_from"
    MINT = "mint"
    BURN = "burn"
    NATIVE_SEND = "native_send"
    ACCOUNTING = "accounting"
    """No token moves; a balance mapping is credited or debited. Just as real to a user."""


class AssetFlow(Claim):
    """Who sends what to whom, under which operation.

    Aliased as `value_flows` on the model for SPEC §7.6 compatibility.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: flow:<digest>
    source: str
    """`ProtocolID` of the sender — an actor, a contract role, or an external dependency."""
    target: str
    asset_id: str
    kind: FlowKind = FlowKind.TRANSFER
    operation_id: str | None = None

    amount_expr: str = ""
    """The amount as written (`amount`, `shares * totalAssets / totalSupply`). Copied from
    source, never simplified — a rewritten expression cannot be checked against the code."""

    conditions: list[str] = Field(default_factory=list)
    """What must hold for the flow to happen: the guards on the path to it."""

    call_site: str = ""  # SolidityID of the function containing the transfer
    line: int = 0


# ══ 8. Operation model ═════════════════════════════════════════════════════════


class OperationKind(StrEnum):
    DEPOSIT = "deposit"
    WITHDRAW = "withdraw"
    MINT = "mint"
    BURN = "burn"
    REDEEM = "redeem"
    BORROW = "borrow"
    REPAY = "repay"
    LIQUIDATE = "liquidate"
    SWAP = "swap"
    ADD_LIQUIDITY = "add_liquidity"
    REMOVE_LIQUIDITY = "remove_liquidity"
    STAKE = "stake"
    UNSTAKE = "unstake"
    CLAIM = "claim"
    HARVEST = "harvest"
    REBALANCE = "rebalance"
    FLASH_LOAN = "flash_loan"
    BRIDGE_SEND = "bridge_send"
    BRIDGE_RECEIVE = "bridge_receive"
    PROPOSE = "propose"
    VOTE = "vote"
    EXECUTE = "execute"
    TRANSFER = "transfer"
    APPROVE = "approve"
    INITIALIZE = "initialize"
    UPGRADE = "upgrade"
    PAUSE = "pause"
    CONFIGURE = "configure"
    ADMIN = "admin"
    VIEW = "view"
    UNKNOWN = "unknown"


class Operation(Claim):
    """One externally callable action, described in protocol terms rather than in Solidity.

    ```
    deposit(uint256)  →  DEPOSIT  ·  actor USER  ·  in ASSET  ·  out SHARES  ·  USER → VAULT
    ```

    This is the record agents reason over. It is *not* a summary of the function — the
    function is still there, addressed by `function_id`, and an agent that needs the body
    reads it. This says what the body is *for*.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: op:<function_id>
    function_id: str
    contract_id: str | None = None
    name: str = ""
    kind: OperationKind = OperationKind.UNKNOWN
    component_id: str | None = None
    description: str = ""

    actor_ids: list[str] = Field(default_factory=list)
    is_privileged: bool = False
    is_permissionless: bool = True

    inputs: list[str] = Field(default_factory=list)
    """Asset `ProtocolID`s the caller supplies."""
    outputs: list[str] = Field(default_factory=list)
    """Asset `ProtocolID`s the caller receives."""

    preconditions: list[str] = Field(default_factory=list)
    """Extracted from `require`/`revert`/modifiers — the checks, as written."""
    postconditions: list[str] = Field(default_factory=list)

    reads: list[str] = Field(default_factory=list)  # state ProtocolIDs
    writes: list[str] = Field(default_factory=list)
    flow_ids: list[str] = Field(default_factory=list)
    transition_ids: list[str] = Field(default_factory=list)

    external_calls: list[str] = Field(default_factory=list)
    """Where control leaves. Carried on the operation because "does this operation hand
    control to an untrusted party?" is asked by three different agents."""

    emits: list[str] = Field(default_factory=list)
    is_payable: bool = False
    is_view: bool = False


# ══ 9. State model ═════════════════════════════════════════════════════════════


class StateRole(StrEnum):
    """What a storage variable *means*, as opposed to what type it has."""

    ACCOUNTING_TOTAL = "accounting_total"  # totalAssets, totalSupply
    USER_BALANCE = "user_balance"  # balanceOf, shares[user]
    DEBT_RECORD = "debt_record"
    COLLATERAL_RECORD = "collateral_record"
    SHARE_SUPPLY = "share_supply"
    EXCHANGE_RATE = "exchange_rate"
    ACCUMULATOR = "accumulator"  # rewardPerTokenStored, borrowIndex
    PRICE = "price"
    RATE_PARAM = "rate_param"  # interest rate, fee bps
    CONFIG = "config"
    ROLE_REGISTRY = "role_registry"
    ADDRESS_REF = "address_ref"  # a dependency's address
    TIMESTAMP = "timestamp"
    NONCE = "nonce"
    FLAG = "flag"  # paused, initialized
    LOCK = "lock"  # reentrancy guard
    CACHE = "cache"
    UNKNOWN = "unknown"


class StateItem(Claim):
    """One storage variable, with its meaning, its readers and its writers.

    Readers and writers come straight from the storage graph, so they are complete for
    everything the graph can see — and honestly incomplete for what it cannot. A variable
    written only inside inline assembly shows an empty `writers` list, which is why
    `ProtocolModel.gaps` exists.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: state:<state_var_id>
    state_var_id: str
    contract_id: str
    name: str = ""
    type: str = ""
    role: StateRole = StateRole.UNKNOWN
    meaning: str = ""

    readers: list[str] = Field(default_factory=list)  # SolidityIDs
    writers: list[str] = Field(default_factory=list)
    asset_id: str | None = None

    is_constant: bool = False
    is_immutable: bool = False
    is_admin_controlled: bool = False
    """Only writable from a privileged operation — a lever, and therefore a risk surface."""
    is_critical: bool = False
    """Corrupting it breaks solvency or authorization. Drives ranking, not severity."""
    slot: int | None = None


# ══ 10. State transitions ══════════════════════════════════════════════════════


class TransitionEffect(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"
    SET = "set"
    DELETE = "delete"
    UNKNOWN = "unknown"


class StateTransition(Claim):
    """`before → operation → after`, for one state item.

    Symbolic, not numeric: `delta_expr` holds the expression as written. Concrete before/
    after values (`totalAssets = 1000 → 1100`) belong in an *example*, and an example is
    only sound once it is executed — which is Phase I, not here. A fabricated concrete
    trace is the single most convincing way to mislead an agent.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: transition:<digest>
    operation_id: str
    state_id: str
    effect: TransitionEffect = TransitionEffect.UNKNOWN
    delta_expr: str = ""
    condition: str = ""
    order: int = -1
    """Position within the operation body. Ordering is what makes CEI and
    check-effects reasoning possible at this level."""

    after_external_call: bool = False


# ══ 11. External dependencies ══════════════════════════════════════════════════


class DependencyKind(StrEnum):
    ORACLE = "oracle"
    DEX = "dex"
    LENDING_PROTOCOL = "lending_protocol"
    STAKING_PROTOCOL = "staking_protocol"
    BRIDGE = "bridge"
    TOKEN = "token"
    REGISTRY = "registry"
    KEEPER_NETWORK = "keeper_network"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class Dependency(Claim):
    """Something outside the audited code that the protocol's correctness rests on."""

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: dep:<name>[@<ref>]
    name: str
    kind: DependencyKind = DependencyKind.UNKNOWN
    interface_id: str | None = None  # SolidityID of the interface it is called through
    description: str = ""

    used_by: list[str] = Field(default_factory=list)  # SolidityIDs of calling functions
    call_sites: list[str] = Field(default_factory=list)

    is_upgradeable_by_third_party: bool = False
    is_trusted: bool = True
    """Whether the protocol *treats* it as trusted — an observation about the code, not an
    endorsement. An untrusted-in-fact dependency treated as trusted is the finding."""

    failure_modes: list[str] = Field(default_factory=list)
    """How it can go wrong from here: stale price, reverting call, reentrant callback."""


# ══ 12. Accounting model ═══════════════════════════════════════════════════════


class RelationKind(StrEnum):
    EQUALITY = "equality"  # a == b
    SUM = "sum"  # a == Σ b
    RATIO = "ratio"  # a == b / c
    PROPORTIONAL = "proportional"  # a ∝ b
    BOUND = "bound"  # a <= b
    CONSERVATION = "conservation"  # Σ in == Σ out
    MONOTONIC = "monotonic"  # a never decreases


class AccountingQuantity(Claim):
    """A number the protocol's correctness depends on, and where it comes from."""

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: qty:<state_var_id>
    name: str
    state_id: str | None = None
    asset_id: str | None = None
    unit: str = ""
    """What one of these *is*: `USDC (6dp)`, `shares`, `bps`. Unit confusion between a
    share amount and an asset amount is a whole vulnerability class, and it is invisible
    unless someone writes the unit down."""

    description: str = ""
    increased_by: list[str] = Field(default_factory=list)  # operation ProtocolIDs
    decreased_by: list[str] = Field(default_factory=list)


class AccountingRelation(Claim):
    """A relationship between quantities — the raw material of every accounting invariant.

    **Only assert what the implementation shows.** If the code never divides by
    `totalShares`, do not record a ratio because vaults usually have one. A relationship
    invented from the archetype produces an invariant that is false for this protocol, and
    an agent that "confirms" a false invariant produces a confident wrong finding.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: rel:<digest>
    kind: RelationKind
    expression: str
    """As close to the source as possible: `assets == shares * totalAssets / totalSupply`."""

    quantity_ids: list[str] = Field(default_factory=list)
    holds_when: str = ""
    rounding: str = ""
    """`down`, `up`, `unspecified`. Which way a division rounds decides who absorbs the
    dust, and "unspecified" is itself worth reporting."""


class Accounting(BaseModel):
    """Stage 12 as a whole: the quantities and how they relate."""

    model_config = ConfigDict(extra="forbid")

    quantities: list[AccountingQuantity] = Field(default_factory=list)
    relations: list[AccountingRelation] = Field(default_factory=list)
    unit_conflicts: list[str] = Field(default_factory=list)
    """Places where two quantities with different units meet without conversion."""


# ══ 13. Economic model ═════════════════════════════════════════════════════════


class SurfaceKind(StrEnum):
    """Named places where economics and precision live. Not vulnerabilities — *addresses*."""

    SHARE_PRICING = "share_pricing"
    ROUNDING = "rounding"
    PRECISION_LOSS = "precision_loss"
    FEE = "fee"
    DONATION = "donation"
    FIRST_DEPOSITOR = "first_depositor"
    INFLATION = "inflation"
    SLIPPAGE = "slippage"
    INTEREST_ACCRUAL = "interest_accrual"
    LIQUIDATION_INCENTIVE = "liquidation_incentive"
    REWARD_EMISSION = "reward_emission"
    ORACLE_PRICING = "oracle_pricing"
    FLASH_LOAN = "flash_loan"
    MEV = "mev"
    GRIEFING = "griefing"
    CENTRALIZATION = "centralization"
    UPGRADE = "upgrade"


class EconomicSurface(Claim):
    """Where value is created, destroyed, redistributed, or lost to arithmetic.

    This is a **map, not a verdict** (rule 2 at the top of this module). "`deposit` rounds
    shares down" tells the Business Logic agent where to point its attention; whether that
    rounding is exploitable here is its job, and calling it a bug at this stage would let an
    interpretation reach the report without ever meeting the validator.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: surface:<kind>:<target>
    kind: SurfaceKind
    target: str
    """What it attaches to — an operation, a contract or a relation `ProtocolID`."""

    description: str = ""
    actors: list[str] = Field(default_factory=list)  # who is exposed, who could benefit
    assets: list[str] = Field(default_factory=list)
    function_ids: list[str] = Field(default_factory=list)
    questions: list[str] = Field(default_factory=list)
    """What an auditor should ask here. Phrased as questions on purpose — a question
    survives being wrong; an assertion does not."""


class EconomicModel(BaseModel):
    """Stage 13: how value enters, moves and leaves."""

    model_config = ConfigDict(extra="forbid")

    summary: str = ""
    fee_sources: list[str] = Field(default_factory=list)
    reward_sources: list[str] = Field(default_factory=list)
    incentives: list[str] = Field(default_factory=list)
    """Behaviours the protocol pays for: liquidation bounties, keeper rewards, LP yield."""
    value_capture: list[str] = Field(default_factory=list)
    surfaces: list[EconomicSurface] = Field(default_factory=list)


# ══ 14. Documentation reconciliation ═══════════════════════════════════════════


class Reconciliation(StrEnum):
    AGREES = "agrees"
    CONFLICTS = "conflicts"
    """Documentation and code disagree. Often the highest-signal record in this artifact:
    a documented promise the code breaks is a finding with the intent already established."""
    UNIMPLEMENTED = "unimplemented"
    UNVERIFIABLE = "unverifiable"
    """Cannot be checked deterministically — a `SemanticGap`, not a silent pass."""
    NOT_CHECKED = "not_checked"


class DocumentationRule(Claim):
    """A normative statement the project makes about itself, and whether the code keeps it.

    Only *normative* sentences belong here — "shares represent proportional ownership",
    not "this repo uses Foundry". A rule set diluted with prose makes reconciliation
    meaningless, since almost everything will trivially "agree".
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: docrule:<digest>
    statement: str
    source_path: str = ""
    source_kind: str = "readme"  # readme | natspec | docs | comment
    line: int = 0

    subject_ids: list[str] = Field(default_factory=list)
    """What it is about — `SolidityID`s or `ProtocolID`s. A rule with no subject cannot be
    reconciled and should be dropped rather than carried."""

    status: Reconciliation = Reconciliation.NOT_CHECKED
    finding: str = ""
    """What the comparison actually showed, in one line."""


# ══ 15. Invariants ═════════════════════════════════════════════════════════════


class InvariantKind(StrEnum):
    ACCOUNTING = "accounting"
    SOLVENCY = "solvency"
    CONSERVATION = "conservation"
    SUPPLY = "supply"
    AUTHORIZATION = "authorization"
    MONOTONICITY = "monotonicity"
    TEMPORAL = "temporal"
    LIVENESS = "liveness"
    CONFIGURATION = "configuration"


class InvariantStatus(StrEnum):
    """How much weight an invariant can bear. It starts at the bottom and is *earned* up.

    The default is `CANDIDATE` and nothing in the deterministic pipeline may promote past
    `SUPPORTED`: only an executed check (Phase I) produces `VERIFIED`. A model asserting an
    invariant holds is a `PROPOSED` claim, not a verification, no matter how it phrases it.
    """

    CANDIDATE = "candidate"
    """Proposed from structure. May be wrong; may not even be intended."""

    SUPPORTED = "supported"
    """Corroborated by code and documentation, but not executed."""

    VERIFIED = "verified"
    """Held under an actual run — a Forge invariant test that passed."""

    REFUTED = "refuted"
    """A counterexample exists. Points a security agent at something real."""

    UNVERIFIABLE = "unverifiable"
    """Cannot be expressed as an executable check with what we can see."""


class Invariant(Claim):
    """A property that should remain true, with everything needed to check it later.

    ```
    INV-001  A user's redeemable assets must not exceed their proportional claim
             on vault assets.                                    status: CANDIDATE
             ├── src/Vault.sol:Vault.withdraw(uint256)
             ├── src/Vault.sol:Vault#totalAssets
             ├── src/Vault.sol:Vault#totalShares
             └── src/Vault.sol:Vault#shares
    ```

    The target list is not decoration. It is what lets the Validator say *the finding is
    supported by these exact pieces of code*, and what Phase I turns into a Forge test.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: inv:<digest> — stable across runs
    label: str = ""  # INV-001 — ordinal, human-facing, assigned at assembly
    statement: str
    kind: InvariantKind = InvariantKind.ACCOUNTING
    status: InvariantStatus = InvariantStatus.CANDIDATE

    targets: list[str] = Field(default_factory=list)
    """`SolidityID`s the invariant constrains. Required — an invariant with no target
    cannot be checked, cannot be cited, and must not be emitted."""

    quantity_ids: list[str] = Field(default_factory=list)
    operation_ids: list[str] = Field(default_factory=list)
    relation_id: str | None = None

    expression: str = ""
    """A checkable form where one exists: `totalAssets >= totalShares * pricePerShare`."""

    holds_when: str = ""
    breaks_if: list[str] = Field(default_factory=list)
    """Conditions under which it would fail — the bridge from invariant to attack path."""

    source: str = "heuristic"  # heuristic | documentation | model | test
    verification: str = ""  # how it was checked, or why it could not be

    @property
    def is_actionable(self) -> bool:
        """Usable by an agent: it names what it constrains and is not already refuted."""
        return bool(self.targets) and self.status is not InvariantStatus.UNVERIFIABLE


# ══ Assumptions, risk surfaces, gaps ═══════════════════════════════════════════


class Assumption(Claim):
    """Something taken as given for the protocol to be safe.

    Distinct from an invariant: an invariant is enforced *by* the code, an assumption is
    relied on *by* the code and enforced somewhere else — or nowhere. Recording them
    separately is what stops "the oracle is honest" being reported as a bug in every run,
    and what lets it be reported as a bug when the protocol never says it.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: assume:<digest>
    statement: str
    holder: str = ""  # the ProtocolID relied upon: an actor or a dependency
    criticality: str = "medium"  # low | medium | high
    is_documented: bool = False
    """Documented assumptions are design decisions; undocumented ones are often oversights.
    The difference decides whether this becomes a report note or a finding."""

    consequences: list[str] = Field(default_factory=list)


class RiskSurface(Claim):
    """Where to look, expressed as an area with reasons — never as a defect.

    Overlaps `EconomicSurface` by design: the economic one answers "where does value move",
    this one answers "where should an agent spend its budget", and they are ranked
    differently. `priority` feeds context selection directly.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: surface:<kind>:<target>
    kind: SurfaceKind
    title: str = ""
    description: str = ""
    targets: list[str] = Field(default_factory=list)  # SolidityIDs
    actors: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    invariant_ids: list[str] = Field(default_factory=list)
    priority: float = 0.0  # 0..1
    suggested_agents: list[str] = Field(default_factory=list)


class SemanticGap(BaseModel):
    """A specific question the deterministic pass could not answer.

    This is the seam between V1 and Phase H, and it is deliberately narrow. Enrichment is
    not "send the repo to a model and ask what it does" — it is *this* question, with
    *these* few `SolidityID`s as context, answered into *that* field. Small context, checkable
    answer, evidence required on the way back in.

    Not a `Claim`: a gap asserts nothing. It is the absence of a claim.
    """

    model_config = ConfigDict(extra="forbid")

    id: str  # ProtocolID: gap:<digest>
    subject: str
    """The `ProtocolID` or `SolidityID` the question is about."""
    question: str
    field: str = ""
    """Dotted path of the field an answer would populate: `assets.is_fee_on_transfer`."""

    context_ids: list[str] = Field(default_factory=list)
    """The minimal set of `SolidityID`s an answer needs. Keeping this small is the entire
    cost-control mechanism for Phase H."""

    priority: float = 0.0
    blocking: bool = False
    """True when a downstream stage produces something misleading without an answer."""


class Enrichment(BaseModel):
    """Provenance for the Phase H pass, so a deterministic run is distinguishable from an
    enriched one — and so the two can be diffed to measure whether the model helped."""

    model_config = ConfigDict(extra="forbid")

    applied: bool = False
    provider: str = ""
    model: str = ""
    prompt_hash: str = ""
    gaps_answered: int = 0
    gaps_rejected: int = 0
    """Answers that failed evidence validation. A rising number here is the signal that
    the enrichment prompt or the gap framing is wrong."""
    notes: list[str] = Field(default_factory=list)


# ══ 17. Assembly ═══════════════════════════════════════════════════════════════


class Coverage(BaseModel):
    """What this model actually managed to say. Read before trusting anything above it.

    A `ProtocolModel` that understood nothing and a `ProtocolModel` that understood
    everything are the same shape; without this block they are indistinguishable, and the
    empty one reads to a downstream agent as "this protocol has no invariants".
    """

    model_config = ConfigDict(extra="forbid")

    contracts_total: int = 0
    contracts_classified: int = 0
    entrypoints_total: int = 0
    operations_modelled: int = 0
    state_vars_total: int = 0
    state_vars_explained: int = 0
    grounded_claims: int = 0
    ungrounded_claims: int = 0
    unmodelled: list[str] = Field(default_factory=list)
    """Named blind spots: assembly bodies, proxies whose implementation is absent,
    dependencies with no interface. Silence here would read as completeness."""

    @property
    def classification_rate(self) -> float:
        return self.contracts_classified / self.contracts_total if self.contracts_total else 0.0

    @property
    def operation_rate(self) -> float:
        return self.operations_modelled / self.entrypoints_total if self.entrypoints_total else 0.0


class ProtocolModel(BaseModel):
    """The semantic layer. Required input to every security agent (SPEC §8).

    Field order below follows the seventeen stages, so the artifact reads top to bottom in
    the order it is built.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    content_hash: str = ""
    repo_content_hash: str = ""
    code_content_hash: str = ""
    graph_content_hash: str = ""

    # 1 — discovery
    identity: ProtocolIdentity = Field(default_factory=ProtocolIdentity)
    summary: str = ""
    """200–400 words, the "what is this" (SPEC §7.6). Templated by the deterministic pass;
    rewritten by enrichment when available."""
    archetypes: list[ArchetypeClaim] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)

    # 2–3 — roles and standards
    contracts: list[ContractClassification] = Field(default_factory=list)
    standards: list[StandardClaim] = Field(default_factory=list)

    # 4–5 — actors and boundaries
    actors: list[Actor] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)

    # 6–7 — assets and flows
    assets: list[Asset] = Field(default_factory=list)
    asset_flows: list[AssetFlow] = Field(default_factory=list)

    # 8 — operations
    operations: list[Operation] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)  # SolidityIDs (SPEC §7.6)
    privileged: list[str] = Field(default_factory=list)

    # 9–10 — state
    state: list[StateItem] = Field(default_factory=list)
    state_transitions: list[StateTransition] = Field(default_factory=list)

    # 11 — dependencies
    dependencies: list[Dependency] = Field(default_factory=list)

    # 12–13 — economics
    accounting: Accounting = Field(default_factory=Accounting)
    economics: EconomicModel = Field(default_factory=EconomicModel)

    # 14 — documentation
    documentation_rules: list[DocumentationRule] = Field(default_factory=list)

    # 15 — invariants and what they rest on
    assumptions: list[Assumption] = Field(default_factory=list)
    invariants: list[Invariant] = Field(default_factory=list)
    risk_surfaces: list[RiskSurface] = Field(default_factory=list)

    # 16–17 — honesty about the result
    core_contracts: list[str] = Field(default_factory=list)
    """Ranked most-central first. Drives context selection (SPEC §7.6)."""
    gaps: list[SemanticGap] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    enrichment: Enrichment = Field(default_factory=Enrichment)
    notes: list[str] = Field(default_factory=list)

    # ── SPEC §7.6 aliases ─────────────────────────────────────────────────────
    # SPEC names these fields; this model stores richer records under different names.
    # Exposed as properties so §7.6's contract holds without duplicating state.

    @property
    def archetype(self) -> list[str]:
        return [claim.archetype.value for claim in self.archetypes]

    @property
    def value_flows(self) -> list[AssetFlow]:
        return self.asset_flows

    @property
    def trust_assumptions(self) -> list[str]:
        return [assumption.statement for assumption in self.assumptions]

    @property
    def external_deps(self) -> list[str]:
        return [dependency.name for dependency in self.dependencies]

    # ── Lookups ───────────────────────────────────────────────────────────────

    def contract(self, contract_id: str) -> ContractClassification | None:
        return next((c for c in self.contracts if c.contract_id == contract_id), None)

    def operation(self, protocol_id: str) -> Operation | None:
        return next((o for o in self.operations if o.id == protocol_id), None)

    def operation_for(self, function_id: str) -> Operation | None:
        return next((o for o in self.operations if o.function_id == function_id), None)

    def contract_by_name(self, name: str) -> ContractClassification | None:
        """By source name. Convenient for reports and tests; ambiguous when two contracts
        in different files share a name, so `contract()` stays the addressed form."""
        return next((c for c in self.contracts if c.name == name), None)

    def operation_by_name(self, name: str) -> Operation | None:
        """First operation with this function name. Overloads share a name, so this returns
        whichever sorts first — use `operation_for()` with a `SolidityID` to disambiguate."""
        return next((o for o in self.operations if o.name == name), None)

    def actor(self, protocol_id: str) -> Actor | None:
        return next((a for a in self.actors if a.id == protocol_id), None)

    def asset(self, protocol_id: str) -> Asset | None:
        return next((a for a in self.assets if a.id == protocol_id), None)

    def state_item(self, protocol_id: str) -> StateItem | None:
        return next((s for s in self.state if s.id == protocol_id), None)

    def invariant(self, protocol_id: str) -> Invariant | None:
        return next((i for i in self.invariants if i.id == protocol_id), None)

    def operations_of_kind(self, kind: OperationKind) -> list[Operation]:
        return [o for o in self.operations if o.kind is kind]

    def standards_of(self, contract_id: str) -> list[StandardClaim]:
        return [s for s in self.standards if s.contract_id == contract_id]

    def flows_of(self, operation_id: str) -> list[AssetFlow]:
        return [f for f in self.asset_flows if f.operation_id == operation_id]

    def transitions_of(self, operation_id: str) -> list[StateTransition]:
        return [t for t in self.state_transitions if t.operation_id == operation_id]

    def claims(self) -> list[Claim]:
        """Every `Claim` in the artifact, for coverage accounting and evidence validation.

        Enumerated explicitly rather than by walking the model tree: a reflective walk would
        silently start including any new nested `Claim`, and the point of this list is that
        adding a field is a decision someone made, not a side effect.
        """
        nested: list[Claim] = []
        for actor in self.actors:
            nested.extend(actor.capabilities)
        return [
            *self.archetypes,
            *self.components,
            *self.contracts,
            *self.standards,
            *self.actors,
            *nested,
            *self.trust_boundaries,
            *self.assets,
            *self.asset_flows,
            *self.operations,
            *self.state,
            *self.state_transitions,
            *self.dependencies,
            *self.accounting.quantities,
            *self.accounting.relations,
            *self.economics.surfaces,
            *self.documentation_rules,
            *self.assumptions,
            *self.invariants,
            *self.risk_surfaces,
        ]

    def evidence_for(self, protocol_id: str) -> list[Evidence]:
        """Every piece of evidence behind one record. What the Validator cites."""
        for claim in self.claims():
            if getattr(claim, "id", None) == protocol_id:
                return claim.evidence
        return []

    # ── Derived views ─────────────────────────────────────────────────────────

    @property
    def candidate_invariants(self) -> list[Invariant]:
        return [i for i in self.invariants if i.status is InvariantStatus.CANDIDATE]

    @property
    def verified_invariants(self) -> list[Invariant]:
        return [i for i in self.invariants if i.status is InvariantStatus.VERIFIED]

    @property
    def unverified_invariants(self) -> list[Invariant]:
        return [
            i
            for i in self.invariants
            if i.status in (InvariantStatus.CANDIDATE, InvariantStatus.SUPPORTED)
        ]

    @property
    def conflicts(self) -> list[DocumentationRule]:
        """Documented promises the code appears to break — read these first."""
        return [r for r in self.documentation_rules if r.status is Reconciliation.CONFLICTS]

    @property
    def untrusted_actors(self) -> list[Actor]:
        return [a for a in self.actors if a.trust is TrustLevel.UNTRUSTED]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "archetypes": len(self.archetypes),
            "components": len(self.components),
            "contracts": len(self.contracts),
            "standards": len(self.standards),
            "actors": len(self.actors),
            "trust_boundaries": len(self.trust_boundaries),
            "assets": len(self.assets),
            "asset_flows": len(self.asset_flows),
            "operations": len(self.operations),
            "state": len(self.state),
            "state_transitions": len(self.state_transitions),
            "dependencies": len(self.dependencies),
            "quantities": len(self.accounting.quantities),
            "relations": len(self.accounting.relations),
            "economic_surfaces": len(self.economics.surfaces),
            "documentation_rules": len(self.documentation_rules),
            "doc_conflicts": len(self.conflicts),
            "assumptions": len(self.assumptions),
            "invariants": len(self.invariants),
            "risk_surfaces": len(self.risk_surfaces),
            "gaps": len(self.gaps),
        }

    def confidence_histogram(self) -> dict[str, int]:
        """How much of this artifact is derived versus guessed. The honesty check."""
        histogram = {level.value: 0 for level in Confidence}
        for claim in self.claims():
            histogram[claim.confidence.value] += 1
        return histogram

    def evidence_histogram(self) -> dict[str, int]:
        histogram = {kind.value: 0 for kind in EvidenceKind}
        for claim in self.claims():
            for item in claim.evidence:
                histogram[item.kind.value] += 1
        return histogram

    # ── Serialization (SPEC §7.1) ─────────────────────────────────────────────

    def hash_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"content_hash"})

    def with_content_hash(self) -> ProtocolModel:
        from engine.core.artifacts import content_hash as _hash

        return self.model_copy(update={"content_hash": _hash(self.hash_payload())})


__all__ = [
    "ARTIFACT_NAME",
    "SCHEMA_VERSION",
    "Accounting",
    "AccountingQuantity",
    "AccountingRelation",
    "ActorKind",
    "Actor",
    "Archetype",
    "ArchetypeClaim",
    "Asset",
    "AssetFlow",
    "AssetKind",
    "Assumption",
    "Capability",
    "Claim",
    "Compliance",
    "Component",
    "Confidence",
    "ContractClassification",
    "ContractRole",
    "Coverage",
    "Dependency",
    "DependencyKind",
    "DocumentationRule",
    "EconomicModel",
    "EconomicSurface",
    "Enrichment",
    "Evidence",
    "EvidenceKind",
    "FlowKind",
    "Invariant",
    "InvariantKind",
    "InvariantStatus",
    "Operation",
    "OperationKind",
    "ProtocolIdentity",
    "ProtocolModel",
    "Reconciliation",
    "RelationKind",
    "RiskSurface",
    "SemanticGap",
    "Standard",
    "StandardClaim",
    "StateItem",
    "StateRole",
    "StateTransition",
    "SurfaceKind",
    "TransitionEffect",
    "TrustBoundary",
    "TrustLevel",
]
