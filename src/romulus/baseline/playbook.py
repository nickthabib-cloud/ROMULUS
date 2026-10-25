"""Sweep-facing baseline playbooks and their cell-scoped accumulation contract."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Protocol

from romulus.baseline.carry import PendingResolver
from romulus.baseline.count import KeyCounter
from romulus.baseline.spec import SPEC_BY_ID, BaselineSpec, KeyContext, Pending
from romulus.detect.base import Match, Playbook
from romulus.evidence.typed import TypedEvent


@dataclass(frozen=True)
class BaselineCell:
    """The bounded result of one source partition for one baseline spec."""

    spec_id: str
    observations: tuple[dict, ...]
    counts: tuple[dict, ...]
    scope_hours: tuple[dict, ...]
    event_hours: tuple[dict, ...]
    pendings: tuple[Pending, ...]
    partial: bool
    reasons: tuple[str, ...]
    partial_hours: tuple[datetime, ...]
    partial_host_hours: tuple[tuple[str, tuple[datetime, ...]], ...]
    whole_cell_partial: bool


class SnapshotView(Protocol):
    """The post-lookback judge supplied by the hunt-layer baseline stage."""

    def judge(self, playbook: BaselinePlaybook) -> Iterable[Match]: ...


class BaselinePlaybook(Playbook):
    """A baseline spec as a playbook: count during sweep, publish only from a frozen snapshot."""

    kind: ClassVar[str] = "baseline"
    claim_type: ClassVar[str] = "anomaly"
    severity: ClassVar[str] = "info"
    lane: ClassVar[str] = "lead"
    anchor_class: ClassVar[str] = "baseline"
    attack_exempt: ClassVar[str] = (
        "Baseline deviations are technique-agnostic context, not claims of adversary behavior."
    )
    spec: ClassVar[BaselineSpec]

    def __init__(self) -> None:
        super().__init__()
        # The baseline spec owns the persisted protocol version. Keeping an inherited Playbook.version on the
        # instance would let sweep, judge and publication address different observation rows.
        self.version = self.spec.version
        self._counter: KeyCounter | None = None
        self._context = KeyContext()

    def begin_cell(self, segment_id: str, span: tuple[datetime, datetime], context: KeyContext) -> None:
        if self._counter is not None:
            raise RuntimeError(f"baseline cell already open for {self.id}")
        self._context = context
        self._counter = KeyCounter(
            segment_id,
            self.spec,
            span=span,
            retain_observations_when_partial=True,
        )

    def consume(self, events: list[TypedEvent]) -> list[Match]:
        if self._counter is None:
            # Generic full-pack probes call every playbook directly, outside a sweep cell. Baselines have no
            # defensible span in that mode, so they neither accumulate nor publish.
            return []
        for event in events:
            before = self._counter.partial
            self._counter.consume(event, self._context)
            self.evaluated += 1
            if not before and self._counter.partial:
                self.missing_required += 1
        return []

    def mark_cell_partial(self, reason: str) -> None:
        if self._counter is None:
            raise RuntimeError(f"baseline cell is not open for {self.id}")
        self._counter.mark_partial(reason)

    def resolve_pendings(self, resolver: PendingResolver) -> None:
        """Resolve compact children after the cell and its later continuity have been recorded."""
        if self._counter is None:
            raise RuntimeError(f"baseline cell is not open for {self.id}")
        for pending in self._counter.take_pendings():
            resolution = resolver.resolve(pending)
            if resolution.reason is not None:
                self._counter.mark_partial(f"{pending.event_id}: {resolution.reason}", pending.ts)
            else:
                self._counter.add_keys(
                    pending.ts, resolution.keys, event_id=pending.event_id,
                    event_refs=[{"target": target, "native_id": native_id}
                                for target, native_id in pending.raw_refs],
                )

    def finish_cell(self) -> BaselineCell:
        if self._counter is None:
            raise RuntimeError(f"baseline cell is not open for {self.id}")
        counter, self._counter = self._counter, None
        return BaselineCell(
            spec_id=self.spec.id,
            observations=tuple(counter.observation_rows()),
            counts=tuple(counter.material_count_rows()),
            scope_hours=tuple(counter.scope_hour_rows(include_witnesses=self.spec.measure == "rate")),
            event_hours=tuple(counter.event_hour_rows()),
            pendings=counter.take_pendings(),
            partial=counter.partial,
            reasons=counter.reasons,
            partial_hours=counter.partial_hours,
            partial_host_hours=counter.partial_host_hours,
            whole_cell_partial=counter.whole_cell_partial,
        )

    def judge(self, view: SnapshotView) -> Iterable[Match]:
        return view.judge(self)

    def finalize(self) -> list[Match]:
        return []


class SshTupleBaseline(BaselinePlaybook):
    id = "bl.ssh_tuple"
    title = "SSH tuple baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    os_families = ("linux",)


class ExecPathBaseline(BaselinePlaybook):
    id = "bl.exec_path"
    title = "Executable path baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    os_families = ("linux",)


class ExecPairBaseline(BaselinePlaybook):
    id = "bl.exec_pair"
    title = "Parent and child executable baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    os_families = ("linux",)


class CommandShapeBaseline(BaselinePlaybook):
    id = "bl.cmd_shape"
    title = "Command shape baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    os_families = ("linux",)
    assures_negative = False
    positive_only_reason = "command-shape baselines publish positive deviations only"


class ExternalDestinationBaseline(BaselinePlaybook):
    id = "bl.ext_dest"
    title = "External destination baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    direction_dependent = True


class ServiceExecRateBaseline(BaselinePlaybook):
    id = "bl.svc_exec_rate"
    title = "Service-account execution rate baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    os_families = ("linux",)
    assures_negative = False
    positive_only_reason = "service-account rate baselines publish positive deviations only"


BASELINE_PLAYBOOKS = [
    SshTupleBaseline,
    ExecPathBaseline,
    ExecPairBaseline,
    CommandShapeBaseline,
    ExternalDestinationBaseline,
    ServiceExecRateBaseline,
]
