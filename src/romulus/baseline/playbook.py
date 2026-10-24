"""Sweep-facing baseline playbooks and their cell-scoped accumulation contract."""
from __future__ import annotations

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
    pendings: tuple[Pending, ...]
    partial: bool
    reasons: tuple[str, ...]


class SnapshotView(Protocol):
    """The post-lookback judge supplied by the hunt-layer baseline stage."""

    def judge(self, playbook: BaselinePlaybook) -> list[Match]: ...


class BaselinePlaybook(Playbook):
    """A baseline spec as a playbook: count during sweep, publish only from a frozen snapshot."""

    kind: ClassVar[str] = "baseline"
    claim_type: ClassVar[str] = "anomaly"
    severity: ClassVar[str] = "info"
    lane: ClassVar[str] = "lead"
    anchor_class: ClassVar[str] = "baseline"
    spec: ClassVar[BaselineSpec]

    def __init__(self) -> None:
        super().__init__()
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
            raise RuntimeError(f"baseline cell is not open for {self.id}")
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
                self._counter.mark_partial(f"{pending.event_id}: {resolution.reason}")
            else:
                self._counter.add_keys(pending.ts, resolution.keys, event_id=pending.event_id)

    def finish_cell(self) -> BaselineCell:
        if self._counter is None:
            raise RuntimeError(f"baseline cell is not open for {self.id}")
        counter, self._counter = self._counter, None
        return BaselineCell(
            spec_id=self.spec.id,
            observations=tuple(counter.observation_rows()),
            pendings=counter.take_pendings(),
            partial=counter.partial,
            reasons=counter.reasons,
        )

    def judge(self, view: SnapshotView) -> list[Match]:
        return view.judge(self)

    def finalize(self) -> list[Match]:
        return []


class SshTupleBaseline(BaselinePlaybook):
    id = "bl.ssh_tuple"
    title = "SSH tuple baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families


class ExecPathBaseline(BaselinePlaybook):
    id = "bl.exec_path"
    title = "Executable path baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families


class ExecPairBaseline(BaselinePlaybook):
    id = "bl.exec_pair"
    title = "Parent and child executable baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families


class CommandShapeBaseline(BaselinePlaybook):
    id = "bl.cmd_shape"
    title = "Command shape baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    assures_negative = False
    positive_only_reason = "command-shape baselines publish positive deviations only"


class ExternalDestinationBaseline(BaselinePlaybook):
    id = "bl.ext_dest"
    title = "External destination baseline"
    spec = SPEC_BY_ID[id]
    families = spec.families
    direction_dependent = True


BASELINE_PLAYBOOKS = [
    SshTupleBaseline,
    ExecPathBaseline,
    ExecPairBaseline,
    CommandShapeBaseline,
    ExternalDestinationBaseline,
]
