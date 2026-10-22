"""Durable, deterministic short aliases for model-visible hunt objects."""
from __future__ import annotations

from collections.abc import Iterable

from romulus.decide.policy import LANE_ORDER
from romulus.store.repo import Repo

ALIAS_KINDS = frozenset({"F", "I", "E", "N", "L"})


class AliasError(ValueError):
    """Base class for typed alias failures returned by agent tools."""


class UnknownAlias(AliasError):
    pass


class AliasKindMismatch(AliasError):
    pass


class AliasFromOtherHunt(AliasError):
    pass


class AliasBook:
    """Map model-visible aliases to hunt-scoped database identifiers.

    Existing findings and entities are assigned in content order so independently
    populated twin databases produce the same aliases. Later objects append within
    their own kind-specific sequence.
    """

    def __init__(self, repo: Repo, hunt_id: str):
        if repo.get_hunt(hunt_id) is None:
            raise KeyError(hunt_id)
        self.repo = repo
        self.hunt_id = hunt_id
        findings = sorted(
            repo.candidates(hunt_id),
            key=lambda row: (
                LANE_ORDER.get(row["lane"], 99), -float(row["priority"]), row["ts"], row["id"],
            ),
        )
        seeds = [("F", row["id"]) for row in findings]
        seeds.extend(("N", row["id"]) for row in repo.entities(hunt_id))
        repo.seed_agent_aliases(hunt_id, seeds)

    @staticmethod
    def _check_kind(kind: str) -> None:
        if kind not in ALIAS_KINDS:
            raise AliasKindMismatch(f"unknown alias kind {kind!r}; expected one of {sorted(ALIAS_KINDS)}")

    def _persist(self, kind: str, target_id: str) -> str:
        return self.repo.get_or_create_agent_alias(self.hunt_id, kind, target_id)["alias"]

    def alias_for(self, kind: str, target_id: str) -> str:
        self._check_kind(kind)
        owners = self.repo.agent_alias_target_hunts(kind, target_id)
        if owners and self.hunt_id not in owners:
            raise AliasFromOtherHunt(
                f"{kind} target {target_id!r} belongs to another hunt, not {self.hunt_id}",
            )
        if kind in {"F", "E", "N", "L"} and not owners:
            raise UnknownAlias(f"unknown {kind} target {target_id!r} in hunt {self.hunt_id}")
        return self._persist(kind, target_id)

    def resolve(self, alias: str, expected_kinds: Iterable[str]) -> str:
        expected = frozenset(expected_kinds)
        for kind in expected:
            self._check_kind(kind)
        row = self.repo.agent_alias(self.hunt_id, alias)
        if row is None:
            raise UnknownAlias(f"unknown alias {alias!r} in hunt {self.hunt_id}")
        if row["kind"] not in expected:
            raise AliasKindMismatch(
                f"alias {alias!r} is kind {row['kind']}; expected one of {sorted(expected)}",
            )
        return row["target_id"]
