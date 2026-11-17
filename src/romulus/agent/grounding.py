"""How strongly the deterministic evidence supports what the AI narrative cites.

The narrative checker and the assessment input read one store-backed view of each cited finding: its lane, whether it
is Reported (the final ranking's Reported set; without a final ranking, the lanes the headline result follows: urgent
and high), whether it is confirmed (lane urgent), and the AI triage pass's verdict for its group. A finding supports
the narrative strongly when it is confirmed, triaged as likely or possible attack, or Reported without a likely-benign
verdict: the Reported set can hold nearly every surfaced finding, so the verdict outweighs it, while a confirmed
finding outweighs any verdict. Nothing here changes a rank, lane, Reported flag or the triage order: it only reads
them.

A cited evidence record stands for the reportable deterministic findings that cite it, found through the event index
and bounded per record; when a record has more such findings than the bound, its support is unknown (the checker
never counts unknown support as strong, and says the support could not be determined).
Findings the AI agent proposed never support the narrative here: the model must not ground its story on its own
claims. Triage verdicts are read by group (a finding's section, rule and primary target, as the triage pass grouped
it), streamed over the pass's stored groups and kept only for the groups asked about.
"""
from __future__ import annotations

from dataclasses import dataclass

from romulus.agent.triage_order import group_fields, placement
from romulus.decide import rank as rank_model
from romulus.hunt.rank import PASS_FINAL, rank_unranked
from romulus.report.markdown import SUPPORT_LABELS
from romulus.store.repo import Repo

REPORTABLE_LANES = ("urgent", "high", "lead")
# Without a final ranking the headline result follows these lanes (`Repo.detection_result`).
UNRANKED_REPORTED_LANES = ("urgent", "high")
ATTACK_VERDICTS = ("likely_attack", "possible_attack")
BENIGN_VERDICT = "likely_benign"
NOT_TRIAGED = "not_triaged"
# Verdicts usable from a triage pass in these states (a partial pass's untriaged groups read as not triaged).
USABLE_TRIAGE = ("complete", "partial")
# Reportable findings looked up per cited evidence record; one more than this makes the record's support unknown.
EVENT_FINDINGS = 50
TRIAGE_PAGE = 500


@dataclass(frozen=True)
class TriageContext:
    """The triage pass an assessment may read verdicts from, or why there is none: `status` is the pass's status
    (complete, partial, failed, skipped), `off` when AI triage is off, or `not_run` when no pass ran for it. Without a
    usable pass every finding reads as not triaged."""
    usable: bool
    status: str
    pass_no: int | None = None

    def view(self) -> dict:
        """What the assessment input says about the verdicts: whether they are available, and the pass's status."""
        return {"verdicts": "available" if self.usable else "unavailable", "status": self.status,
                **({"pass": self.pass_no} if self.pass_no is not None else {})}


def triage_context(summary: dict | None, *, enabled: bool = True) -> TriageContext:
    """The context for a triage summary the caller ran or reused for this assessment (None: none was run)."""
    if not enabled:
        return TriageContext(False, "off")
    if summary is None:
        return TriageContext(False, "not_run")
    status = str(summary.get("status") or "unknown")
    pass_no = int(summary["pass"]) if isinstance(summary.get("pass"), int) else None
    return TriageContext(status in USABLE_TRIAGE, status, pass_no)


def stored_triage_context(repo: Repo, hunt_id: str, *, enabled: bool) -> TriageContext:
    """The latest published triage pass, for an assessment run outside the agent phase."""
    from romulus.agent.triage import latest_summary
    return triage_context(latest_summary(repo, hunt_id), enabled=enabled)


@dataclass(frozen=True)
class FindingStrength:
    lane: str
    deterministic: bool
    reported: bool
    confirmed: bool
    triage: str             # an assessment, or NOT_TRIAGED
    # its triage group (`triage_order.group_fields`), for a deterministic surfaced finding
    group: tuple | None = None

    @property
    def untriaged_reported(self) -> bool:
        """Reported, not confirmed, and without any triage verdict: a cite a verdict could still weaken."""
        return self.reportable and self.reported and not self.confirmed and self.triage == NOT_TRIAGED

    @property
    def reportable(self) -> bool:
        return self.deterministic and self.lane in REPORTABLE_LANES

    @property
    def strong(self) -> bool:
        """Confirmed, or triaged as likely or possible attack, or Reported and not triaged likely benign
        (deterministic findings only). The Reported set holds nearly every surfaced finding on a busy hunt, so a
        triage verdict of likely benign outweighs it; a confirmed finding outweighs any verdict."""
        return self.reportable and (self.confirmed or self.triage in ATTACK_VERDICTS
                                    or (self.reported and self.triage != BENIGN_VERDICT))

    @property
    def benign(self) -> bool:
        """Triaged likely benign and not confirmed."""
        return self.reportable and not self.confirmed and self.triage == BENIGN_VERDICT

    @property
    def category(self) -> str:
        """The support category this finding gives a paragraph (`SUPPORT_CATEGORIES`)."""
        if not self.reportable:
            return "other"
        if self.confirmed:
            return "confirmed"
        if self.triage in ATTACK_VERDICTS:
            return "attack"
        if self.triage == BENIGN_VERDICT:
            return "benign"
        return "reported" if self.reported else "other"

    def view(self) -> dict:
        return {"lane": self.lane, "reported": self.reported, "confirmed": self.confirmed, "triage": self.triage}


# A paragraph's support summary counts its distinct cites in these categories, strongest first; a cite falls in the
# first category any of its findings gives: confirmed, triaged likely or possible attack, Reported without a
# likely-benign verdict, support unknown (the evidence lookup's cap), a raw record (observed text: a returned record
# no normalizer read), triaged likely benign, anything else (a finding neither Reported nor triaged, an AI proposal,
# a link or hypothesis).
SUPPORT_CATEGORIES = tuple(SUPPORT_LABELS)


@dataclass(frozen=True)
class CiteStrength:
    """What one cited alias rests on: the reportable deterministic findings behind it, and whether that list is
    complete. A raw record (`raw`) rests on no finding: it shows that a record with its text exists. It is never
    reportable (an observed sentence citing only raw records becomes inferred: a mention is not an action), never
    strong (citing a text hit cannot lift a paragraph out of Context) and never benign (no verdict was given on
    it)."""
    findings: tuple[FindingStrength, ...] = ()
    complete: bool = True
    raw: bool = False

    @property
    def reportable(self) -> bool:
        return bool(self.findings) or not self.complete

    @property
    def strong(self) -> bool:
        return any(item.strong for item in self.findings)

    @property
    def unknown(self) -> bool:
        return not self.complete and not self.strong

    @property
    def benign(self) -> bool:
        return self.complete and bool(self.findings) and all(item.benign for item in self.findings)

    @property
    def category(self) -> str:
        """The strongest category its findings give (`SUPPORT_CATEGORIES`); unknown when the lookup was capped and
        none of the findings it read is strong."""
        given = {item.category for item in self.findings}
        for name in ("confirmed", "attack", "reported"):
            if name in given:
                return name
        if not self.complete:
            return "unknown"
        if self.raw:
            return "raw"
        return "benign" if self.benign else "other"


class EvidenceStrength:
    """Batched, cached strength lookups for one hunt and one triage context."""

    def __init__(self, repo: Repo, hunt_id: str, triage: TriageContext):
        self.repo, self.hunt_id, self.triage = repo, hunt_id, triage
        self.ranked = repo.has_rank_pass(hunt_id, PASS_FINAL)
        self._findings: dict[str, FindingStrength | None] = {}
        self._events: dict[str, tuple[list[str], bool]] = {}

    def findings(self, ids) -> dict[str, FindingStrength]:
        """Strength of each finding id that exists in this hunt."""
        wanted = [item for item in dict.fromkeys(ids) if item not in self._findings]
        if wanted:
            rows = [row for row in self.repo.candidates_by_ids(wanted, hunt_id=self.hunt_id)
                    if row.get("hunt_id", self.hunt_id) == self.hunt_id]
            ranks = self._ranks(rows)
            groups = self._groups(rows, ranks)
            verdicts = self._verdicts(groups)
            found = {row["id"] for row in rows}
            for row in rows:
                rank = ranks.get(row["id"])
                reported = (bool(rank and rank["reported"]) if self.ranked
                            else row["lane"] in UNRANKED_REPORTED_LANES)
                self._findings[row["id"]] = FindingStrength(
                    lane=row["lane"], deterministic=row.get("provenance") != rank_model.AGENT_PROVENANCE,
                    reported=reported, confirmed=row["lane"] == rank_model.CONFIRMED_LANE,
                    triage=verdicts.get(row["id"], NOT_TRIAGED), group=groups.get(row["id"]))
            self._findings.update((item, None) for item in wanted if item not in found)
        return {item: value for item in ids if (value := self._findings.get(item)) is not None}

    def cites(self, refs) -> dict[tuple[str, str], CiteStrength]:
        """Strength of each (alias kind, target id): a finding stands for itself, an evidence record for the
        reportable deterministic findings that cite it, a raw record (Q) for observed text only; anything else rests
        on no finding."""
        refs = list(dict.fromkeys(refs))
        for kind, target in refs:
            if kind == "E" and target not in self._events:
                ids = self.repo.candidate_ids_for_event(self.hunt_id, target, REPORTABLE_LANES, EVENT_FINDINGS + 1)
                self._events[target] = (ids[:EVENT_FINDINGS], len(ids) <= EVENT_FINDINGS)
        strengths = self.findings([target for kind, target in refs if kind == "F"]
                                  + [item for kind, target in refs if kind == "E" for item in self._events[target][0]])
        out = {}
        for kind, target in refs:
            if kind == "F":
                found = strengths.get(target)
                out[(kind, target)] = CiteStrength((found,) if found is not None and found.reportable else ())
            elif kind == "E":
                ids, complete = self._events[target]
                out[(kind, target)] = CiteStrength(tuple(strengths[item] for item in ids if item in strengths
                                                         and strengths[item].reportable), complete)
            elif kind == "Q":
                out[(kind, target)] = CiteStrength(raw=True)
            else:
                out[(kind, target)] = CiteStrength()
        return out

    # -- internals ---------------------------------------------------------------------------------------------------
    def _ranks(self, rows: list[dict]) -> dict[str, dict]:
        if not self.ranked:
            return {}
        surfaced = [row for row in rows if row["lane"] in REPORTABLE_LANES]
        ranks = self.repo.finding_ranks_for(self.hunt_id, PASS_FINAL, [row["id"] for row in surfaced])
        late = rank_unranked(self.repo, self.hunt_id, [row for row in surfaced if row["id"] not in ranks])
        return {**late, **ranks}

    def _groups(self, rows: list[dict], ranks: dict[str, dict]) -> dict[str, tuple]:
        """Each deterministic surfaced finding's triage group key."""
        out = {}
        for row in rows:
            if row["lane"] not in REPORTABLE_LANES or row.get("provenance") == rank_model.AGENT_PROVENANCE:
                continue
            rank = ranks.get(row["id"])
            if self.ranked and rank is None:
                continue
            section, _order, target = placement(row, rank, self.ranked)
            out[row["id"]] = group_fields(row, section, target)
        return out

    def _verdicts(self, groups: dict[str, tuple]) -> dict[str, str]:
        """Each finding's group verdict from the usable triage pass, read by group key."""
        if not self.triage.usable:
            return {}
        keys: dict[tuple, list[str]] = {}
        for finding_id, key in groups.items():
            keys.setdefault(key, []).append(finding_id)
        out: dict[str, str] = {}
        if not keys:
            return out
        after = 0
        while page := self.repo.triage_groups(self.hunt_id, after_position=after, limit=TRIAGE_PAGE):
            for group in page:
                key = (int(group["section"]), group["provenance"], group["rule_id"], group["entity_kind"],
                       group["entity"] or "")
                if key in keys:
                    verdict = (group["assessment"] if group["status"] in ("assessed", "promoted")
                               and group["assessment"] else NOT_TRIAGED)
                    out.update((finding_id, verdict) for finding_id in keys[key])
            after = page[-1]["position"]
        return out
