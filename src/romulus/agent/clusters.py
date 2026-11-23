"""The hunt's finding clusters, and which of them no hypothesis explains yet, from typed state only.

A cluster is one incident of the deterministic incident graph over the hunt's reportable findings (urgent, high and
lead): findings joined by observed expansion links, or one finding on its own. A cluster is explained once any
hypothesis of the hunt, in any state, cites one of its findings, one of its links, or evidence one of its findings
cites (through the candidate-event index). Nothing a model wrote decides it: no statement, note or summary is read.
Agent findings never form or join a cluster, and mentions never define one: a mention is text a record contains, not
an action.

Clusters are ranked as the report orders their best finding: by the hunt's final ranking when it ran (confirmed,
reported, ranked but not reported), else by lane and priority. The graph is built over at most CLUSTER_FINDING_LIMIT
findings, the top of that order; past it the view is partial and says how many findings were not clustered, so a cap
is never read as "every cluster is explained".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from romulus.agent.dossier import MATERIALIZE_FINDING_LIMIT, REPORTABLE_LANES, _candidate_key, _report_key
from romulus.report.incidents import build_incident_graph
from romulus.store.repo import FINAL_RANK_PASS, Repo

# The most findings the cluster graph is built over: the dossier's own materialization cap, so the agent's view of
# the hunt and its clusters agree on what was evaluated.
CLUSTER_FINDING_LIMIT = MATERIALIZE_FINDING_LIMIT
# Findings read per page when the hunt has more reportable findings than the limit.
_PAGE = 1_000
# The findings an evidence cite can map to (through the candidate-event index), per cited event.
EVIDENCE_FINDINGS_LIMIT = 50
# The findings, clusters and hosts a hypothesis card's leads list by name (the rest are counted), and the characters
# of a listed rule id, host or claim.
LEADS_LIMIT = 8
LEADS_TEXT_LIMIT = 160
LEADS_FOCUS = (
    "Every finding counted here is already reported by a deterministic rule; proving it again adds nothing. Use the "
    "findings as anchors to find what no finding covers: activity before and after them on the same hosts and "
    "accounts, other hosts the same account, address, file or parent process reached, and the clusters' open ends. "
    "Read the findings no hypothesis cites yet first. Not cited is not benign, and records not found are never an "
    "absence.")


@dataclass(frozen=True, eq=False)     # one object per incident in a view: compared and hashed by identity
class Cluster:
    key: str                         # the incident's id
    finding_ids: tuple[str, ...]     # its deterministic findings, best first in report order
    link_ids: tuple[str, ...]        # the expansion links anchored in it
    top: dict                        # the best finding's candidate row
    order: tuple                     # the report order of its best finding
    open_ends: dict = field(default_factory=dict)   # open expansion ends by kind, counted


@dataclass
class ClusterView:
    clusters: list[Cluster]
    by_finding: dict[str, Cluster]
    by_link: dict[str, Cluster]
    findings: int                    # reportable deterministic findings in the hunt
    clustered: int                   # of them, those the graph was built over
    incidents: dict[str, dict] = field(default_factory=dict)   # the graph's incidents by id

    @property
    def partial(self) -> dict | None:
        if self.clustered >= self.findings:
            return None
        return {"reason": f"cap:cluster_findings:{CLUSTER_FINDING_LIMIT}",
                "findings_not_clustered": self.findings - self.clustered}


def _reportable(repo: Repo, hunt_id: str) -> tuple[list[dict], int]:
    """The hunt's reportable deterministic findings the graph is built over (at most CLUSTER_FINDING_LIMIT, the top
    of the lane and priority order), and how many there are in all."""
    total = repo.candidate_count_lanes(hunt_id, REPORTABLE_LANES)
    if total <= CLUSTER_FINDING_LIMIT:
        rows = repo.candidates(hunt_id, list(REPORTABLE_LANES), provenance="deterministic")
        return rows, len(rows)
    rows: list[dict] = []
    offset = 0
    while len(rows) < CLUSTER_FINDING_LIMIT:
        page = repo.candidate_page(hunt_id, offset=offset, limit=_PAGE)
        if not page:
            break
        offset += len(page)
        rows.extend(row for row in page if row["lane"] in REPORTABLE_LANES
                    and row.get("provenance", "deterministic") == "deterministic")
        if page[-1]["lane"] not in REPORTABLE_LANES:
            break      # the page order is lane first: no reportable finding comes after a context one
    rows = rows[:CLUSTER_FINDING_LIMIT]
    # the agent's own findings (bounded by its per-hunt cap) are counted out of the total; they never cluster
    deterministic = total - len(repo.candidates(hunt_id, list(REPORTABLE_LANES), provenance="agent"))
    return rows, max(deterministic, len(rows))


def hunt_clusters(repo: Repo, hunt_id: str) -> ClusterView:
    """The hunt's clusters in report order of their best finding."""
    rows, total = _reportable(repo, hunt_id)
    if not rows:
        return ClusterView([], {}, {}, total, 0)
    by_id = {row["id"]: row for row in rows}
    if repo.has_rank_pass(hunt_id, FINAL_RANK_PASS):
        ranks = repo.finding_ranks_for(hunt_id, FINAL_RANK_PASS, list(by_id))
        keys = {row["id"]: _report_key(row, ranks.get(row["id"])) for row in rows}
    else:
        keys = {row["id"]: (0, 0, _candidate_key(row)) for row in rows}
    graph = build_incident_graph(repo, hunt_id, [{
        "id": row["id"], "lane": row["lane"], "rule_id": row["rule_id"],
        "observed_at": str(row["ts"]) if row["ts"] is not None else None, "entities": row.get("entities") or [],
        "event_ids": row.get("event_ids") or [], "citations": [], "source_link_id": row.get("source_link_id"),
    } for row in rows], include_agent_links=False)
    clusters: list[Cluster] = []
    incidents: dict[str, dict] = {}
    for incident in graph["incidents"]:
        members = sorted((item for item in incident["finding_ids"] if item in by_id), key=lambda item: keys[item])
        if not members:
            continue
        incidents[incident["id"]] = incident
        clusters.append(Cluster(
            key=incident["id"], finding_ids=tuple(members), link_ids=tuple(sorted(incident["link_ids"])),
            top=by_id[members[0]], order=keys[members[0]],
            open_ends={kind: len(values) for kind, values in sorted((incident.get("open_ends") or {}).items())
                       if values}))
    clusters.sort(key=lambda cluster: (cluster.order, cluster.key))
    by_finding = {item: cluster for cluster in clusters for item in cluster.finding_ids}
    by_link = {item: cluster for cluster in clusters for item in cluster.link_ids}
    return ClusterView(clusters, by_finding, by_link, total, len(rows), incidents)


def cited_findings(repo: Repo, hunt_id: str, view: ClusterView) -> set[str]:
    """The reportable findings any hypothesis of the hunt explains: cited as findings, through the evidence they cite,
    or as members of a cluster whose link a hypothesis cites."""
    out: set[str] = set()
    events: set[str] = set()
    for cite in repo.agent_hypothesis_cites(hunt_id=hunt_id):
        kind, target = cite["target_kind"], str(cite["target_id"])
        if kind == "finding":
            out.add(target)
        elif kind == "evidence":
            events.add(target)
        elif kind == "link" and target in view.by_link:
            out.update(view.by_link[target].finding_ids)
    for event in sorted(events):
        out.update(repo.candidate_ids_for_event(hunt_id, event, REPORTABLE_LANES, EVIDENCE_FINDINGS_LIMIT))
    return out


def _host(row: dict) -> str | None:
    for item in row.get("entities") or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == "host" and item[1] not in (None, ""):
            return str(item[1])
    return None


def hypothesis_leads(repo: Repo, hunt_id: str, hypothesis_id: str, aliases, view: ClusterView) -> dict | None:
    """What an investigate session's card says about where to look, from typed state only: the clusters the
    hypothesis's cited findings (or the findings citing its cited evidence) belong to, how many of their findings
    are already reported, the ones no hypothesis cites yet (best first, at most LEADS_LIMIT, the rest counted), the
    clusters' open expansion ends, and how many findings the agent has already proposed. None when the hypothesis
    cites no clustered finding. Every finding listed is a deterministic, already reported finding: it is an anchor to
    widen from, not something to prove again."""
    own: set[str] = set()
    events: set[str] = set()
    for cite in repo.agent_hypothesis_cites(hypothesis_id=hypothesis_id):
        if cite["target_kind"] == "finding":
            own.add(str(cite["target_id"]))
        elif cite["target_kind"] == "evidence":
            events.add(str(cite["target_id"]))
        elif cite["target_kind"] == "link" and str(cite["target_id"]) in view.by_link:
            own.update(view.by_link[str(cite["target_id"])].finding_ids)
    for event in sorted(events):
        own.update(repo.candidate_ids_for_event(hunt_id, event, REPORTABLE_LANES, EVIDENCE_FINDINGS_LIMIT))
    mine = list(dict.fromkeys(view.by_finding[item] for item in sorted(own) if item in view.by_finding))
    if not mine:
        return None
    mine.sort(key=lambda cluster: (cluster.order, cluster.key))
    explained = cited_findings(repo, hunt_id, view)
    members = [item for cluster in mine for item in cluster.finding_ids]
    rows = {row["id"]: row for cluster in mine for row in [cluster.top]}
    uncited = [item for item in members if item not in explained]
    shown = uncited[:LEADS_LIMIT]
    if shown:
        rows.update({row["id"]: row for row in repo.candidates_by_ids(shown, hunt_id=hunt_id)})
    hosts = list(dict.fromkeys(host for row in [*(cluster.top for cluster in mine), *(rows[i] for i in shown
                                                                                      if i in rows)]
                               for host in [_host(row)] if host))
    agent_findings = len(repo.candidates(hunt_id, list(REPORTABLE_LANES), provenance="agent"))
    return {
        "clusters": [{"incident": aliases.alias_for("I", cluster.key), "findings": len(cluster.finding_ids),
                      "cited_by_hypotheses": sum(item in explained for item in cluster.finding_ids),
                      "open_ends": dict(cluster.open_ends)} for cluster in mine[:LEADS_LIMIT]],
        "already_reported_findings": len(members),
        "not_yet_cited": [{"alias": aliases.alias_for("F", item), "lane": rows[item]["lane"],
                           "rule_id": _bounded(rows[item]["rule_id"]), "host": _bounded(_host(rows[item])),
                           "claim": _bounded(rows[item]["claim"])} for item in shown if item in rows],
        "not_yet_cited_more": max(0, len(uncited) - len(shown)),
        "hosts": [_bounded(host) for host in hosts[:LEADS_LIMIT]],
        "agent_findings_proposed": agent_findings,
        "focus": LEADS_FOCUS,
    }


def _bounded(value, limit: int = LEADS_TEXT_LIMIT):
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else f"{text[:limit]}…"


def unexplained_clusters(repo: Repo, hunt_id: str, view: ClusterView | None = None) -> list[Cluster]:
    """The clusters no hypothesis explains yet, in report order of their best finding."""
    view = view if view is not None else hunt_clusters(repo, hunt_id)
    explained = cited_findings(repo, hunt_id, view)
    return [cluster for cluster in view.clusters if not explained.intersection(cluster.finding_ids)]
