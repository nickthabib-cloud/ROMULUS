"""The hunt's finding clusters, and which of them no hypothesis explains yet, from typed state only.

A cluster is one incident of the deterministic incident graph over the hunt's reportable findings (urgent, high and
lead): findings joined by observed expansion links, or one finding on its own. A cluster is explained once a
hypothesis of the hunt, in any state, was opened citing one of its findings, one of its links, or evidence one of
its findings cites (through the candidate-event index), and the cluster is among the best CLUSTERS_PER_HYPOTHESIS
those opening cites reach; later cites never change it, so explanation is monotone. Nothing a model wrote decides it: no statement, note or summary is read.
Agent findings never form or join a cluster, and mentions never define one: a mention is text a record contains, not
an action.

Clusters are ranked as the report orders their best finding: by the hunt's final ranking when it ran (confirmed,
reported, ranked but not reported), else by lane and priority. The graph is built over at most CLUSTER_FINDING_LIMIT
findings: past that many, the findings clustered are the top of the store's lane and priority order (read in keyset
pages, so the selection stays bounded without loading the ranking for every finding), and the clusters among them are
ranked as above. The view is then partial and says how many findings were not clustered, so a cap is never read as
"every cluster is explained"; the run records the cap and how many clusters were left unexplained.
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
# The most clusters one hypothesis explains. A session (tens of tool calls) can examine a few clusters closely, not a
# hunt's worth; a broad hypothesis citing more explains only its best three in report order, and the rest get
# hypotheses of their own. Three covers a hypothesis that links an intrusion's steps across a few hosts' clusters.
CLUSTERS_PER_HYPOTHESIS = 3
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
    """The reportable findings any hypothesis of the hunt cites (as findings, through the evidence they cite, or as
    members of a cluster whose link a hypothesis cites). A cite is not an explanation: which clusters are explained
    is `explanations`."""
    return set().union(*_cites_by_hypothesis(repo, hunt_id, view).values())


def _host(row: dict) -> str | None:
    for item in row.get("entities") or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == "host" and item[1] not in (None, ""):
            return str(item[1])
    return None


def _cites_by_hypothesis(repo: Repo, hunt_id: str, view: ClusterView) -> dict[str, set[str]]:
    """Every reportable finding each hypothesis of the hunt cites: as a finding, through the evidence it cites, or as
    a member of the cluster of a link it cites."""
    out: dict[str, set[str]] = {}
    mapped: dict[str, list[str]] = {}
    for cite in repo.agent_hypothesis_cites(hunt_id=hunt_id):
        hypothesis, kind, target = str(cite["hypothesis_id"]), cite["target_kind"], str(cite["target_id"])
        found = out.setdefault(hypothesis, set())
        if kind == "finding":
            found.add(target)
        elif kind == "evidence":
            if target not in mapped:
                mapped[target] = repo.candidate_ids_for_event(hunt_id, target, REPORTABLE_LANES,
                                                              EVIDENCE_FINDINGS_LIMIT)
            found.update(mapped[target])
        elif kind == "link" and target in view.by_link:
            found.update(view.by_link[target].finding_ids)
    return out


def hypothesis_leads(repo: Repo, hunt_id: str, hypothesis_id: str, aliases, view: ClusterView) -> dict | None:
    """What an investigate session's card says about where to look, from typed state only and as the controller sees
    it (`explanations`): the clusters this hypothesis explains, how many hypotheses explain each, how many of their
    findings are already reported, the ones no hypothesis explaining that cluster cites yet (best first, at most
    LEADS_LIMIT, the rest counted), the clusters' open expansion ends, and how many findings the agent has already
    proposed. None when the hypothesis explains no cluster. Every finding listed is a deterministic, already reported
    finding: it is an anchor to widen from, not something to prove again."""
    explained = explanations(repo, hunt_id, view)
    by_key = {cluster.key: cluster for cluster in view.clusters}
    mine = [by_key[key] for key in explained.get(hypothesis_id) or [] if key in by_key]
    if not mine:
        return None
    cites = _cites_by_hypothesis(repo, hunt_id, view)
    explainers = {cluster.key: [h for h, keys in explained.items() if cluster.key in keys] for cluster in mine}
    cited = {key: set().union(*(cites.get(h, set()) for h in hypotheses)) if hypotheses else set()
             for key, hypotheses in explainers.items()}
    members = [item for cluster in mine for item in cluster.finding_ids]
    rows = {row["id"]: row for cluster in mine for row in [cluster.top]}
    uncited = [item for cluster in mine for item in cluster.finding_ids if item not in cited[cluster.key]]
    shown = uncited[:LEADS_LIMIT]
    if shown:
        rows.update({row["id"]: row for row in repo.candidates_by_ids(shown, hunt_id=hunt_id)})
    hosts = list(dict.fromkeys(host for row in [*(cluster.top for cluster in mine), *(rows[i] for i in shown
                                                                                      if i in rows)]
                               for host in [_host(row)] if host))
    agent_findings = len(repo.candidates(hunt_id, list(REPORTABLE_LANES), provenance="agent"))
    return {
        "clusters": [{"incident": aliases.alias_for("I", cluster.key), "findings": len(cluster.finding_ids),
                      "explained_by_hypotheses": len(explainers[cluster.key]),
                      "findings_cited": sum(item in cited[cluster.key] for item in cluster.finding_ids),
                      "open_ends": dict(cluster.open_ends)} for cluster in mine],
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


def _opening_cites(repo: Repo, hypothesis: dict) -> list[tuple[str, str]] | None:
    """The cites a hypothesis was opened with, as (target kind, target id), from its opened event: the controller's
    finding, or the supporting cites open_hypothesis took. None for a hypothesis whose event does not record them
    (one opened before it did)."""
    for event in repo.agent_hypothesis_events(hypothesis["id"]):
        if event["kind"] != "opened":
            continue
        payload = event.get("payload") or {}
        if payload.get("by") == "controller" and payload.get("finding_id"):
            return [("finding", str(payload["finding_id"]))]
        if isinstance(payload.get("supporting"), list):
            return [(str(item.get("kind")), str(item.get("id"))) for item in payload["supporting"]
                    if isinstance(item, dict)]
        return None
    return None


def explanations(repo: Repo, hunt_id: str, view: ClusterView) -> dict[str, list[str]]:
    """For each hypothesis of the hunt, the keys of the clusters it explains, best first: the clusters the cites it
    was opened with reach (findings, findings citing its evidence, a link's cluster), at most CLUSTERS_PER_HYPOTHESIS
    of them, the best in report order. They are fixed when it opens, so explanation is monotone: what a session cites
    later never moves a hypothesis off the cluster it was opened for, and a cluster once explained stays explained
    (the controller never opens a second hypothesis for it). A hypothesis whose opened event does not record its cites
    is read from all its cites, with the same limit."""
    cites: dict[str, list[tuple[str, str]]] = {}
    for cite in repo.agent_hypothesis_cites(hunt_id=hunt_id):
        cites.setdefault(str(cite["hypothesis_id"]), []).append((cite["target_kind"], str(cite["target_id"])))
    mapped: dict[str, list[str]] = {}

    def reach(pairs: list[tuple[str, str]]) -> list[str]:
        ids: set[str] = set()
        for kind, target in pairs:
            if kind == "finding":
                ids.add(target)
            elif kind == "evidence":
                if target not in mapped:
                    mapped[target] = repo.candidate_ids_for_event(hunt_id, target, REPORTABLE_LANES,
                                                                  EVIDENCE_FINDINGS_LIMIT)
                ids.update(mapped[target])
            elif kind == "link" and target in view.by_link:
                ids.update(view.by_link[target].finding_ids)
        reached = {view.by_finding[item].key: view.by_finding[item] for item in ids if item in view.by_finding}
        best = sorted(reached.values(), key=lambda cluster: (cluster.order, cluster.key))
        return [cluster.key for cluster in best[:CLUSTERS_PER_HYPOTHESIS]]

    out: dict[str, list[str]] = {}
    for hypothesis in repo.agent_hypotheses(hunt_id):
        opening = _opening_cites(repo, hypothesis)
        out[hypothesis["id"]] = reach(opening if opening is not None else cites.get(hypothesis["id"], []))
    return out


def explained_clusters(repo: Repo, hunt_id: str, view: ClusterView) -> set[str]:
    """The keys of the clusters any hypothesis of the hunt explains (`explanations`)."""
    return {key for keys in explanations(repo, hunt_id, view).values() for key in keys}


def controller_clusters(repo: Repo, hunt_id: str, view: ClusterView) -> set[str]:
    """The keys of the clusters the controller has already opened a hypothesis for (by its opened event)."""
    out: set[str] = set()
    for hypothesis in repo.agent_hypotheses(hunt_id):
        for event in repo.agent_hypothesis_events(hypothesis["id"]):
            payload = event.get("payload") or {}
            if event["kind"] == "opened" and payload.get("by") == "controller":
                finding = str(payload.get("finding_id") or "")
                if finding in view.by_finding:
                    out.add(view.by_finding[finding].key)
    return out


def unexplained_clusters(repo: Repo, hunt_id: str, view: ClusterView | None = None) -> list[Cluster]:
    """The clusters no hypothesis explains yet (`explained_clusters`), in report order of their best finding."""
    view = view if view is not None else hunt_clusters(repo, hunt_id)
    explained = explained_clusters(repo, hunt_id, view)
    return [cluster for cluster in view.clusters if cluster.key not in explained]
