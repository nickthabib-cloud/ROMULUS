"""Deterministic behavioral summaries for analyst reasoning.

The model should reason over compact distributions and cited observations, not
an arbitrary handful of raw rows. These routines make no malicious/benign
decision; they describe rarity, fan-out, cadence, sequences, and data quality.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import ipaddress
import math
import re
from typing import Any, Iterable

from ..investigation.scheduler import outcome_resolves


def summarize_evidence(host_events: list[dict], network_events: list[dict], limit: int = 12) -> dict[str, Any]:
    all_events = list(host_events) + list(network_events)
    source_counts = Counter(str(e.get("source") or "unknown") for e in all_events)
    times = [(stamp, e) for e in all_events if (stamp := _time(e.get("observed_at"))) is not None]
    host_assets = Counter(_values(e, ("host.name", "host.hostname", "host.ip"), include_asset=True)[0]
                          for e in host_events if _values(e, ("host.name", "host.hostname", "host.ip"), include_asset=True))
    processes = Counter(x.lower() for e in host_events for x in _values(e, ("process.name", "process.executable", "process.parent.name")))
    users = Counter(x.lower() for e in host_events for x in _values(e, ("user.name", "winlog.event_data.SubjectUserName", "account.name")))
    event_codes = Counter(x for e in host_events for x in _values(e, ("event.code", "event.id", "winlog.event_id", "event_id")))

    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    edge_counts: Counter[tuple[str, str, str]] = Counter()
    fanout: dict[str, set[str]] = defaultdict(set)
    fanout_ports: dict[str, set[str]] = defaultdict(set)
    edge_events: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    byte_rows: list[tuple[int, dict]] = []
    for event in network_events:
        srcs = _values(event, ("source.ip", "srcIp", "src_ip", "ip.src", "ipSource"))
        dsts = _values(event, ("destination.ip", "dstIp", "dst_ip", "ip.dst", "ipDestination"))
        ports = _values(event, ("destination.port", "dstPort", "dst_port", "tcp.dstport", "udp.dstport", "port"))
        protocols = _values(event, ("network.protocol", "network.transport", "network.application", "protocol", "protocols", "ipProtocol"))
        domains = _values(event, ("dns.question.name", "dns.qry.name", "dns.host", "http.host", "host.http", "tls.handshake.extensions_server_name"))
        src_counts.update(srcs); dst_counts.update(dsts); port_counts.update(ports)
        protocol_counts.update(x.lower() for x in protocols); domain_counts.update(x.lower() for x in domains)
        src = srcs[0] if srcs else "?"; dst = dsts[0] if dsts else "?"; port = ports[0] if ports else "?"
        if src != "?" and dst != "?":
            edge = (src, dst, port); edge_counts[edge] += 1; edge_events[edge].append(event)
            fanout[src].add(dst)
            if port != "?": fanout_ports[src].add(port)
        byte_value = _first_number(event, ("network.bytes", "totBytes", "bytes", "source.bytes", "destination.bytes"))
        if byte_value is not None: byte_rows.append((byte_value, event))

    authentication = _authentication_sequences(host_events, limit)
    periodic = _periodic_edges(edge_events, limit)
    high_fanout = []
    for src in sorted(fanout, key=lambda x: (len(fanout[x]), len(fanout_ports[x])), reverse=True)[:limit]:
        refs = [e.get("evidence_id") for edge, rows in edge_events.items() if edge[0] == src for e in rows[:1] if e.get("evidence_id")]
        high_fanout.append({"source": src, "unique_destinations": len(fanout[src]),
                            "unique_destination_ports": len(fanout_ports[src]), "sample_evidence_ids": refs[:4]})
    rare_external = []
    for destination, count in sorted(dst_counts.items(), key=lambda item: (item[1], item[0])):
        if count > 2 or not _external_ip(destination): continue
        refs = [e.get("evidence_id") for e in network_events if destination in _values(e, ("destination.ip", "dstIp", "dst_ip", "ip.dst")) and e.get("evidence_id")]
        rare_external.append({"destination": destination, "observations": count, "sample_evidence_ids": refs[:3]})
        if len(rare_external) >= limit: break

    signals = _behavior_signals(all_events, limit)
    aggregate_signals = _aggregate_signal_rows(
        host_events, network_events, authentication, high_fanout, periodic, rare_external, limit
    )
    quality = {
        "events_total": len(all_events),
        "timestamp_coverage_pct": _percent(len(times), len(all_events)),
        "host_entity_coverage_pct": _percent(sum(bool(_values(e, ("host.name", "host.hostname", "host.ip"), True)) for e in host_events), len(host_events)),
        "network_endpoint_coverage_pct": _percent(sum(bool(_values(e, ("source.ip", "srcIp", "ip.src"))) and bool(_values(e, ("destination.ip", "dstIp", "ip.dst"))) for e in network_events), len(network_events)),
    }
    return {
        "scope": {"host_events": len(host_events), "network_events": len(network_events),
                  "sources": dict(source_counts),
                  "first_observed": min((x[0] for x in times), default=None).isoformat() if times else None,
                  "last_observed": max((x[0] for x in times), default=None).isoformat() if times else None},
        "telemetry_quality": quality,
        "host_profile": {"top_assets": _top(host_assets, limit), "top_processes": _top(processes, limit),
                         "top_users": _top(users, limit), "top_event_codes": _top(event_codes, limit),
                         "authentication_sequences": authentication},
        "network_profile": {"top_sources": _top(src_counts, limit), "top_destinations": _top(dst_counts, limit),
                            "top_destination_ports": _top(port_counts, limit), "top_protocols": _top(protocol_counts, limit),
                            "top_domains": _top(domain_counts, limit), "high_fanout": high_fanout,
                            "low_frequency_external_destinations": rare_external, "periodic_edge_candidates": periodic,
                            "largest_byte_records": [{"bytes": value, "evidence_id": event.get("evidence_id")} for value, event in sorted(byte_rows, reverse=True, key=lambda x: x[0])[:limit]]},
        "behavioral_observations": signals,
        "aggregate_signals": aggregate_signals,
    }


def _task_outcome_resolves(outcome: dict | None) -> bool:
    return outcome_resolves(outcome or {})


def build_coverage_ledger(
    hypotheses: list[dict],
    search_tasks: dict[str, dict] | list[dict],
    search_outcomes: list[dict],
    host_available: bool,
    network_available: bool,
    candidates: list[dict] | None = None,
) -> dict[str, Any]:
    """Derive closure only from exact scheduler ownership and outcomes."""
    tasks = list(search_tasks.values()) if isinstance(search_tasks, dict) else list(search_tasks or [])
    outcomes_by_task: dict[str, dict] = {}
    for outcome in search_outcomes or []:
        if isinstance(outcome, dict) and outcome.get("task_id"):
            outcomes_by_task[str(outcome["task_id"])] = outcome
    unavailable_families = ({"host"} if not host_available else set()) | ({"network"} if not network_available else set())

    rows = []
    for hypothesis in hypotheses:
        hid = hypothesis.get("hypothesis_id")
        planned = [task for task in tasks if hid and hid in (task.get("hypothesis_ids") or [])]
        attempted = [task for task in planned if str(task.get("task_id")) in outcomes_by_task]
        resolved = [task for task in attempted if _task_outcome_resolves(outcomes_by_task.get(str(task.get("task_id"))))]
        sources = sorted({str(task.get("source_family")) for task in attempted if task.get("source_family")})
        returned = sum(int(outcomes_by_task[str(task["task_id"])].get("returned_total") or 0)
                       for task in attempted if str(task.get("task_id")) in outcomes_by_task)
        assessment = (hypothesis.get("model_assessment") if isinstance(hypothesis.get("model_assessment"), dict)
            else hypothesis.get("deterministic_assessment") if isinstance(hypothesis.get("deterministic_assessment"), dict) else {})
        gaps = []
        if hypothesis.get("expected_host") and not host_available: gaps.append("host telemetry unavailable")
        if hypothesis.get("expected_network") and not network_available: gaps.append("network telemetry unavailable")
        required_families=({"host"} if hypothesis.get("expected_host") else set()) | ({"network"} if hypothesis.get("expected_network") else set())
        status = assessment.get("status") or ("searched_unassessed" if attempted else "untested")
        assessment_cited = status in {"supported", "contradicted", "inconclusive"} and bool(assessment.get("evidence_ids"))
        all_planned_resolved = bool(planned) and len(resolved) == len(planned)
        unresolved = [task for task in planned if task not in resolved]
        available_required=required_families-unavailable_families
        available_requirements_tested=all(any(str(task.get("source_family"))==family for task in resolved)
            for family in available_required)
        explicit_gap_closure = bool(gaps) and available_requirements_tested and all(
            str(task.get("source_family")) in unavailable_families for task in unresolved)
        closed = (all_planned_resolved and assessment_cited) or explicit_gap_closure
        rows.append({"hypothesis_id":hid,"technique_id":hypothesis.get("technique_id"),
            "priority":hypothesis.get("priority",3),"tactics":hypothesis.get("tactics",[]),
            "planned_analytics":len(planned),"executed_analytics":len(attempted),
            "resolved_analytics":len(resolved),"sources":sources,"returned":returned,
            "assessment":status,"telemetry_gaps":gaps,
            "unresolved_task_ids":[task.get("task_id") for task in unresolved],"closed":closed})

    high = [row for row in rows if int(row.get("priority") or 3) >= 4]
    candidate_rows = []
    for candidate in candidates or []:
        candidate_id = candidate.get("candidate_id")
        actionable = (candidate.get("priority_tier") in {"high", "critical"}
            or candidate.get("kind") == "trusted_indicator" or bool(candidate.get("customer_visible")))
        unfinished = []
        unresolved_task_ids = []
        for follow_up in candidate.get("follow_ups", []) or []:
            follow_up_id = follow_up.get("follow_up_id")
            owned = [task for task in tasks
                if candidate_id in (task.get("candidate_ids") or [])
                and follow_up_id in (task.get("follow_up_ids") or [])]
            resolved_owned = [task for task in owned
                if _task_outcome_resolves(outcomes_by_task.get(str(task.get("task_id"))))]
            unresolved_owned = [task for task in owned if task not in resolved_owned]
            source_gap = bool(unresolved_owned) and all(
                str(task.get("source_family")) in unavailable_families for task in unresolved_owned
            )
            explicitly_not_applicable = follow_up.get("status") == "not_applicable"
            explicit_telemetry_gap=(follow_up.get("status")=="skipped_due_gap"
                and bool(candidate.get("telemetry_gaps")))
            if not ((owned and len(resolved_owned) == len(owned)) or source_gap
                    or explicitly_not_applicable or explicit_telemetry_gap):
                unfinished.append(follow_up_id)
                unresolved_task_ids.extend(task.get("task_id") for task in unresolved_owned)
        disposition = str(candidate.get("disposition") or "observed")
        if disposition in {"benign_likely", "dismissed"}:
            closed = not unfinished
        elif disposition == "unresolved":
            closed = bool(candidate.get("telemetry_gaps")) and not unfinished
        elif disposition == "corroborated":
            closed = bool(candidate.get("finding_ids")) and not unfinished
        else:
            closed = False
        candidate_rows.append({"candidate_id":candidate_id,"priority_tier":candidate.get("priority_tier"),
            "disposition":disposition,"actionable":actionable,"unfinished_follow_up_ids":unfinished,
            "unresolved_task_ids":list(dict.fromkeys(unresolved_task_ids)),
            "finding_ids":candidate.get("finding_ids",[]),"telemetry_gaps":candidate.get("telemetry_gaps",[]),
            "closed":closed})
    actionable_candidates = [item for item in candidate_rows if item["actionable"]]
    open_candidate_ids=[item["candidate_id"] for item in actionable_candidates if not item["closed"]]
    candidate_detail_limit=100
    hypothesis_ready = all(bool(item["closed"]) for item in high)
    candidate_ready = all(item["closed"] for item in actionable_candidates)
    return {"rows":rows,"high_priority_total":len(high),
        "high_priority_tested":sum(item["executed_analytics"]>0 or bool(item["telemetry_gaps"]) for item in high),
        "high_priority_closed":sum(bool(item["closed"]) for item in high),
        "untested_hypotheses":[item["hypothesis_id"] for item in rows
            if not item["executed_analytics"] and not item["telemetry_gaps"]],
        "candidate_rows":candidate_rows[:candidate_detail_limit],
        "candidate_rows_total":len(candidate_rows),
        "candidate_detail_limit":candidate_detail_limit,
        "candidate_details_truncated":len(candidate_rows)>candidate_detail_limit,
        "actionable_candidates":len(actionable_candidates),
        "open_candidate_count":len(open_candidate_ids),
        "open_candidate_ids":open_candidate_ids[:candidate_detail_limit],
        "hypothesis_closure_ready":hypothesis_ready,"candidate_closure_ready":candidate_ready,
        "closure_ready":hypothesis_ready and candidate_ready}


def _authentication_sequences(events: list[dict], limit: int) -> list[dict]:
    grouped: dict[tuple[str, str], list[tuple[datetime, str, str]]] = defaultdict(list)
    for event in events:
        code = next(iter(_values(event, ("event.code", "event.id", "winlog.event_id", "event_id"))), "")
        text = _event_text(event)
        outcome = "failure" if code == "4625" or any(x in text for x in ("failed logon", "authentication failure", "invalid password")) else (
            "success" if code == "4624" or any(x in text for x in ("successful logon", "accepted password", "accepted publickey")) else "")
        stamp = _time(event.get("observed_at"))
        if not outcome or stamp is None: continue
        user = next(iter(_values(event, ("user.name", "winlog.event_data.SubjectUserName"))), "unknown")
        source = next(iter(_values(event, ("source.ip", "winlog.event_data.IpAddress", "ip.src"))), "unknown")
        grouped[(user, source)].append((stamp, outcome, str(event.get("evidence_id") or "")))
    out = []
    for (user, source), rows in grouped.items():
        rows.sort(); failures: list[tuple[datetime, str]] = []
        for stamp, outcome, ref in rows:
            if outcome == "failure":
                failures.append((stamp, ref)); continue
            failures = [(failure_time, failure_ref) for failure_time, failure_ref in failures
                if stamp - timedelta(minutes=15) <= failure_time <= stamp]
            if failures:
                refs = [failure_ref for _, failure_ref in failures if failure_ref]
                if ref: refs.append(ref)
                out.append({"user": user, "source": source, "failures_before_success": len(failures),
                            "success_at": stamp.isoformat(), "sample_evidence_ids": list(dict.fromkeys(refs))[:6]})
            failures = []
    return sorted(out, key=lambda x: x["failures_before_success"], reverse=True)[:limit]


def _periodic_edges(edge_events: dict[tuple[str, str, str], list[dict]], limit: int) -> list[dict]:
    out = []
    for edge, events in edge_events.items():
        rows = sorted(
            ((stamp, event) for event in events if (stamp := _time(event.get("observed_at"))) is not None),
            key=lambda row: (row[0], str(row[1].get("evidence_id") or "")),
        )
        if len(rows) < 4: continue
        intervals = [(rows[i][0] - rows[i - 1][0]).total_seconds() for i in range(1, len(rows))]
        mean = sum(intervals) / len(intervals)
        if mean <= 0: continue
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        cv = math.sqrt(variance) / mean
        if cv <= 0.25:
            out.append({"source": edge[0], "destination": edge[1], "port": edge[2], "observations": len(rows),
                        "mean_interval_seconds": round(mean, 1), "interval_cv": round(cv, 3),
                        "sample_evidence_ids": [e.get("evidence_id") for _, e in rows[:3] if e.get("evidence_id")]})
    return sorted(out, key=lambda x: (x["interval_cv"], -x["observations"]))[:limit]


def _aggregate_signal_rows(host_events: list[dict], network_events: list[dict], authentication: list[dict],
                           high_fanout: list[dict], periodic: list[dict], rare_external: list[dict],
                           limit: int) -> dict[str, list[dict]]:
    """Build every aggregate catalog signal from cited, deterministic observations."""
    result = {
        "auth_failures_then_success": list(authentication[:limit]),
        "privileged_logon_then_execution": [],
        "authentication_fanout": [],
        "remote_service_then_execution": [],
        "high_fanout": [row for row in high_fanout
                        if int(row.get("unique_destinations", 0)) >= 4 or int(row.get("unique_destination_ports", 0)) >= 6][:limit],
        "periodic_edge": list(periodic[:limit]),
        "rare_external_destination": list(rare_external[:limit]),
        "dns_high_entropy": [],
        "dns_nxdomain_burst": [],
        "protocol_port_mismatch": [],
        "outbound_volume_outlier": [],
        "rare_process_rare_destination": [],
        "staging_then_outbound_transfer": [],
        "dns_query_fanout": [],
        "http_path_fanout": [],
        "web_scanner_user_agent": [],
        "scan_then_reverse_connection": [],
    }
    host_rows = [(stamp, event) for event in host_events if (stamp := _time(event.get("observed_at"))) is not None]
    network_rows = [(stamp, event) for event in network_events if (stamp := _time(event.get("observed_at"))) is not None]

    privileged = []
    executions = []
    successful_auth: dict[str, list[tuple[datetime, dict, str]]] = defaultdict(list)
    process_counts: Counter[str] = Counter()
    processes_by_asset: dict[str, list[tuple[datetime, dict, str]]] = defaultdict(list)
    staging = []
    for stamp, event in host_rows:
        code = next(iter(_values(event, ("event.code", "event.id", "winlog.event_id", "event_id"))), "")
        user = next(iter(_values(event, ("user.name", "winlog.event_data.SubjectUserName", "account.name"))), "")
        asset = _asset(event)
        text = _event_text(event)
        process = next(iter(_values(event, ("process.name", "process.executable"))), "").lower()
        if process:
            process_counts[process] += 1
            processes_by_asset[asset].append((stamp, event, process))
        is_execution = code in {"1", "4688"} or bool(_values(event, ("process.name", "process.executable", "process.command_line")))
        if is_execution:
            execution_source = next(iter(_values(event, ("source.ip", "winlog.event_data.IpAddress", "ip.src"))), "")
            executions.append((stamp, event, asset, user, process, execution_source))
        success = code == "4624" or any(token in text for token in ("successful logon", "accepted password", "accepted publickey"))
        if code == "4672" or (success and user.lower() in {"root", "administrator", "admin", "system", "nt authority\\system"}):
            privileged.append((stamp, event, asset, user))
        source = next(iter(_values(event, ("source.ip", "winlog.event_data.IpAddress", "ip.src"))), "")
        if success and source:
            successful_auth[source].append((stamp, event, asset))
        context = _behavior_context(event)
        if any(_word(context, token) for token in ("7z ", "rar ", "tar ", "zip ", "compress-archive")):
            staging.append((stamp, event, asset))

    for login_time, login, asset, user in privileged:
        match = next(((stamp, event) for stamp, event, target, execution_user, process, _ in sorted(executions, key=lambda row: row[0])
                      if target == asset and login_time <= stamp <= login_time + timedelta(minutes=15)
                      and event.get("evidence_id") != login.get("evidence_id")
                      and process and process_counts[process] <= 2
                      and (not user or not execution_user or user.lower() == execution_user.lower())), None)
        if match:
            result["privileged_logon_then_execution"].append({"asset": asset, "user": user,
                "sample_evidence_ids": _refs(login, match[1])})
            if len(result["privileged_logon_then_execution"]) >= limit: break

    for source, rows in successful_auth.items():
        window = _distinct_asset_window(rows, minutes=30, minimum=4)
        if window:
            assets = {asset for _, _, asset in window if asset and asset != "unknown"}
            result["authentication_fanout"].append({"source": source, "unique_destinations": len(assets),
                "sample_evidence_ids": [event.get("evidence_id") for _, event, _ in window if event.get("evidence_id")][:5]})
    result["authentication_fanout"] = result["authentication_fanout"][:limit]

    remote_ports = {"22", "135", "445", "3389", "5985", "5986"}
    for net_time, event in network_rows:
        port = next(iter(_values(event, ("destination.port", "dstPort", "dst_port", "tcp.dstport"))), "")
        destination = next(iter(_values(event, ("destination.ip", "dstIp", "dst_ip", "ip.dst"))), "")
        initiator = next(iter(_values(event, ("source.ip", "srcIp", "src_ip", "ip.src"))), "")
        if port not in remote_ports or not destination: continue
        match = next(((stamp, host) for stamp, host, asset, _, process, execution_source in sorted(executions, key=lambda row: row[0])
                      if _asset_matches(host, destination) and net_time <= stamp <= net_time + timedelta(minutes=15)
                      and process and process_counts[process] <= 2
                      and (not execution_source or not initiator or execution_source == initiator)), None)
        if match:
            result["remote_service_then_execution"].append({"asset": destination, "port": port,
                "sample_evidence_ids": _refs(event, match[1])})
            if len(result["remote_service_then_execution"]) >= limit: break

    nxdomain: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    dns_queries: dict[str, list[tuple[datetime, dict, str]]] = defaultdict(list)
    http_paths: dict[tuple[str, str], list[tuple[datetime, dict, str]]] = defaultdict(list)
    peer_activity: dict[tuple[str,str], list[tuple[datetime, dict, str]]] = defaultdict(list)
    external_by_source: dict[str, list[tuple[datetime, dict, str]]] = defaultdict(list)
    byte_rows = []
    expected_ports = {
        "dns": {"53", "853"}, "http": {"80", "8000", "8080"}, "https": {"443", "8443"},
        "tls": {"443", "8443"}, "smb": {"445"}, "rdp": {"3389"}, "ssh": {"22"},
        "winrm": {"5985", "5986"},
    }
    for stamp, event in network_rows:
        source = next(iter(_values(event, ("source.ip", "srcIp", "src_ip", "ip.src"))), "")
        destination = next(iter(_values(event, ("destination.ip", "dstIp", "dst_ip", "ip.dst"))), "")
        port = next(iter(_values(event, ("destination.port", "dstPort", "dst_port", "tcp.dstport", "udp.dstport"))), "")
        protocol = next(iter(_values(event, ("network.protocol", "network.application", "protocol", "protocols"))), "").lower()
        domain = next(iter(_values(event, ("dns.question.name", "dns.qry.name", "dns.host"))), "").lower().rstrip(".")
        uri = next(iter(_values(event, ("http.request.uri", "http.uri", "url.path", "uri"))), "")
        user_agent = next(iter(_values(event, ("http.user_agent", "http.user-agent", "http.request.user_agent", "user_agent"))), "")
        rcode = next(iter(_values(event, ("dns.response_code", "dns.header.response_code", "dns.flags.rcode", "rcode"))), "").lower()
        if domain:
            dns_queries[source or _asset(event)].append((stamp,event,domain))
            label = domain.split(".", 1)[0]
            entropy = _entropy(label)
            if len(label) >= 20 and entropy >= 3.0:
                result["dns_high_entropy"].append({"source": source or _asset(event), "domain": domain,
                    "label_length": len(label), "entropy": round(entropy, 2), "sample_evidence_ids": _refs(event)})
        if rcode in {"3", "nxdomain", "name_error"}:
            nxdomain[source or _asset(event)].append((stamp, event))
        if source and destination and uri:
            http_paths[(source,destination)].append((stamp,event,uri.split("?",1)[0]))
        if user_agent and any(token in user_agent.lower() for token in
                ("sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab", "gobuster", "dirbuster", "ffuf", "nuclei")):
            result["web_scanner_user_agent"].append({"source":source or _asset(event),
                "destination":destination,"user_agent":user_agent[:200],"sample_evidence_ids":_refs(event)})
        if source and destination:
            peer_activity[(source,destination)].append((stamp,event,port))
        if protocol in expected_ports and port and port not in expected_ports[protocol]:
            result["protocol_port_mismatch"].append({"source": source, "destination": destination,
                "protocol": protocol, "port": port, "sample_evidence_ids": _refs(event)})
        byte_value = _first_number(event, ("network.bytes", "totBytes", "bytes", "source.bytes", "destination.bytes"))
        if byte_value is not None:
            byte_rows.append((byte_value, stamp, event, source, destination))
        if source and destination and _external_ip(destination):
            external_by_source[source].append((stamp, event, destination))
    result["dns_high_entropy"] = result["dns_high_entropy"][:limit]
    result["protocol_port_mismatch"] = result["protocol_port_mismatch"][:limit]
    result["web_scanner_user_agent"] = result["web_scanner_user_agent"][:limit]
    for source,rows in dns_queries.items():
        window=_strongest_distinct_value_window(rows,minutes=10,minimum=12)
        if window:
            result["dns_query_fanout"].append({"source":source,
                "unique_queries":len({value for _,_,value in window}),
                "sample_evidence_ids":[event.get("evidence_id") for _,event,_ in window if event.get("evidence_id")][:5]})
    result["dns_query_fanout"]=sorted(result["dns_query_fanout"],
        key=lambda row:(-int(row.get("unique_queries",0)),str(row.get("source") or "")))[:limit]
    for (source,destination),rows in http_paths.items():
        window=_strongest_distinct_value_window(rows,minutes=10,minimum=12)
        if window:
            result["http_path_fanout"].append({"source":source,"destination":destination,
                "unique_paths":len({value for _,_,value in window}),
                "sample_evidence_ids":[event.get("evidence_id") for _,event,_ in window if event.get("evidence_id")][:5]})
    result["http_path_fanout"]=sorted(result["http_path_fanout"],
        key=lambda row:(-int(row.get("unique_paths",0)),str(row.get("source") or ""),str(row.get("destination") or "")))[:limit]
    for (source,destination),rows in peer_activity.items():
        ordered=sorted(rows,key=lambda row:row[0]); left=0; port_counts=Counter()
        reverse_rows=sorted(peer_activity.get((destination,source),[]),key=lambda row:row[0])
        if not reverse_rows: continue
        for right,(stamp,event,port) in enumerate(ordered):
            if port: port_counts[port]+=1
            while left<=right and (stamp-ordered[left][0]).total_seconds()>15*60:
                old_port=ordered[left][2]
                if old_port:
                    port_counts[old_port]-=1
                    if port_counts[old_port]<=0: del port_counts[old_port]
                left+=1
            if len(port_counts)<6: continue
            callback=next((reverse_event for reverse_stamp,reverse_event,_ in reverse_rows
                if stamp<=reverse_stamp<=stamp+timedelta(minutes=60)),None)
            if not callback: continue
            scan_events=[scan_event for _,scan_event,_ in ordered[left:right+1]]
            result["scan_then_reverse_connection"].append({"source":source,"destination":destination,
                "unique_ports":len(port_counts),
                "sample_evidence_ids":list(dict.fromkeys(
                    [scan_event.get("evidence_id") for scan_event in scan_events[:4] if scan_event.get("evidence_id")]+_refs(callback)))})
            break
    reversal_pairs={(str(row.get("source") or ""),str(row.get("destination") or ""))
        for row in result["scan_then_reverse_connection"]}
    for (source,destination),rows in http_paths.items():
        if (source,destination) in reversal_pairs:
            continue
        window=_strongest_distinct_value_window(rows,minutes=10,minimum=12)
        if not window:
            continue
        reverse_rows=sorted(peer_activity.get((destination,source),[]),key=lambda row:row[0])
        scan_end=window[-1][0]
        callback=next((reverse_event for reverse_stamp,reverse_event,_ in reverse_rows
            if scan_end+timedelta(seconds=10)<=reverse_stamp<=scan_end+timedelta(minutes=60)),None)
        if not callback:
            continue
        result["scan_then_reverse_connection"].append({
            "source":source,"destination":destination,"scan_basis":"http_path_fanout",
            "unique_paths":len({value for _,_,value in window}),
            "sample_evidence_ids":list(dict.fromkeys(
                [scan_event.get("evidence_id") for _,scan_event,_ in window[:4]
                 if scan_event.get("evidence_id")]+_refs(callback))),
        })
    result["scan_then_reverse_connection"]=sorted(result["scan_then_reverse_connection"],
        key=lambda row:(-max(int(row.get("unique_ports",0)),int(row.get("unique_paths",0))),
            str(row.get("source") or ""),str(row.get("destination") or "")))[:limit]
    for source, rows in nxdomain.items():
        window = _event_window(rows, minutes=10, minimum=5)
        if window:
            result["dns_nxdomain_burst"].append({"source": source, "observations": len(window),
                "sample_evidence_ids": [event.get("evidence_id") for _, event in window if event.get("evidence_id")][:5]})
    result["dns_nxdomain_burst"] = result["dns_nxdomain_burst"][:limit]

    if byte_rows:
        ordered = sorted(value for value, *_ in byte_rows)
        median = ordered[len(ordered)//2] if len(ordered) % 2 else (ordered[len(ordered)//2-1] + ordered[len(ordered)//2]) / 2
        threshold = max(1_000_000, median * 4)
        for value, _, event, source, destination in sorted(byte_rows, key=lambda row: row[0], reverse=True):
            if value < threshold or not _external_ip(destination): continue
            result["outbound_volume_outlier"].append({"source": source, "destination": destination,
                "bytes": value, "median_bytes": median, "sample_evidence_ids": _refs(event)})
            if len(result["outbound_volume_outlier"]) >= limit: break

    for asset, process_rows in processes_by_asset.items():
        for process_time, process_event, process in process_rows:
            if process_counts[process] > 1: continue
            for network_time, network_event, destination in external_by_source.get(asset, []):
                if abs((network_time-process_time).total_seconds()) > 3600: continue
                if sum(1 for rows in external_by_source.values() for _, _, value in rows if value == destination) > 2: continue
                result["rare_process_rare_destination"].append({"asset": asset, "process": process,
                    "destination": destination, "sample_evidence_ids": _refs(process_event, network_event)})
                break
            if len(result["rare_process_rare_destination"]) >= limit: break

    for stage_time, stage_event, asset in staging:
        for net_time, network_event, destination in external_by_source.get(asset, []):
            byte_value = _first_number(network_event, ("network.bytes", "totBytes", "bytes", "source.bytes", "destination.bytes")) or 0
            if stage_time <= net_time <= stage_time + timedelta(minutes=60) and byte_value >= 1_000_000:
                result["staging_then_outbound_transfer"].append({"asset": asset, "destination": destination,
                    "bytes": byte_value, "sample_evidence_ids": _refs(stage_event, network_event)})
                break
        if len(result["staging_then_outbound_transfer"]) >= limit: break
    return result


def _asset(event: dict) -> str:
    return next(iter(_values(event, ("host.name", "host.hostname", "host.ip"), include_asset=True)), "unknown")


def _asset_matches(event: dict, entity: str) -> bool:
    return entity in _values(event, ("host.name", "host.hostname", "host.ip"), include_asset=True)


def _refs(*events: dict) -> list[str]:
    return list(dict.fromkeys(str(event.get("evidence_id")) for event in events if event.get("evidence_id")))


def _entropy(value: str) -> float:
    if not value: return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _event_window(rows: list[tuple[datetime, Any]], minutes: int, minimum: int) -> list[tuple[datetime, Any]]:
    ordered = sorted(rows, key=lambda row: row[0])
    left = 0
    for right, (stamp, _) in enumerate(ordered):
        while left <= right and (stamp - ordered[left][0]).total_seconds() > minutes * 60:
            left += 1
        if right - left + 1 >= minimum:
            return ordered[left:right + 1]
    return []


def _distinct_asset_window(rows: list[tuple[datetime, dict, str]], minutes: int,
                           minimum: int) -> list[tuple[datetime, dict, str]]:
    ordered = sorted(rows, key=lambda row: row[0])
    for left in range(len(ordered)):
        window = [row for row in ordered[left:] if (row[0] - ordered[left][0]).total_seconds() <= minutes * 60]
        if len({asset for _, _, asset in window if asset and asset != "unknown"}) >= minimum:
            return window
    return []


def _strongest_distinct_value_window(rows: list[tuple[datetime, dict, str]], minutes: int,
                                     minimum: int) -> list[tuple[datetime, dict, str]]:
    ordered=sorted(rows,key=lambda row:row[0]); left=0; counts=Counter(); best=(0,0,-1)
    for right,(stamp,_,value) in enumerate(ordered):
        if value: counts[value]+=1
        while left<=right and (stamp-ordered[left][0]).total_seconds()>minutes*60:
            old_value=ordered[left][2]
            if old_value:
                counts[old_value]-=1
                if counts[old_value]<=0: del counts[old_value]
            left+=1
        if len(counts)>best[0]: best=(len(counts),left,right)
    return ordered[best[1]:best[2]+1] if best[0]>=minimum else []


def _behavior_signals(events: list[dict], limit: int) -> list[dict]:
    families = {
        "transfer_or_download": ("wget", "curl", "certutil", "bitsadmin", "scp ", "download"),
        "discovery_or_scanning": ("linpeas", "systeminfo", "whoami", "net user", "nmap", "masscan", "arp -a"),
        "remote_execution_or_service": ("psexec", "wmic", "wsmprovhost", "schtasks", "service install", "sc.exe"),
        "credential_access": ("mimikatz", "secretsdump", "lsass", "/etc/shadow", "sam save"),
        "defense_impairment": ("disable defender", "wevtutil cl", "auditd stop", "clear-eventlog"),
        "tunneling_or_remote_access": ("chisel", "ngrok", "socat", "anydesk", "teamviewer", "screenconnect"),
        "staging_or_impact": ("7z ", "rar ", "tar ", "vssadmin delete", "wbadmin delete", "ransom"),
    }
    contextualized = [(event, _behavior_context(event)) for event in events]
    out = []
    for name, needles in families.items():
        matched = [event for event, text in contextualized if text and any(_word(text, needle) for needle in needles)]
        if matched:
            out.append({"analytic": name, "observations": len(matched),
                        "sample_evidence_ids": [e.get("evidence_id") for e in matched[:5] if e.get("evidence_id")],
                        "note": "Command or artifact-context seed match; validate execution, intent, and causal effects."})
    return sorted(out, key=lambda x: x["observations"], reverse=True)[:limit]


def _behavior_context(event: dict) -> str:
    """Return bounded command/artifact context without flattening unrelated text.

    Broad telemetry messages often contain software feature lists, signatures,
    documentation, or search expressions. Treating every mention as execution
    creates high-volume false signals. Prefer structured command fields and
    parse only bounded execution-oriented message fragments.
    """
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    parts = _values(event, (
        "process.name", "process.executable", "process.command_line", "process.args",
        "winlog.event_data.Image", "winlog.event_data.CommandLine",
        "winlog.event_data.ParentCommandLine", "audit.command", "audit.exe",
    ))
    message = str(_nested(raw, "message") or raw.get("message") or "")
    dataset = " ".join(_values(event, ("event.dataset", "event.module"))).lower()
    record_type = " ".join(_values(event, ("audit.record_type",))).lower()
    event_codes = set(_values(event, ("event.code", "event.id", "winlog.event_id", "event_id")))

    if record_type in {"execve", "user_cmd", "proctitle"} or "audit" in dataset:
        arguments = []
        for match in re.finditer(r"\ba\d+=(?:\"([^\"]*)\"|'([^']*)'|(\S+))", message):
            value = next((group for group in match.groups() if group is not None), "")
            if value: arguments.append(value)
        if arguments:
            # Keep the executable and ordinary bounded arguments. This drops a
            # giant sed/grep pattern that merely enumerates tool names while
            # retaining direct execution and shell command strings.
            parts.extend(arg for index, arg in enumerate(arguments[:10]) if index == 0 or len(arg) <= 240)
        elif len(message) <= 800:
            parts.append(message)

    if event_codes & {"1", "4688"} and len(message) <= 2000:
        parts.append(message)

    command_match = re.search(r"(?:\bCOMMAND=|\bCommandLine\s*[:=])(.{1,600})", message, flags=re.IGNORECASE)
    if command_match:
        parts.append(command_match.group(1))

    parts.extend(_values(event, (
        "file.path", "file.name", "url.path", "http.request.uri", "http.uri",
        "smb2.filename", "dns.question.name", "dns.qry.name",
    )))
    return " ".join(str(value) for value in parts if str(value).strip())[:4000].lower()


def _values(event: dict, fields: tuple[str, ...], include_asset: bool = False) -> list[str]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    out = []
    for field in fields:
        value = _nested(raw, field)
        if value is None: value = raw.get(field)
        if value is None: value = _nested(event, field)
        for item in value if isinstance(value, list) else [value]:
            if item is not None and str(item).strip() and str(item) not in out: out.append(str(item))
    if include_asset and event.get("asset") and str(event["asset"]) not in out: out.append(str(event["asset"]))
    return out


def _nested(value: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(value, dict): return None
        value = value.get(part)
    return value


def _event_text(event: dict) -> str:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    return (str(event.get("observation") or "") + " " + " ".join(str(x) for x in _flatten(raw))).lower()


def _flatten(value: Any, depth: int = 0):
    if depth > 4: return []
    if isinstance(value, dict):
        return [item for child in value.values() for item in _flatten(child, depth + 1)]
    if isinstance(value, list):
        return [item for child in value[:30] for item in _flatten(child, depth + 1)]
    return [value]


def _first_number(event: dict, fields: tuple[str, ...]) -> int | None:
    for value in _values(event, fields):
        try: return int(float(value))
        except (TypeError, ValueError): pass
    return None


def _time(value: Any) -> datetime | None:
    if not value: return None
    try:
        number = float(value)
        if number > 10_000_000_000: number /= 1000
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError): pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError): return None


def _external_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local)
    except ValueError: return False


def _top(counter: Counter, limit: int) -> list[dict]:
    return [{"value": str(value), "count": count} for value, count in counter.most_common(limit) if str(value)]


def _percent(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 1) if denominator else None


def _word(text: str, needle: str) -> bool:
    if any(x in needle for x in (" ", "/", ".")): return needle in text
    return bool(re.search(r"(?<![a-z0-9_])" + re.escape(needle) + r"(?![a-z0-9_])", text))
