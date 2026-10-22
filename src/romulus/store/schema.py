"""SQLAlchemy Core table definitions (versioned via Alembic)."""
from __future__ import annotations

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    UniqueConstraint,
)

metadata = MetaData()

hunt = Table(
    "hunt", metadata,
    Column("id", String, primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("created_by", String, nullable=False),
    Column("manifest", JSON, nullable=False),          # immutable after start
    Column("manifest_digest", String, nullable=False),
    Column("parent_hunt_id", String, ForeignKey("hunt.id")),
    Column("execution_state", String, nullable=False),
    Column("detection_result", String),
    Column("stop_reason", Text),
    Column("started_at", DateTime(timezone=True)),
    Column("ended_at", DateTime(timezone=True)),
    Column("heartbeat_at", DateTime(timezone=True)),
    Column("lease_until", DateTime(timezone=True)),
    Column("lease_owner", String),
)

source_profile = Table(
    "source_profile", metadata,
    Column("id", String, primary_key=True),             # digest of profile content
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("target", String, nullable=False),
    Column("kind", String, nullable=False),             # es_index | arkime | pcap
    Column("profile", JSON, nullable=False),
    Column("captured_at", DateTime(timezone=True), nullable=False),
)

task = Table(
    "task", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("kind", String, nullable=False),             # sweep | pivot | inventory
    Column("owner", String, nullable=False),            # playbook id or case id
    Column("intent", JSON, nullable=False),
    Column("fingerprint", String, nullable=False),
    Column("state", String, nullable=False),
    Column("priority", Float, nullable=False, default=0.0),
    Column("lease_until", DateTime(timezone=True)),
    Column("attempts", Integer, nullable=False, default=0),
    Column("source_queries", Integer, nullable=False, default=0),
    Column("outcome", JSON),
    Column("error", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("hunt_id", "owner", "fingerprint", name="uq_task_owner_fp"),
)
Index("ix_task_hunt_state", task.c.hunt_id, task.c.state, task.c.priority)

raw_record = Table(
    "raw_record", metadata,
    Column("id", String, primary_key=True),             # sha256 of (target, native_id)
    Column("target", String, nullable=False),
    Column("native_id", String, nullable=False),
    Column("digest", String, nullable=False),           # sha256 of canonical source JSON
    Column("source", JSON, nullable=False),             # retained copy
    Column("first_task_id", String, ForeignKey("task.id")),
    Column("retrieved_at", DateTime(timezone=True), nullable=False),
)

typed_event = Table(
    "typed_event", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("family", String, nullable=False),           # process_exec | auth | http_access | net_flow | ...
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("host", String),
    Column("event", JSON, nullable=False),              # typed payload with field lineage
    Column("raw_ids", JSON, nullable=False),            # list of raw_record ids
    Column("normalizer", String, nullable=False),       # name@version
    UniqueConstraint("hunt_id", "id", name="uq_event"),
)
Index("ix_event_hunt_family_ts", typed_event.c.hunt_id, typed_event.c.family, typed_event.c.ts)
Index("ix_event_host_ts", typed_event.c.hunt_id, typed_event.c.host, typed_event.c.ts)

normalization_error = Table(
    "normalization_error", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("raw_id", String, nullable=False),
    Column("normalizer", String, nullable=False),
    Column("error", Text, nullable=False),
)

entity = Table(
    "entity", metadata,
    Column("id", String, primary_key=True),             # kind:canonical value
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("kind", String, nullable=False),
    Column("value", String, nullable=False),
    Column("first_seen", DateTime(timezone=True)),
    Column("last_seen", DateTime(timezone=True)),
    Column("event_count", Integer, nullable=False, default=0),
)

event_entity = Table(
    "event_entity", metadata,
    Column("event_id", String, nullable=False),
    Column("entity_id", String, nullable=False),
    Column("role", String, nullable=False),             # actor | subject | src | dst | host
    UniqueConstraint("event_id", "entity_id", "role", name="uq_event_entity"),
)
Index("ix_event_entity_entity", event_entity.c.entity_id)

rule_run = Table(
    "rule_run", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("rule_id", String, nullable=False),
    Column("rule_version", String, nullable=False),
    Column("target", String, nullable=False),
    Column("partition", String, nullable=False),
    Column("state", String, nullable=False),            # coverage-ledger state (spec section 9)
    Column("matched", Integer, nullable=False, default=0),
    Column("evaluated", Integer, nullable=False, default=0),
    Column("detail", JSON),
    UniqueConstraint("hunt_id", "rule_id", "rule_version", "target", "partition", name="uq_rule_cell"),
)

candidate = Table(
    "candidate", metadata,
    Column("id", String, primary_key=True),             # stable: rule + evidence identity
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("rule_id", String, nullable=False),
    Column("rule_version", String, nullable=False),
    Column("claim", Text, nullable=False),
    Column("claim_type", String, nullable=False),       # observed_action | network_observation | anomaly | mention
    Column("event_ids", JSON, nullable=False),
    Column("predicate_fields", JSON, nullable=False),   # [{field, value, raw_path}]
    Column("entities", JSON, nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("severity", String, nullable=False),
    Column("confidence", String, nullable=False),
    Column("lane", String, nullable=False),
    Column("priority", Float, nullable=False),
    Column("priority_reasons", JSON, nullable=False),
    Column("gate_results", JSON, nullable=False),
    Column("benign_alternatives", JSON, nullable=False),
    Column("next_checks", JSON, nullable=False),
    Column("group_key", String, nullable=False, default=""),
    Column("source_case_id", String),
    Column("source_anchor_id", String),
    Column("source_link_id", String),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_candidate_hunt_lane", candidate.c.hunt_id, candidate.c.lane, candidate.c.priority)

expansion_anchor = Table(
    "expansion_anchor", metadata,
    Column("id", String, primary_key=True),              # the anchored candidate id
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("candidate_id", String, ForeignKey("candidate.id"), nullable=False),
    Column("depth", Integer, nullable=False),
    Column("parent_anchor_id", String),
    Column("host", String),
    Column("lane", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("status", String, nullable=False),            # pending | expanded_complete | expanded_partial | unexpanded
    Column("reasons", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("hunt_id", "candidate_id", name="uq_expansion_anchor_candidate"),
)
Index("ix_expansion_anchor_hunt_status", expansion_anchor.c.hunt_id, expansion_anchor.c.status)

expansion_link = Table(
    "expansion_link", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("anchor_id", String, ForeignKey("expansion_anchor.id"), nullable=False),
    Column("link_type", String, nullable=False),
    Column("window_label", String, nullable=False),
    Column("window_start", DateTime(timezone=True), nullable=False),
    Column("window_end", DateTime(timezone=True), nullable=False),
    Column("strength", String, nullable=False),
    Column("key", JSON, nullable=False),
    Column("status", String, nullable=False),
    Column("event_ids", JSON, nullable=False),
    Column("evidence_ids", JSON, nullable=False),
    Column("task_ids", JSON, nullable=False),
    Column("coverage", JSON, nullable=False),
    Column("reasons", JSON, nullable=False),
    Column("duration_ms", Integer, nullable=False),
    Column("query_spend", Integer, nullable=False, default=0),
    Column("evaluated", Integer, nullable=False, default=0),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)
Index("ix_expansion_link_anchor", expansion_link.c.anchor_id, expansion_link.c.link_type)

# A relation an analyst asserts between two findings. Shown on the attack-path timeline in its own style and
# labelled as an assertion: never an observed or inferred link, never merged into incidents.
analyst_link = Table(
    "analyst_link", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("from_finding", String, nullable=False),
    Column("to_finding", String, nullable=False),
    Column("relation", String, nullable=False),
    Column("note", Text),
    Column("actor", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_analyst_link_hunt", analyst_link.c.hunt_id)

disposition_event = Table(
    "disposition_event", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("candidate_id", String, ForeignKey("candidate.id"), nullable=False),
    Column("actor", String, nullable=False),
    Column("at", DateTime(timezone=True), nullable=False),
    Column("status", String, nullable=False),
    Column("note", Text),
)

case = Table(
    "case", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("seed_candidate_id", String),
    Column("title", Text, nullable=False),
    Column("status", String, nullable=False),           # open | parked | fallback_parked | escalated | closed | budget_exhausted
    Column("priority", Float, nullable=False),
    Column("entities", JSON, nullable=False),
    Column("hypotheses", JSON, nullable=False),
    Column("steps_used", Integer, nullable=False, default=0),
    Column("step_budget", Integer, nullable=False),
    Column("summary", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

model_call = Table(
    "model_call", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("case_id", String),
    Column("purpose", String, nullable=False),
    Column("model", String, nullable=False),
    Column("options", JSON, nullable=False),
    Column("prompt_digest", String, nullable=False),
    Column("prompt_tokens_est", Integer),
    Column("prompt_eval_count", Integer),
    Column("eval_count", Integer),
    Column("duration_ms", Integer),
    Column("raw_response", Text),
    Column("parsed", JSON),
    Column("validation", JSON),                         # {ok, errors[]}
    Column("status", String, nullable=False),           # ok | invalid | truncated | error
    Column("at", DateTime(timezone=True), nullable=False),
    # provider-port calls only (the AI agent): where the call went and what the server reported
    Column("provider", String),
    Column("endpoint_host", String),
    Column("egress", String),                           # local | remote
    Column("model_reported", String),
    Column("finish_reason", String),
    Column("cost_usd_est", Float),
)

case_step = Table(
    "case_step", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", String, ForeignKey("case.id"), nullable=False),
    Column("n", Integer, nullable=False),
    Column("model_call_id", String),
    Column("decision", JSON, nullable=False),
    Column("accepted", Integer, nullable=False),
    Column("rejection", Text),
    Column("task_id", String),
    Column("result_digest", JSON(none_as_null=True)),
    Column("at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("case_id", "n", name="uq_case_step_n"),
)

report_manifest = Table(
    "report_manifest", metadata,
    Column("id", String, primary_key=True),
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("supersedes", String),
    Column("manifest", JSON, nullable=False),
    Column("digest", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("hunt_id", "revision", name="uq_report_rev"),
)

user = Table(
    "user", metadata,
    Column("username", String, primary_key=True),
    Column("password_hash", String, nullable=False),
    Column("role", String, nullable=False),             # lead | analyst
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("disabled", Integer, nullable=False, default=0),
)

audit_event = Table(
    "audit_event", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("at", DateTime(timezone=True), nullable=False),
    Column("actor", String, nullable=False),
    Column("action", String, nullable=False),
    Column("hunt_id", String),
    Column("detail", JSON),
)

baseline_segment = Table(
    "baseline_segment", metadata,
    Column("id", String, primary_key=True),
    Column("site", String, nullable=False),
    Column("target", String, nullable=False),
    Column("spec_id", String, nullable=False),
    Column("spec_version", String, nullable=False),
    Column("key_version", String, nullable=False),
    Column("normalizer", String, nullable=False),
    Column("start", DateTime(timezone=True), nullable=False),
    Column("end", DateTime(timezone=True), nullable=False),
    Column("bucket", String, nullable=False),
    Column("origin", String, nullable=False),
    Column("source_hunt_id", String),
    Column("built_by_hunt_id", String),
    Column("exclusion_digest", String, nullable=False),
    Column("excluded_keys", JSON, nullable=False),
    Column("hunted", Integer, nullable=False),
    Column("events_total", Integer, nullable=False),
    # order-independent digest of the segment's count and scope-hour rows, so a rewrite of the same id with
    # other content is refused without reading the stored rows back
    Column("rows_digest", String, nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("origin IN ('lookback', 'hunt')", name="ck_baseline_segment_origin"),
    CheckConstraint("bucket IN ('day', 'hour')", name="ck_baseline_segment_bucket"),
    CheckConstraint("status IN ('building', 'active', 'stale', 'revoked')", name="ck_baseline_segment_status"),
    CheckConstraint("hunted IN (0, 1)", name="ck_baseline_segment_hunted"),
    CheckConstraint("events_total >= 0", name="ck_baseline_segment_events"),
)
Index(
    "ix_baseline_segment_cover", baseline_segment.c.site, baseline_segment.c.target,
    baseline_segment.c.spec_id, baseline_segment.c.status, baseline_segment.c.start, baseline_segment.c.end,
)
Index("ix_baseline_segment_source_hunt", baseline_segment.c.source_hunt_id)
Index("ix_baseline_segment_built_hunt", baseline_segment.c.built_by_hunt_id)

baseline_count = Table(
    "baseline_count", metadata,
    Column("segment_id", String, ForeignKey("baseline_segment.id", ondelete="CASCADE"), nullable=False),
    Column("scope_kind", String, nullable=False),
    Column("scope", String, nullable=False),
    Column("key_id", String, nullable=False),
    Column("key_digest", String, nullable=False),
    Column("key", JSON, nullable=False),
    Column("bucket", DateTime(timezone=True), nullable=False),
    Column("count", Integer, nullable=False),
    Column("first_ts", DateTime(timezone=True), nullable=False),
    Column("last_ts", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("segment_id", "scope", "key_digest", "bucket", name="pk_baseline_count"),
    CheckConstraint("count >= 1", name="ck_baseline_count_count"),
)
# Prevalence ("how many scopes of one kind hold this key in these segments") and the scoped history probe are
# both one range search on this index; the primary key serves per-segment reads.
Index(
    "ix_baseline_count_key", baseline_count.c.key_id, baseline_count.c.scope_kind, baseline_count.c.scope,
    baseline_count.c.segment_id,
)

baseline_scope_hour = Table(
    "baseline_scope_hour", metadata,
    Column("segment_id", String, ForeignKey("baseline_segment.id", ondelete="CASCADE"), nullable=False),
    Column("scope_kind", String, nullable=False),
    Column("scope", String, nullable=False),
    Column("hour", DateTime(timezone=True), nullable=False),
    Column("events", Integer, nullable=False),
    PrimaryKeyConstraint("segment_id", "scope", "hour", name="pk_baseline_scope_hour"),
    CheckConstraint("events >= 0", name="ck_baseline_scope_hour_events"),
)
Index(
    "ix_baseline_scope_hour_lookup", baseline_scope_hour.c.scope_kind, baseline_scope_hour.c.scope,
    baseline_scope_hour.c.segment_id, baseline_scope_hour.c.hour,
)

baseline_snapshot = Table(
    "baseline_snapshot", metadata,
    Column("hunt_id", String, ForeignKey("hunt.id"), primary_key=True),
    Column("plan", JSON, nullable=False),
    Column("store_cut", JSON, nullable=False),
    Column("segment_ids", JSON, nullable=False),
    Column("coverage", JSON, nullable=False),
    Column("status", String, nullable=False),
    Column("digest", String, nullable=False),
    CheckConstraint(
        "status IN ('resolved', 'shortened', 'unresolved')", name="ck_baseline_snapshot_status",
    ),
)

# Snapshot membership is normalized so every baseline probe joins the frozen hunt cut instead of
# interpolating a potentially huge list of segment ids into SQL.
baseline_snapshot_segment = Table(
    "baseline_snapshot_segment", metadata,
    Column("hunt_id", String, ForeignKey("baseline_snapshot.hunt_id", ondelete="CASCADE"), nullable=False),
    Column("segment_id", String, ForeignKey("baseline_segment.id", ondelete="RESTRICT"), nullable=False),
    PrimaryKeyConstraint("hunt_id", "segment_id", name="pk_baseline_snapshot_segment"),
)
Index("ix_baseline_snapshot_segment_segment", baseline_snapshot_segment.c.segment_id)

baseline_observation = Table(
    "baseline_observation", metadata,
    Column("hunt_id", String, ForeignKey("hunt.id"), nullable=False),
    Column("spec_id", String, nullable=False),
    Column("spec_version", String, nullable=False),
    Column("scope_kind", String, nullable=False),
    Column("scope", String, nullable=False),
    Column("key_id", String, nullable=False),
    Column("key_digest", String, nullable=False),
    Column("key", JSON, nullable=False),
    Column("window_count", Integer, nullable=False),
    Column("first_ts", DateTime(timezone=True)),
    Column("last_ts", DateTime(timezone=True)),
    Column("first_event_id", String),
    Column("history_count", Integer),
    Column("history_decayed", Float),
    Column("peer_scopes_with_key", Integer),
    Column("peer_scopes", Integer),
    Column("threshold", Float),
    Column("mean", Float),
    Column("sigma", Float),
    Column("n_hours", Integer),
    Column("verdict", String, nullable=False),
    Column("reason", Text),
    Column("candidate_id", String),
    PrimaryKeyConstraint(
        "hunt_id", "spec_id", "spec_version", "scope", "key_digest",
        name="pk_baseline_observation",
    ),
    CheckConstraint("window_count >= 0", name="ck_baseline_observation_window_count"),
    CheckConstraint(
        "verdict IN ('first_seen', 'rare', 'common', 'over_threshold', 'within_threshold', 'unresolved')",
        name="ck_baseline_observation_verdict",
    ),
)
# Deleting a hunt keeps every typed event another hunt's observation cites as its first event.
Index("ix_baseline_observation_first_event", baseline_observation.c.first_event_id)
