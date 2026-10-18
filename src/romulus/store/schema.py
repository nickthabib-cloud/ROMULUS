"""SQLAlchemy Core table definitions for the M1 slice (versioned via Alembic)."""
from __future__ import annotations

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
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
    Column("source_case_id", String),
    Column("created_at", DateTime(timezone=True), nullable=False),
)
Index("ix_candidate_hunt_lane", candidate.c.hunt_id, candidate.c.lane, candidate.c.priority)

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
    Column("status", String, nullable=False),           # open | parked | escalated | closed | budget_exhausted
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
