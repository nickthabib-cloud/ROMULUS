"""Load runtime configuration from the environment / .env with secret redaction."""
from __future__ import annotations

import functools
import json
import math
import os
import re
from collections.abc import Collection
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, PrivateAttr, SecretStr, field_validator, model_validator

from romulus.detect.netdef import EXTERNAL_SETTING, INTERNAL_SETTING, SiteNetworks, parse_networks

SECRET_KEYS = ("PASSWORD", "API_KEY", "SECRET", "TOKEN")
MIN_SECRET_LENGTH = 8      # shorter secrets are hard to tell apart from ordinary text (doctor warns)
# OpenSearch's built-in superuser role (full cluster access, writes to every index).
FULL_ACCESS_ROLE = "all_access"
_BASE_PATH = re.compile(r"(/[A-Za-z0-9._~-]+)+")


def parse_env_file(path: Path) -> dict[str, str]:
    """Minimal KEY=VALUE parser (no interpolation, no shell semantics)."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            # unquoted values: an inline comment starts at "#" at the beginning or after whitespace
            if value.startswith("#"):
                value = ""
            else:
                for sep in (" #", "\t#"):
                    if sep in value:
                        value = value.split(sep, 1)[0].rstrip()
        out[key.strip()] = value
    return out


# a model id as providers list them: letters, digits and . _ : / -, bounded
MODEL_ID = re.compile(r"[A-Za-z0-9._:/-]{1,128}")


class Settings(BaseModel):
    home: Path = Path.home() / "romulus"
    site: str = ""
    web_bind: str = "127.0.0.1:8443"
    web_tls_cert: str = ""
    web_tls_key: str = ""
    secret_key: SecretStr = SecretStr("")

    # The model is optional: with no endpoint configured, model features are off.
    ollama_url: str = ""
    ollama_model_triage: str = ""
    ollama_model_synthesis: str = ""
    ollama_num_ctx: int = Field(default=8192, ge=2048, le=131072)
    ollama_timeout_seconds: int = Field(default=300, ge=5, le=3600)
    ollama_keep_alive: str = "30m"
    ollama_think: bool = False

    # Evaluation ground truth, if this install has any: doctor refuses source paths that overlap it.
    eval_root: Path | None = None
    # the mention pattern directory (content/mentions when unset)
    mention_dir: Path | None = None
    # records outside the sweep's selection the mention sweep reads per source target (0: none are read; the pool
    # then names them as not offered). Past it the smallest datasets are read whole first and the rest share it.
    mention_residue_records: int = Field(default=1_000_000, ge=0, le=100_000_000)

    es_url: str = "http://127.0.0.1:9200"
    es_flavor: str = "elasticsearch"
    es_username: str = ""
    es_password: SecretStr = SecretStr("")
    es_api_key: SecretStr = SecretStr("")
    es_ca_cert: str = ""
    es_verify_tls: bool = True
    es_index_patterns: list[str] = []
    # OpenSearch only: names of the site's read-only roles. `romulus doctor` reports the account as read-only only
    # when every role the security plugin lists for it is one of these; with none set it cannot say so.
    es_read_only_roles: list[str] = []
    # gzip responses (the client's default); false asks for uncompressed ones, cheaper to read on a fast link
    es_compression: bool = True
    # fetch the sweep's next partition on one background thread while the current one is evaluated; off by
    # default because it holds a second partition's decoded records in memory
    sweep_prefetch: bool = False
    # Where a hunt stages events and detector state that does not fit in memory (default ROMULUS_HOME/stage). Put it
    # on a volume no other service writes to: never the volume of Elasticsearch, Arkime or docker data.
    stage_dir: Path | None = None
    # The hunt's disk total for detector state (0: the smaller of half the stage volume's free space and 10% of its
    # size), the least free space always left on that volume (the reserve is at least 15% of the volume), and the
    # memory the in-memory parts of every rule share. Reaching a disk limit makes coverage partial, never a crash.
    state_disk_gb: float = Field(default=0.0, ge=0.0)
    state_disk_reserve_gb: float = Field(default=2.0, ge=0.0)
    state_memory_mb: int = Field(default=1536, ge=64)
    # Database space for the per-hunt counts a partial hunt keeps so that its resumed run can still write baseline
    # history. Over the limit, the oldest kept counts are released first; the hunts' findings are never affected.
    baseline_retain_disk_gb: float = Field(default=2.0, ge=0.0)
    # Database space for the per-hour parent carry input kept beside baseline history, so a later hunt can resolve
    # exec-pair parents without reading covered hours again. Over the limit, the oldest hours are dropped and read
    # again when a hunt needs them.
    baseline_carry_disk_gb: float = Field(default=4.0, ge=0.0)
    # Post-sweep expansion: every anchor brings its own share of source queries, so the total grows with the findings
    # to follow. This ceiling bounds that total (expansion queries run one at a time, so it is about what its wall
    # clock admits), and the wall clock is the expansion phase's own, so a long sweep never leaves it no time.
    expansion_max_source_queries: int = Field(default=20_000, ge=1, le=1_000_000)
    expansion_wall_clock_minutes: float = Field(default=120.0, gt=0.0)
    # How long a hunt or its agent has to honour an analyst's stop request before a force stop may end its process.
    # The run checks for a stop between source partitions, expansion links, model calls and tool calls; one source
    # query or model call can take minutes (AGENT_TIMEOUT_SECONDS), so the grace covers more than one of them.
    hunt_stop_grace_seconds: int = Field(default=60, ge=5, le=3600)
    # Visibility has its own disk allowance and source time, outside detector state.
    # Per-partition health composites normally fit one 1000-bucket page; 32 pages
    # admit larger sensor fleets while bounding repeated collection at the source.
    zeek_visibility_disk_mb: float = Field(default=256.0, gt=0.0)
    zeek_visibility_max_pages: int = Field(default=32, ge=1)
    zeek_visibility_deadline_seconds: float = Field(default=30.0, gt=0.0)

    arkime_url: str = "http://127.0.0.1:8005"
    arkime_username: str = ""
    arkime_password: SecretStr = SecretStr("")
    arkime_verify_tls: bool = True
    # A viewer published under a path prefix behind a proxy (e.g. /arkime), and how it authenticates: digest is the
    # viewer's own scheme; basic is what an authenticating reverse proxy in front of it usually asks for.
    arkime_base_path: str = ""
    arkime_auth: Literal["digest", "basic"] = "digest"

    pcap_allowed_dirs: list[Path] = []
    tshark_bin: str = "tshark"
    mission_timezone: str = "UTC"
    allow_privileged_source_account: bool = False
    # AI investigating agent: any OpenAI-compatible endpoint, Ollama's native API, the OpenAI Responses API
    # (openai_responses), or the Claude Messages API (anthropic, which needs the optional romulus[anthropic]
    # install). Unset means not configured.
    agent_provider: Literal["openai_compatible", "ollama", "openai_responses", "anthropic"] = "openai_compatible"
    agent_base_url: str = ""
    agent_api_key: SecretStr = SecretStr("")
    agent_model: str = ""
    agent_default: Literal["on", "off"] = "on"
    agent_context_tokens: int = Field(default=0, ge=0, le=10_000_000)    # 0: the server enforces its own limit
    agent_max_output_tokens: int = Field(default=4096, ge=64, le=200_000)
    # anthropic and openai_responses: models that think before answering spend part of each call's output allowance
    # on thinking, so this room is added to AGENT_MAX_OUTPUT_TOKENS; effort sets how much the model thinks
    agent_thinking_tokens: int = Field(default=60_000, ge=1024, le=1_000_000)
    agent_effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    # anthropic only: let the API answer a request its safety classifier declined with the fallback model it
    # recommends for that category (the model that answered is recorded on every call)
    agent_refusal_fallback: Literal["default", "off"] = "default"
    agent_timeout_seconds: int = Field(default=180, ge=5, le=3600)
    agent_max_calls: int = Field(default=200, ge=1, le=100_000)
    agent_max_tokens: int = Field(default=2_000_000, ge=1000, le=10_000_000_000)
    agent_max_wall_seconds: int = Field(default=3600, ge=60, le=7 * 24 * 3600)
    agent_max_cost_usd: float = Field(default=0.0, ge=0.0)                 # 0: no cost budget
    agent_price_input_per_mtok: float = Field(default=0.0, ge=0.0)         # USD per million prompt tokens
    agent_price_output_per_mtok: float = Field(default=0.0, ge=0.0)        # USD per million completion tokens
    # USD per million prompt tokens read from / written to the provider's prompt cache; 0 = unset (see budget.py)
    agent_price_cache_read_per_mtok: float = Field(default=0.0, ge=0.0)
    agent_price_cache_write_per_mtok: float = Field(default=0.0, ge=0.0)
    # anthropic with the refusal fallback on: the prices of the fallback model that may answer a declined call
    agent_price_fallback_input_per_mtok: float = Field(default=0.0, ge=0.0)
    agent_price_fallback_output_per_mtok: float = Field(default=0.0, ge=0.0)
    agent_price_fallback_cache_read_per_mtok: float = Field(default=0.0, ge=0.0)
    # anthropic only: what one prompt token read from / written to the prompt cache counts against the token budgets
    # (AGENT_MAX_TOKENS and the triage input budget), relative to an uncached one, as the API prices them: a cache
    # read at about a tenth of the input price, a five-minute cache write at 1.25 times it. Output tokens count once.
    agent_cache_read_token_weight: float = Field(default=0.1, gt=0.0, le=1.0)
    agent_cache_write_token_weight: float = Field(default=1.25, ge=1.0, le=10.0)
    agent_max_tool_calls_per_session: int = Field(default=25, ge=1, le=500)
    # The AI agent's source queries per hunt, shared out per session and per tool call (hunt/agent_tools.py). Each is a
    # read-only request with a capped record count, and one pivot fans out over the hunt's indices and a few time
    # partitions, so following one lead commonly takes tens of queries. The agent is bounded apart from this by its
    # model calls, tokens and wall clock, so this cap only has to keep its source load proportionate (deterministic
    # expansion's default is 20,000), not stop it from following its leads.
    agent_max_source_queries: int = Field(default=2000, ge=1, le=100_000)
    agent_concurrency: int = Field(default=2, ge=1, le=16)
    agent_max_initial_hypotheses: int = Field(default=8, ge=1, le=40)
    agent_max_hypotheses: int = Field(default=40, ge=1, le=500)
    agent_max_sessions_per_hypothesis: int = Field(default=4, ge=1, le=20)
    agent_assess_reserve_fraction: float = Field(default=0.15, ge=0.0, le=0.5)
    # The most an analyst may give one hunt's agent, as a multiple of the limits above (the standard budget): each
    # limit of a hunt's pinned budget plus its extensions stays at or below this multiple (and the limit's own
    # maximum). Only a lead account may go above it, up to the limit's maximum. romulus/agent/hunt_budget.py.
    agent_budget_ceiling_multiplier: float = Field(default=8.0, ge=1.0, le=100.0)
    agent_max_findings: int = Field(default=200, ge=1, le=10_000)
    agent_max_links: int = Field(default=300, ge=1, le=10_000)
    agent_max_notes: int = Field(default=500, ge=1, le=20_000)
    # raw records (returned rows no normalizer read) the agent's source queries keep as citable text, per hunt; each
    # keeps at most 16 KB of text. At the cap further rows are not kept, and the query result and the report say so.
    agent_max_raw_records: int = Field(default=1_000, ge=0, le=10_000)
    # AI triage order: a separately labelled, promote-only presentation order over a hunt's surfaced findings, run
    # after the agent phase when the agent is enabled, or on demand with `romulus triage`. It never changes lanes,
    # ranks, the Reported set, citations or the deterministic report order. The model sees deterministic group cards
    # (one per rule and primary target in a report section) in budget-sized chunks. Within each report section at
    # most `agent_triage_promote_per_lane` groups are promoted (likely attack before possible, the most buried
    # first), and each moves ahead only the (at most three) findings the model cited for it. Ten groups fill an
    # analyst's first screen, and no finding moves down by more than 10 x 3 = 30 places.
    agent_triage: Literal["on", "off"] = "on"
    # the triage pass's model on the same provider; empty: AGENT_MODEL (`romulus triage --agent-model` overrides both)
    agent_triage_model: str = ""
    agent_triage_promote_per_lane: int = Field(default=10, ge=0, le=100)
    agent_triage_max_calls: int = Field(default=100, ge=1, le=10_000)
    # totals for one triage pass, checked before each call against its worst case (prompt estimate, and the
    # provider's full output allowance including any thinking room)
    agent_triage_max_input_tokens: int = Field(default=4_000_000, ge=1000, le=10_000_000_000)
    agent_triage_max_output_tokens: int = Field(default=2_000_000, ge=1000, le=10_000_000_000)
    # the wall budget also counts staging the order and building the cards, which grow linearly with the hunt's
    # findings and groups; a larger hunt needs a proportionally larger wall budget
    agent_triage_max_wall_seconds: int = Field(default=1800, ge=10, le=7 * 24 * 3600)
    # one call: the cards it carries (estimated prompt tokens) and the answer it may write
    agent_triage_call_input_tokens: int = Field(default=30_000, ge=2000, le=1_000_000)
    agent_triage_call_output_tokens: int = Field(default=8192, ge=512, le=200_000)
    # groups of Reported findings the AI narrative cites that the triage pass left without a verdict, triaged after
    # the assessment so the narrative check can weigh them (those cited by the most paragraphs first); 0 = none
    agent_triage_cited_max_groups: int = Field(default=20, ge=0, le=1000)
    # Bootstrap-only switch: the one value that lets telemetry excerpts reach a non-local model endpoint.
    model_egress: Literal["", "lab-public-data"] = ""
    # Extra hosts, addresses or CIDR networks treated as local (e.g. a team's model server on an enclave address).
    model_local_hosts: list[str] = []
    # The site's internal address space (CIDRs) and carve-outs inside it that are outside the site (partner or
    # VPN ranges). Unset, the default RFC 1918 and reserved ranges are used and labelled as the default.
    internal_networks: list[str] = []
    external_networks: list[str] = []
    # The hunt whose resolved agent budget these settings carry (romulus.agent.hunt_budget.hunt_settings): its
    # limits are then read as they are, never resolved again. Not configuration: never read from the environment.
    _budget_hunt: str = PrivateAttr(default="")

    @field_validator("es_index_patterns", "pcap_allowed_dirs", "model_local_hosts", "internal_networks",
                     "external_networks", "es_read_only_roles", mode="before")
    @classmethod
    def _split(cls, v):
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @field_validator("es_flavor")
    @classmethod
    def _flavor(cls, v: str) -> str:
        if v not in ("elasticsearch", "opensearch"):
            raise ValueError("ES_FLAVOR must be elasticsearch or opensearch")
        return v

    @field_validator("es_read_only_roles")
    @classmethod
    def _read_only_roles(cls, v: list[str]) -> list[str]:
        roles = [role.strip() for role in v]
        if any(not role or any(ch.isspace() for ch in role) for role in roles):
            raise ValueError("ES_READ_ONLY_ROLES must be comma-separated role names without spaces")
        # OpenSearch's built-in superuser role grants writes to every index: it can never prove read-only access
        if FULL_ACCESS_ROLE in roles:
            raise ValueError(f"ES_READ_ONLY_ROLES must not name {FULL_ACCESS_ROLE}, which can write to every index")
        return roles

    @field_validator("arkime_base_path")
    @classmethod
    def _arkime_base_path(cls, v: str) -> str:
        # one or more plain path segments; no query, fragment, encoding or dot segments can reach the viewer URL
        path = v.strip().rstrip("/")
        if path and (not _BASE_PATH.fullmatch(path) or any(seg in (".", "..") for seg in path.split("/"))):
            raise ValueError("ARKIME_BASE_PATH must be empty or a path such as /arkime (letters, digits, . _ ~ -)")
        return path

    @field_validator("arkime_auth", mode="before")
    @classmethod
    def _arkime_auth(cls, v: str) -> str:
        if v not in ("digest", "basic"):
            raise ValueError("ARKIME_AUTH must be digest or basic")
        return v

    @field_validator("agent_effort", mode="before")
    @classmethod
    def _agent_effort(cls, v: str) -> str:
        if v not in ("low", "medium", "high", "xhigh", "max"):
            raise ValueError("AGENT_EFFORT must be low, medium, high, xhigh or max")
        return v

    @field_validator("agent_refusal_fallback", mode="before")
    @classmethod
    def _agent_refusal_fallback(cls, v: str) -> str:
        if v not in ("default", "off"):
            raise ValueError("AGENT_REFUSAL_FALLBACK must be default or off")
        return v

    @field_validator("agent_triage_model")
    @classmethod
    def _agent_triage_model(cls, v: str) -> str:
        v = v.strip()
        if v and not MODEL_ID.fullmatch(v):
            raise ValueError("AGENT_TRIAGE_MODEL must be empty or a model id of 1 to 128 letters, digits and "
                             ". _ : / - characters")
        return v

    @field_validator("model_egress", mode="before")
    @classmethod
    def _egress(cls, v: str) -> str:
        # a misspelled switch must fail loudly, never silently keep or open egress
        if v not in ("", "lab-public-data"):
            raise ValueError("ROMULUS_MODEL_EGRESS must be empty or lab-public-data")
        return v

    @field_validator("internal_networks", "external_networks")
    @classmethod
    def _networks(cls, v: list[str], info) -> list[str]:
        parse_networks(v, INTERNAL_SETTING if info.field_name == "internal_networks" else EXTERNAL_SETTING)
        return v

    @model_validator(mode="after")
    def _site_networks(self):
        # a carve-out must sit inside the internal set: checked once both lists are known (the site file is
        # validated where it is read, not while settings load)
        SiteNetworks.from_lists(self.internal_networks, self.external_networks)
        return self

    @property
    def stage_path(self) -> Path:
        """The directory a hunt stages events and detector state in."""
        return self.stage_dir if self.stage_dir is not None else self.home / "stage"

    @property
    def db_path(self) -> Path:
        return self.home / "db" / "romulus.db"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    @property
    def web_tls_enabled(self) -> bool:
        return bool(self.web_tls_cert and self.web_tls_key)

    @property
    def synthesis_model(self) -> str:
        return self.ollama_model_synthesis or self.ollama_model_triage

    def redacted(self) -> dict[str, str]:
        """Safe-to-print view: secrets show only whether they are set."""
        out = {}
        for name, value in self.model_dump().items():
            if isinstance(getattr(self, name), SecretStr):
                out[name] = "<set>" if getattr(self, name).get_secret_value() else "<unset>"
            else:
                out[name] = str(value)
        return out


ENV_MAP = {
    "ROMULUS_HOME": "home", "ROMULUS_SITE": "site", "ROMULUS_EVAL_ROOT": "eval_root",
    "ROMULUS_MENTION_DIR": "mention_dir", "ROMULUS_MENTION_RESIDUE_RECORDS": "mention_residue_records",
    "ROMULUS_WEB_BIND": "web_bind", "ROMULUS_SECRET_KEY": "secret_key",
    "ROMULUS_WEB_TLS_CERT": "web_tls_cert", "ROMULUS_WEB_TLS_KEY": "web_tls_key",
    "OLLAMA_URL": "ollama_url", "OLLAMA_MODEL_TRIAGE": "ollama_model_triage",
    "OLLAMA_MODEL_SYNTHESIS": "ollama_model_synthesis", "OLLAMA_NUM_CTX": "ollama_num_ctx",
    "OLLAMA_TIMEOUT_SECONDS": "ollama_timeout_seconds", "OLLAMA_KEEP_ALIVE": "ollama_keep_alive",
    "OLLAMA_THINK": "ollama_think",
    "ES_URL": "es_url", "ES_FLAVOR": "es_flavor", "ES_USERNAME": "es_username", "ES_PASSWORD": "es_password",
    "ES_API_KEY": "es_api_key", "ES_CA_CERT": "es_ca_cert", "ES_VERIFY_TLS": "es_verify_tls",
    "ES_INDEX_PATTERNS": "es_index_patterns", "ES_COMPRESSION": "es_compression",
    "ES_READ_ONLY_ROLES": "es_read_only_roles",
    "ROMULUS_SWEEP_PREFETCH": "sweep_prefetch",
    "ROMULUS_STAGE_DIR": "stage_dir", "ROMULUS_STATE_DISK_GB": "state_disk_gb", "ROMULUS_STATE_DISK_RESERVE_GB": "state_disk_reserve_gb",
    "ROMULUS_STATE_MEMORY_MB": "state_memory_mb", "ROMULUS_BASELINE_RETAIN_DISK_GB": "baseline_retain_disk_gb",
    "ROMULUS_BASELINE_CARRY_DISK_GB": "baseline_carry_disk_gb",
    "ROMULUS_EXPANSION_MAX_SOURCE_QUERIES": "expansion_max_source_queries",
    "ROMULUS_EXPANSION_WALL_CLOCK_MINUTES": "expansion_wall_clock_minutes",
    "ROMULUS_HUNT_STOP_GRACE_SECONDS": "hunt_stop_grace_seconds",
    "ROMULUS_ZEEK_VISIBILITY_DISK_MB": "zeek_visibility_disk_mb",
    "ROMULUS_ZEEK_VISIBILITY_MAX_PAGES": "zeek_visibility_max_pages",
    "ROMULUS_ZEEK_VISIBILITY_DEADLINE_SECONDS": "zeek_visibility_deadline_seconds",
    "ARKIME_URL": "arkime_url", "ARKIME_USERNAME": "arkime_username", "ARKIME_PASSWORD": "arkime_password",
    "ARKIME_VERIFY_TLS": "arkime_verify_tls", "ARKIME_BASE_PATH": "arkime_base_path", "ARKIME_AUTH": "arkime_auth",
    "PCAP_ALLOWED_DIRS": "pcap_allowed_dirs", "TSHARK_BIN": "tshark_bin", "MISSION_TIMEZONE": "mission_timezone",
    "ROMULUS_ALLOW_PRIVILEGED_SOURCE_ACCOUNT": "allow_privileged_source_account",
    "AGENT_PROVIDER": "agent_provider", "AGENT_BASE_URL": "agent_base_url", "AGENT_API_KEY": "agent_api_key",
    "AGENT_MODEL": "agent_model", "AGENT_DEFAULT": "agent_default", "AGENT_CONTEXT_TOKENS": "agent_context_tokens",
    "AGENT_MAX_OUTPUT_TOKENS": "agent_max_output_tokens", "AGENT_THINKING_TOKENS": "agent_thinking_tokens",
    "AGENT_EFFORT": "agent_effort", "AGENT_REFUSAL_FALLBACK": "agent_refusal_fallback",
    "AGENT_TIMEOUT_SECONDS": "agent_timeout_seconds",
    "AGENT_MAX_CALLS": "agent_max_calls", "AGENT_MAX_TOKENS": "agent_max_tokens",
    "AGENT_MAX_WALL_SECONDS": "agent_max_wall_seconds", "AGENT_MAX_COST_USD": "agent_max_cost_usd",
    "AGENT_PRICE_INPUT_PER_MTOK": "agent_price_input_per_mtok",
    "AGENT_PRICE_OUTPUT_PER_MTOK": "agent_price_output_per_mtok",
    "AGENT_PRICE_CACHE_READ_PER_MTOK": "agent_price_cache_read_per_mtok",
    "AGENT_PRICE_CACHE_WRITE_PER_MTOK": "agent_price_cache_write_per_mtok",
    "AGENT_PRICE_FALLBACK_INPUT_PER_MTOK": "agent_price_fallback_input_per_mtok",
    "AGENT_PRICE_FALLBACK_OUTPUT_PER_MTOK": "agent_price_fallback_output_per_mtok",
    "AGENT_PRICE_FALLBACK_CACHE_READ_PER_MTOK": "agent_price_fallback_cache_read_per_mtok",
    "AGENT_CACHE_READ_TOKEN_WEIGHT": "agent_cache_read_token_weight",
    "AGENT_CACHE_WRITE_TOKEN_WEIGHT": "agent_cache_write_token_weight",
    "AGENT_MAX_TOOL_CALLS_PER_SESSION": "agent_max_tool_calls_per_session",
    "AGENT_MAX_SOURCE_QUERIES": "agent_max_source_queries",
    "AGENT_CONCURRENCY": "agent_concurrency",
    "AGENT_MAX_INITIAL_HYPOTHESES": "agent_max_initial_hypotheses",
    "AGENT_MAX_HYPOTHESES": "agent_max_hypotheses",
    "AGENT_MAX_SESSIONS_PER_HYPOTHESIS": "agent_max_sessions_per_hypothesis",
    "AGENT_ASSESS_RESERVE_FRACTION": "agent_assess_reserve_fraction",
    "AGENT_BUDGET_CEILING_MULTIPLIER": "agent_budget_ceiling_multiplier",
    "AGENT_MAX_FINDINGS": "agent_max_findings", "AGENT_MAX_LINKS": "agent_max_links",
    "AGENT_MAX_NOTES": "agent_max_notes",
    "AGENT_MAX_RAW_RECORDS": "agent_max_raw_records",
    "AGENT_TRIAGE": "agent_triage",
    "AGENT_TRIAGE_MODEL": "agent_triage_model",
    "AGENT_TRIAGE_PROMOTE_PER_LANE": "agent_triage_promote_per_lane",
    "AGENT_TRIAGE_MAX_CALLS": "agent_triage_max_calls",
    "AGENT_TRIAGE_MAX_INPUT_TOKENS": "agent_triage_max_input_tokens",
    "AGENT_TRIAGE_MAX_OUTPUT_TOKENS": "agent_triage_max_output_tokens",
    "AGENT_TRIAGE_MAX_WALL_SECONDS": "agent_triage_max_wall_seconds",
    "AGENT_TRIAGE_CALL_INPUT_TOKENS": "agent_triage_call_input_tokens",
    "AGENT_TRIAGE_CALL_OUTPUT_TOKENS": "agent_triage_call_output_tokens",
    "AGENT_TRIAGE_CITED_MAX_GROUPS": "agent_triage_cited_max_groups",
    "ROMULUS_MODEL_EGRESS": "model_egress", "MODEL_LOCAL_HOSTS": "model_local_hosts",
    "ROMULUS_INTERNAL_NETWORKS": "internal_networks", "ROMULUS_EXTERNAL_NETWORKS": "external_networks",
}


def load_settings(env_file: Path | None = None, environ: dict[str, str] | None = None) -> Settings:
    """Precedence: process environment > .env file > defaults."""
    environ = dict(os.environ) if environ is None else environ
    if env_file is None:
        env_file = Path(environ.get("ROMULUS_ENV_FILE", ".env"))
    merged = {**parse_env_file(env_file), **{k: v for k, v in environ.items() if k in ENV_MAP}}
    if "AGENT_MODE" in (dict(environ) | parse_env_file(env_file)):
        import logging
        logging.getLogger("romulus.config").warning("AGENT_MODE is deprecated and ignored; use AGENT_DEFAULT and --agent/--no-agent")
    kwargs = {ENV_MAP[k]: v for k, v in merged.items() if k in ENV_MAP and v != ""}
    return Settings(**kwargs)


def with_agent_model(settings: Settings, model: str | None) -> Settings:
    """`settings` with AGENT_MODEL replaced for one run (nothing is written back); unchanged when `model` is None.
    Raises ValueError for anything but a plain model id."""
    if model is None:
        return settings
    if not MODEL_ID.fullmatch(model):
        raise ValueError("--agent-model must be a model id of 1 to 128 letters, digits and . _ : / - characters")
    return settings.model_copy(update={"agent_model": model})


def triage_model(settings: Settings, model: str | None = None) -> tuple[str, str]:
    """The triage pass's model and where it came from: `model` (`romulus triage --agent-model`), else
    AGENT_TRIAGE_MODEL, else AGENT_MODEL. Raises ValueError for a malformed `model`."""
    if model is not None:
        return with_agent_model(settings, model).agent_model, "--agent-model"
    if settings.agent_triage_model:
        return settings.agent_triage_model, "AGENT_TRIAGE_MODEL"
    return settings.agent_model.strip(), "AGENT_MODEL"


def triage_settings(settings: Settings, model: str | None = None) -> Settings:
    """`settings` for the triage pass: AGENT_MODEL replaced by its model (`triage_model`), for that pass only."""
    chosen, _source = triage_model(settings, model)
    return settings if chosen == settings.agent_model else settings.model_copy(update={"agent_model": chosen})


def secret_settings(settings: Settings) -> list[tuple[str, str]]:
    """Every configured (non-empty) secret as (environment name, value), in field order. Callers report only the
    name: a value never leaves this list."""
    names = {field: key for key, field in ENV_MAP.items()}
    return [(names.get(name, name.upper()), getattr(settings, name).get_secret_value())
            for name in type(settings).model_fields
            if isinstance(getattr(settings, name), SecretStr) and getattr(settings, name).get_secret_value()]


def short_secrets(settings: Settings) -> list[str]:
    """The environment names of configured secrets shorter than MIN_SECRET_LENGTH (never their values or lengths).
    Text that short also turns up in ordinary words, so redacting it distorts prompts and reports, and below 4
    characters it is not redacted at all."""
    return sorted(name for name, value in secret_settings(settings) if len(value) < MIN_SECRET_LENGTH)


# A configured secret is weak when any of these measures holds. Doctor's secrets.strength warning and the AI agent's
# secret guard both use this one rule.
# - It is shorter than MIN_SECRET_LENGTH (doctor's secrets.length warning reports those).
# - It is under WEAK_SINGLE_CLASS_BELOW characters and uses one character class: all letters (either case), all
#   digits, or all other characters. Ordinary words are all letters. A longer single-class value is left to the
#   entropy measure, since a long random string of letters is strong.
# - Its estimated entropy, its length times the Shannon entropy of its own character distribution, is under
#   WEAK_ENTROPY_BITS. The estimate is at most length x log2(length), so any value under about 12 characters scores
#   below the threshold (such a value is weak whatever its characters); a 32-character random key scores about 150.
# - It occurs as a whole word, in any case, in the product's own source or templates: public text the agent's secret
#   guard would also match.
# No wordlist is bundled with the product, so dictionary words are found by the second and last measures.
#
# The rule decides only what a secret in a model reply does to the agent's session, never what is redacted: every
# secret's text is redacted wherever it appears. A weak secret in a reply is scrubbed and the session goes on; a
# strong one ends the session at the secret guard.
WEAK_ENTROPY_BITS = 40.0
WEAK_SINGLE_CLASS_BELOW = 32
SOURCE_SUFFIXES = frozenset({".py", ".html", ".md", ".js", ".css", ".mako", ".txt", ".json", ".yml", ".yaml",
                             ".toml", ".sql", ".j2"})
SOURCE_FILE_MAX_BYTES = 8 * 2**20
_WORD = "A-Za-z0-9_"
_PACKAGE_ROOT = Path(__file__).resolve().parent


def _entropy_bits(value: str) -> float:
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -n * sum(c / n * math.log2(c / n) for c in counts.values())


def _single_class(value: str) -> bool:
    classes = {"letter" if ch.isalpha() else "digit" if ch.isdigit() else "other" for ch in value}
    return len(classes) == 1


def _source_words(values: list[str], root: Path) -> set[str]:
    """The values that occur as a whole word (any case) in the text files under `root`. Each file is read once."""
    pending = {value: re.compile(rf"(?<![{_WORD}]){re.escape(value)}(?![{_WORD}])", re.IGNORECASE)
               for value in values}
    found: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not pending:
            break
        try:
            if path.suffix.lower() not in SOURCE_SUFFIXES or not path.is_file() \
                    or path.stat().st_size > SOURCE_FILE_MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lowered = text.lower()
        for value, pattern in list(pending.items()):
            if value.lower() in lowered and pattern.search(text):
                found.add(value)
                del pending[value]
    return found


def _classify(secrets: tuple[tuple[str, str], ...], root: Path) -> frozenset[str]:
    weak = {name for name, value in secrets
            if len(value) < MIN_SECRET_LENGTH
            or (len(value) < WEAK_SINGLE_CLASS_BELOW and _single_class(value))
            or _entropy_bits(value) < WEAK_ENTROPY_BITS}
    rest = [value for name, value in secrets if name not in weak]
    if rest:
        in_source = _source_words(rest, root)
        weak |= {name for name, value in secrets if value in in_source}
    return frozenset(weak)


@functools.lru_cache(maxsize=16)
def _classify_in_package(secrets: tuple[tuple[str, str], ...]) -> frozenset[str]:
    # the package's own text does not change while the process runs, so each set of secrets is judged once
    return _classify(secrets, _PACKAGE_ROOT)


def weak_secret_names(settings: Settings, source_root: Path | None = None) -> frozenset[str]:
    """The environment names of the configured secrets that are weak (the measures above), judged against the text
    files under `source_root`, by default the product's own package (judged once per process). Names only: never a
    value, which measure fired, or a length."""
    secrets = tuple(secret_settings(settings))
    if not secrets:
        return frozenset()
    return _classify_in_package(secrets) if source_root is None else _classify(secrets, source_root)


# how JSON encoders that escape HTML-significant characters write them (lower- and upper-case hex)
_HTML_SAFE_ESCAPES = ({"&": "\\u0026", "<": "\\u003c", ">": "\\u003e", "'": "\\u0027"},
                      {"&": "\\u0026", "<": "\\u003C", ">": "\\u003E", "'": "\\u0027"})
MASKED_SECRET_MIN_LENGTH = 16   # a masked echo (prefix****last four) is matched only for secrets at least this long


def _secret_forms(secret: str) -> set[str]:
    """The secret as text, and as it appears inside a JSON string (escaped, also with HTML-safe escapes)."""
    escaped = json.dumps(secret)[1:-1]
    return {secret, escaped, *("".join(table.get(c, c) for c in escaped) for table in _HTML_SAFE_ESCAPES)}


def redact_text(text: str, settings: Settings) -> str:
    """Remove any configured secret value from free text (logs, error messages): as written, as escaped inside a
    JSON string, and as a service's masked echo of a long key (its first characters, asterisks, its last four)."""
    return redact_counted(text, settings, None)


def redact_counted(text: str, settings: Settings, counts: dict[str, int] | None,
                   only: Collection[str] | None = None) -> str:
    """`redact_text`, adding to `counts` how many replacements each secret's setting (by environment name) needed.
    The counts carry names and numbers only: never a value or the text around it. Every secret's text is replaced
    wherever it appears, weak or strong. `only`, when given, limits the redaction to those settings."""
    chosen = [(name, secret) for name, secret in secret_settings(settings)
              if len(secret) >= 4 and (only is None or name in only)]
    replaced: dict[str, int] = {}
    # longest first: a secret whose text holds a shorter one's is replaced whole before the shorter one is looked for
    for name, secret in sorted(chosen, key=lambda item: -len(item[1])):
        for form in sorted(_secret_forms(secret), key=len, reverse=True):
            found = text.count(form)
            if found:
                replaced[name] = replaced.get(name, 0) + found
                text = text.replace(form, "<redacted>")
    # Masked echoes only after every exact value is gone, so a value glued to an echo cannot shield it.
    for name, secret in chosen:
        if len(secret) >= MASKED_SECRET_MIN_LENGTH and "****" in text:
            # Key characters only, bounded and delimited: never spans punctuation or starts inside a word,
            # and stays linear on long runs.
            masked = (r"(?<![A-Za-z0-9_-])" + re.escape(secret[:3]) + r"[A-Za-z0-9_-]{0,64}\*{4,64}"
                      r"[A-Za-z0-9_-]{0,16}?" + re.escape(secret[-4:]) + r"(?![A-Za-z0-9_-])")
            text, found = re.subn(masked, "<redacted>", text)
            if found:
                replaced[name] = replaced.get(name, 0) + found
    if counts is not None:
        for name, found in replaced.items():
            counts[name] = counts.get(name, 0) + found
    return text
