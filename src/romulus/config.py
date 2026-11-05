"""Load runtime configuration from the environment / .env with secret redaction."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

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
    # deterministic search is the default; the model is opt-in per hunt
    agent_mode: Literal["model", "deterministic", "off"] = "off"

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
    agent_max_tool_calls_per_session: int = Field(default=25, ge=1, le=500)
    agent_max_source_queries: int = Field(default=200, ge=1, le=100_000)
    agent_concurrency: int = Field(default=2, ge=1, le=16)
    # Bootstrap-only switch: the one value that lets telemetry excerpts reach a non-local model endpoint.
    model_egress: Literal["", "lab-public-data"] = ""
    # Extra hosts, addresses or CIDR networks treated as local (e.g. a team's model server on an enclave address).
    model_local_hosts: list[str] = []
    # The site's internal address space (CIDRs) and carve-outs inside it that are outside the site (partner or
    # VPN ranges). Unset, the default RFC 1918 and reserved ranges are used and labelled as the default.
    internal_networks: list[str] = []
    external_networks: list[str] = []

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

    @field_validator("agent_mode", mode="before")
    @classmethod
    def _agent_mode(cls, v: str) -> str:
        if v not in ("model", "deterministic", "off"):
            raise ValueError("AGENT_MODE must be model, deterministic, or off")
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
    "ARKIME_URL": "arkime_url", "ARKIME_USERNAME": "arkime_username", "ARKIME_PASSWORD": "arkime_password",
    "ARKIME_VERIFY_TLS": "arkime_verify_tls", "ARKIME_BASE_PATH": "arkime_base_path", "ARKIME_AUTH": "arkime_auth",
    "PCAP_ALLOWED_DIRS": "pcap_allowed_dirs", "TSHARK_BIN": "tshark_bin", "MISSION_TIMEZONE": "mission_timezone",
    "ROMULUS_ALLOW_PRIVILEGED_SOURCE_ACCOUNT": "allow_privileged_source_account",
    "AGENT_MODE": "agent_mode",
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
    "AGENT_MAX_TOOL_CALLS_PER_SESSION": "agent_max_tool_calls_per_session",
    "AGENT_MAX_SOURCE_QUERIES": "agent_max_source_queries",
    "AGENT_CONCURRENCY": "agent_concurrency",
    "ROMULUS_MODEL_EGRESS": "model_egress", "MODEL_LOCAL_HOSTS": "model_local_hosts",
    "ROMULUS_INTERNAL_NETWORKS": "internal_networks", "ROMULUS_EXTERNAL_NETWORKS": "external_networks",
}


def load_settings(env_file: Path | None = None, environ: dict[str, str] | None = None) -> Settings:
    """Precedence: process environment > .env file > defaults."""
    environ = dict(os.environ) if environ is None else environ
    if env_file is None:
        env_file = Path(environ.get("ROMULUS_ENV_FILE", ".env"))
    merged = {**parse_env_file(env_file), **{k: v for k, v in environ.items() if k in ENV_MAP}}
    kwargs = {ENV_MAP[k]: v for k, v in merged.items() if k in ENV_MAP and v != ""}
    return Settings(**kwargs)


def short_secrets(settings: Settings) -> list[str]:
    """The environment names of configured secrets shorter than MIN_SECRET_LENGTH (never their values or lengths).
    Text that short also turns up in ordinary words, so redacting it distorts prompts and reports, and below 4
    characters it is not redacted at all."""
    names = {field: key for key, field in ENV_MAP.items()}
    return sorted(names.get(name, name.upper()) for name in type(settings).model_fields
                  if isinstance(getattr(settings, name), SecretStr)
                  and 0 < len(getattr(settings, name).get_secret_value()) < MIN_SECRET_LENGTH)


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
    for name in type(settings).model_fields:
        value = getattr(settings, name)
        if isinstance(value, SecretStr):
            secret = value.get_secret_value()
            if secret and len(secret) >= 4:
                for form in sorted(_secret_forms(secret), key=len, reverse=True):
                    text = text.replace(form, "<redacted>")
                if len(secret) >= MASKED_SECRET_MIN_LENGTH and "****" in text:
                    # Key characters only, bounded and delimited: never spans punctuation or starts inside a word,
                    # and stays linear on long runs.
                    masked = (r"(?<![A-Za-z0-9_-])" + re.escape(secret[:3]) + r"[A-Za-z0-9_-]{0,64}\*{4,64}"
                              r"[A-Za-z0-9_-]{0,16}?" + re.escape(secret[-4:]) + r"(?![A-Za-z0-9_-])")
                    text = re.sub(masked, "<redacted>", text)
    return text
