"""Load runtime configuration from the environment / .env with secret redaction."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

from romulus.detect.netdef import EXTERNAL_SETTING, INTERNAL_SETTING, SiteNetworks, parse_networks

SECRET_KEYS = ("PASSWORD", "API_KEY", "SECRET", "TOKEN")


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
    # gzip responses (the client's default); false asks for uncompressed ones, cheaper to read on a fast link
    es_compression: bool = True
    # fetch the sweep's next partition on one background thread while the current one is evaluated; off by
    # default because it holds a second partition's decoded records in memory
    sweep_prefetch: bool = False

    arkime_url: str = "http://127.0.0.1:8005"
    arkime_username: str = ""
    arkime_password: SecretStr = SecretStr("")
    arkime_verify_tls: bool = True

    pcap_allowed_dirs: list[Path] = []
    tshark_bin: str = "tshark"
    mission_timezone: str = "UTC"
    allow_privileged_source_account: bool = False
    # deterministic search is the default; the model is opt-in per hunt
    agent_mode: Literal["model", "deterministic", "off"] = "off"

    # AI investigating agent: any OpenAI-compatible endpoint, or Ollama's native API. Unset means not configured.
    agent_provider: Literal["openai_compatible", "ollama"] = "openai_compatible"
    agent_base_url: str = ""
    agent_api_key: SecretStr = SecretStr("")
    agent_model: str = ""
    agent_default: Literal["on", "off"] = "on"
    agent_context_tokens: int = Field(default=0, ge=0, le=10_000_000)    # 0: the server enforces its own limit
    agent_max_output_tokens: int = Field(default=4096, ge=64, le=200_000)
    agent_timeout_seconds: int = Field(default=180, ge=5, le=3600)
    agent_max_calls: int = Field(default=200, ge=1, le=100_000)
    agent_max_tokens: int = Field(default=2_000_000, ge=1000, le=10_000_000_000)
    agent_max_wall_seconds: int = Field(default=3600, ge=60, le=7 * 24 * 3600)
    agent_max_cost_usd: float = Field(default=0.0, ge=0.0)                 # 0: no cost budget
    agent_price_input_per_mtok: float = Field(default=0.0, ge=0.0)         # USD per million prompt tokens
    agent_price_output_per_mtok: float = Field(default=0.0, ge=0.0)        # USD per million completion tokens
    agent_max_tool_calls_per_session: int = Field(default=25, ge=1, le=500)
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
                     "external_networks", mode="before")
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

    @field_validator("agent_mode", mode="before")
    @classmethod
    def _agent_mode(cls, v: str) -> str:
        if v not in ("model", "deterministic", "off"):
            raise ValueError("AGENT_MODE must be model, deterministic, or off")
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
        # a carve-out must sit inside the internal set: checked once both lists are known
        SiteNetworks.from_settings(self)
        return self

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
    "ROMULUS_HOME": "home", "ROMULUS_EVAL_ROOT": "eval_root", "ROMULUS_WEB_BIND": "web_bind", "ROMULUS_SECRET_KEY": "secret_key",
    "ROMULUS_WEB_TLS_CERT": "web_tls_cert", "ROMULUS_WEB_TLS_KEY": "web_tls_key",
    "OLLAMA_URL": "ollama_url", "OLLAMA_MODEL_TRIAGE": "ollama_model_triage",
    "OLLAMA_MODEL_SYNTHESIS": "ollama_model_synthesis", "OLLAMA_NUM_CTX": "ollama_num_ctx",
    "OLLAMA_TIMEOUT_SECONDS": "ollama_timeout_seconds", "OLLAMA_KEEP_ALIVE": "ollama_keep_alive",
    "OLLAMA_THINK": "ollama_think",
    "ES_URL": "es_url", "ES_FLAVOR": "es_flavor", "ES_USERNAME": "es_username", "ES_PASSWORD": "es_password",
    "ES_API_KEY": "es_api_key", "ES_CA_CERT": "es_ca_cert", "ES_VERIFY_TLS": "es_verify_tls",
    "ES_INDEX_PATTERNS": "es_index_patterns", "ES_COMPRESSION": "es_compression",
    "ROMULUS_SWEEP_PREFETCH": "sweep_prefetch",
    "ARKIME_URL": "arkime_url", "ARKIME_USERNAME": "arkime_username", "ARKIME_PASSWORD": "arkime_password",
    "ARKIME_VERIFY_TLS": "arkime_verify_tls",
    "PCAP_ALLOWED_DIRS": "pcap_allowed_dirs", "TSHARK_BIN": "tshark_bin", "MISSION_TIMEZONE": "mission_timezone",
    "ROMULUS_ALLOW_PRIVILEGED_SOURCE_ACCOUNT": "allow_privileged_source_account",
    "AGENT_MODE": "agent_mode",
    "AGENT_PROVIDER": "agent_provider", "AGENT_BASE_URL": "agent_base_url", "AGENT_API_KEY": "agent_api_key",
    "AGENT_MODEL": "agent_model", "AGENT_DEFAULT": "agent_default", "AGENT_CONTEXT_TOKENS": "agent_context_tokens",
    "AGENT_MAX_OUTPUT_TOKENS": "agent_max_output_tokens", "AGENT_TIMEOUT_SECONDS": "agent_timeout_seconds",
    "AGENT_MAX_CALLS": "agent_max_calls", "AGENT_MAX_TOKENS": "agent_max_tokens",
    "AGENT_MAX_WALL_SECONDS": "agent_max_wall_seconds", "AGENT_MAX_COST_USD": "agent_max_cost_usd",
    "AGENT_PRICE_INPUT_PER_MTOK": "agent_price_input_per_mtok",
    "AGENT_PRICE_OUTPUT_PER_MTOK": "agent_price_output_per_mtok",
    "AGENT_MAX_TOOL_CALLS_PER_SESSION": "agent_max_tool_calls_per_session",
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


def redact_text(text: str, settings: Settings) -> str:
    """Remove any configured secret value from free text (logs, error messages)."""
    for name in type(settings).model_fields:
        value = getattr(settings, name)
        if isinstance(value, SecretStr):
            secret = value.get_secret_value()
            if secret and len(secret) >= 4:
                text = text.replace(secret, "<redacted>")
    return text
