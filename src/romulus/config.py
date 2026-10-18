"""Load runtime configuration from the environment / .env with secret redaction."""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field, SecretStr, field_validator

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
        out[key.strip()] = value
    return out


class Settings(BaseModel):
    home: Path = Path("/home/user/romulus-v2")
    web_bind: str = "127.0.0.1:8443"
    web_tls_cert: str = ""
    web_tls_key: str = ""
    secret_key: SecretStr = SecretStr("")

    ollama_url: str = "http://192.168.36.1:11434"
    ollama_model_triage: str = "qwen3:8b"
    ollama_model_synthesis: str = ""
    ollama_num_ctx: int = Field(default=8192, ge=2048, le=131072)
    ollama_timeout_seconds: int = Field(default=300, ge=5, le=3600)
    ollama_keep_alive: str = "30m"
    ollama_think: bool = False

    es_url: str = "http://127.0.0.1:9200"
    es_flavor: str = "elasticsearch"
    es_username: str = ""
    es_password: SecretStr = SecretStr("")
    es_api_key: SecretStr = SecretStr("")
    es_ca_cert: str = ""
    es_verify_tls: bool = True
    es_index_patterns: list[str] = []

    arkime_url: str = "http://127.0.0.1:8005"
    arkime_username: str = ""
    arkime_password: SecretStr = SecretStr("")
    arkime_verify_tls: bool = True

    pcap_allowed_dirs: list[Path] = []
    tshark_bin: str = "tshark"
    mission_timezone: str = "UTC"
    allow_privileged_source_account: bool = False

    @field_validator("es_index_patterns", "pcap_allowed_dirs", mode="before")
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
    "ROMULUS_HOME": "home", "ROMULUS_WEB_BIND": "web_bind", "ROMULUS_SECRET_KEY": "secret_key",
    "ROMULUS_WEB_TLS_CERT": "web_tls_cert", "ROMULUS_WEB_TLS_KEY": "web_tls_key",
    "OLLAMA_URL": "ollama_url", "OLLAMA_MODEL_TRIAGE": "ollama_model_triage",
    "OLLAMA_MODEL_SYNTHESIS": "ollama_model_synthesis", "OLLAMA_NUM_CTX": "ollama_num_ctx",
    "OLLAMA_TIMEOUT_SECONDS": "ollama_timeout_seconds", "OLLAMA_KEEP_ALIVE": "ollama_keep_alive",
    "OLLAMA_THINK": "ollama_think",
    "ES_URL": "es_url", "ES_FLAVOR": "es_flavor", "ES_USERNAME": "es_username", "ES_PASSWORD": "es_password",
    "ES_API_KEY": "es_api_key", "ES_CA_CERT": "es_ca_cert", "ES_VERIFY_TLS": "es_verify_tls",
    "ES_INDEX_PATTERNS": "es_index_patterns",
    "ARKIME_URL": "arkime_url", "ARKIME_USERNAME": "arkime_username", "ARKIME_PASSWORD": "arkime_password",
    "ARKIME_VERIFY_TLS": "arkime_verify_tls",
    "PCAP_ALLOWED_DIRS": "pcap_allowed_dirs", "TSHARK_BIN": "tshark_bin", "MISSION_TIMEZONE": "mission_timezone",
    "ROMULUS_ALLOW_PRIVILEGED_SOURCE_ACCOUNT": "allow_privileged_source_account",
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
