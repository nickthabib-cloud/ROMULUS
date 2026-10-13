"""Environment-backed settings. Secrets are loaded but never included in repr/output."""
from dataclasses import dataclass
from pathlib import Path
import os
from urllib.parse import urlsplit, urlunsplit

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}

def _int(name: str, default: int, low: int, high: int) -> int:
    try: value = int(os.getenv(name, str(default)))
    except ValueError: value = default
    return max(low, min(value, high))

def _choice(name: str, default: str, allowed: set[str]) -> str:
    value=os.getenv(name,default).strip().lower()
    return value if value in allowed else default

def safe_url(value: str) -> str:
    """Remove userinfo, query strings, and fragments before displaying or persisting endpoints."""
    try:
        p=urlsplit(value); host=p.hostname or ""
        if p.port: host+=f":{p.port}"
        return urlunsplit((p.scheme,host,p.path,"",""))
    except ValueError: return "[configured endpoint]"

@dataclass(frozen=True)
class Settings:
    home: Path
    mode: str
    ollama_url: str
    ollama_model: str
    ollama_timeout: int
    es_url: str
    es_username: str
    es_password: str
    es_index_patterns: tuple[str, ...]
    es_verify_tls: bool
    es_default_hours: int
    historical_search: bool
    arkime_url: str
    arkime_username: str
    arkime_password: str
    arkime_api_path: str
    arkime_default_hours: int
    mission_timezone: str
    pcap_allowed_dirs: tuple[Path, ...]
    pcap_files: tuple[Path, ...]
    tshark_bin: str
    max_tool_calls: int
    max_depth: int
    min_reasoning_rounds: int
    max_runtime_seconds: int
    max_stagnant_cycles: int
    max_results: int
    arkime_max_results: int
    time_sampling_strata: int
    context_evidence_per_source: int
    tool_timeout_seconds: int
    max_retries: int
    retention_policy: str
    reports_dir: Path
    data_dir: Path
    logs_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        home = Path(os.getenv("ROMULUS_HOME", "/home/user/ROMULUS")).expanduser()
        def paths(key: str) -> tuple[Path, ...]:
            return tuple(Path(x.strip()).expanduser() for x in os.getenv(key, "").split(",") if x.strip())
        return cls(
            home=home, mode=os.getenv("ROMULUS_MODE", "live").lower(),
            ollama_url=os.getenv("OLLAMA_URL", "http://192.168.36.1:11434").rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen3:8b"), ollama_timeout=_int("OLLAMA_TIMEOUT", 180, 1, 600),
            es_url=os.getenv("ES_URL", "http://127.0.0.1:9200").rstrip("/"),
            es_username=os.getenv("ES_USERNAME", "romulus_agent"), es_password=os.getenv("ES_PASSWORD", ""),
            es_index_patterns=tuple(x.strip() for x in os.getenv("ES_INDEX_PATTERNS", "ainception-hostlogs-a-b,ainception-network-a-b").split(",") if x.strip()),
            es_verify_tls=_bool("ES_VERIFY_TLS", True), arkime_url=os.getenv("ARKIME_URL", "http://127.0.0.1:8005").rstrip("/"),
            es_default_hours=_int("ES_LOOKBACK_HOURS", 24, 1, 8760),
            historical_search=_bool("HISTORICAL_SEARCH", True),
            arkime_username=os.getenv("ARKIME_USERNAME", ""), arkime_password=os.getenv("ARKIME_PASSWORD", ""),
            arkime_api_path="/" + os.getenv("ARKIME_API_PATH", "/api/sessions").strip("/"),
            arkime_default_hours=_int("ARKIME_DATE_HOURS", 24, 1, 8760),
            mission_timezone=os.getenv("MISSION_TIMEZONE", "UTC").strip() or "UTC",
            pcap_allowed_dirs=paths("PCAP_ALLOWED_DIRS"), pcap_files=paths("PCAP_FILES"), tshark_bin=os.getenv("TSHARK_BIN", "tshark"),
            max_tool_calls=_int("MAX_TOOL_CALLS", 500, 1, 5000), max_depth=_int("MAX_DEPTH", 40, 1, 200),
            # Compatibility-only routing metadata during the deprecation cycle.
            min_reasoning_rounds=_int("MIN_REASONING_ROUNDS", 3, 1, 10),
            max_runtime_seconds=_int("MAX_RUNTIME_SECONDS", 3600, 10, 86400),
            max_stagnant_cycles=_int("MAX_STAGNANT_CYCLES", 3, 1, 10),
            max_results=_int("MAX_RESULTS", 10000, 1, 20000),
            arkime_max_results=_int("ARKIME_MAX_RESULTS", 20000, 1, 100000),
            time_sampling_strata=_int("TIME_SAMPLING_STRATA", 8, 2, 24),
            context_evidence_per_source=_int("CONTEXT_EVIDENCE_PER_SOURCE", 1000, 100, 5000),
            tool_timeout_seconds=_int("TOOL_TIMEOUT_SECONDS", 60, 1, 300), max_retries=_int("MAX_RETRIES", 2, 0, 5),
            retention_policy=_choice("RETENTION_POLICY","compact",{"compact","full"}),
            reports_dir=Path(os.getenv("REPORTS_DIR", str(home / "reports"))).expanduser(),
            data_dir=Path(os.getenv("DATA_DIR", str(home / "data"))).expanduser(),
            logs_dir=Path(os.getenv("LOGS_DIR", str(home / "logs"))).expanduser(),
        )

    def ensure_dirs(self) -> None:
        for path in (self.home, self.reports_dir, self.data_dir, self.logs_dir):
            path.mkdir(parents=True, exist_ok=True)
