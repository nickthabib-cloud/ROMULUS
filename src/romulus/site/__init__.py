"""Validated, site-local collection attestations with no runtime I/O beyond reading their file."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

COLLECTION_SCHEMA = "romulus-site-collection@1"
COLLECTION_PATH = Path("site") / "collection.yaml"
_HOST_GLOB = re.compile(r"^[a-z0-9*?](?:[a-z0-9._*?-]*[a-z0-9*?])?$")
_SID = re.compile(r"^s-\d+(?:-\d+)+$", re.IGNORECASE)
_ACCOUNT = re.compile(r"^[^\\/\s]+\\[^\\/\r\n]+$")


class SiteValidationError(ValueError):
    """The site collection file is present but unsafe or malformed."""


class SiteChangedError(RuntimeError):
    """A hunt cannot continue under different site facts."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueKeyLoader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise SiteValidationError(f"duplicate key {key!r} in collection.yaml")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _canonical_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _host_glob(value: str) -> str:
    normalized = _canonical_host(value)
    if (
        not normalized
        or not _HOST_GLOB.fullmatch(normalized)
        or ".." in normalized
        or normalized.startswith(".")
        or normalized.endswith(".")
    ):
        raise ValueError(f"invalid host glob {value!r}")
    return normalized


def canonical_account(value: str) -> str:
    normalized = value.strip()
    if _SID.fullmatch(normalized):
        return f"sid:{normalized.lower()}"
    if _ACCOUNT.fullmatch(normalized):
        return f"name:{normalized.lower()}"
    raise ValueError(f"directory_sync_accounts entry must be a SID or DOMAIN\\name: {value!r}")


class SysmonFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    installed: StrictBool
    event_ids: tuple[StrictInt, ...] = ()

    @field_validator("event_ids")
    @classmethod
    def _event_ids(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(type(item) is not int or item < 1 or item > 65_535 for item in value):
            raise ValueError("event_ids must contain integers from 1 through 65535")
        if len(set(value)) != len(value):
            raise ValueError("event_ids must not contain duplicates")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _installed_for_ids(self):
        if self.event_ids and not self.installed:
            raise ValueError("sysmon event_ids cannot be attested when installed is false")
        return self


class CollectionGroup(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hosts: Literal["all"] | tuple[str, ...]
    sysmon: SysmonFacts | None = None
    security_4688_command_line: StrictBool = False
    powershell_script_block: StrictBool = False
    audit_policy: dict[str, Literal["success", "failure", "both"]] = Field(default_factory=dict)
    defender_operational: StrictBool = False
    task_scheduler_operational: StrictBool = False
    system_event_log: StrictBool = False

    @field_validator("hosts", mode="before")
    @classmethod
    def _hosts(cls, value):
        if isinstance(value, str):
            if value.lower() != "all":
                raise ValueError("hosts must be a non-empty list of host globs or the string 'all'")
            return "all"
        if not isinstance(value, (list, tuple)) or not value:
            raise ValueError("hosts must be a non-empty list of host globs or the string 'all'")
        if any(not isinstance(item, str) for item in value):
            raise ValueError("host globs must be text")
        normalized = tuple(_host_glob(item) for item in value)
        if "*" in normalized:
            raise ValueError("catch-all host selector must use hosts: all")
        if len(set(normalized)) != len(normalized):
            raise ValueError("duplicate host glob within collection group")
        return normalized

    @field_validator("audit_policy")
    @classmethod
    def _audit_policy(cls, value):
        normalized = {}
        for key, setting in value.items():
            name = str(key).strip()
            if not name or any(ord(char) < 32 for char in name):
                raise ValueError("audit_policy subcategory names must be non-empty text")
            folded = name.casefold()
            if folded in normalized:
                raise ValueError(f"duplicate audit_policy subcategory {name!r}")
            normalized[folded] = setting
        return normalized

    def matches(self, host: str) -> bool:
        if self.hosts == "all":
            return True
        full = _canonical_host(host)
        short = full.split(".", 1)[0]
        return any(fnmatchcase(full, pattern) or fnmatchcase(short, pattern) for pattern in self.hosts)


class _SiteDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema: Literal[COLLECTION_SCHEMA]
    collection: tuple[CollectionGroup, ...] = ()
    domain_controllers: tuple[str, ...] = ()
    directory_sync_accounts: tuple[str, ...] = ()

    @field_validator("domain_controllers")
    @classmethod
    def _domain_controllers(cls, value):
        if any(not isinstance(item, str) for item in value):
            raise ValueError("domain_controllers entries must be text")
        normalized = tuple(_canonical_host(item) for item in value)
        if any(not item or "*" in item or "?" in item or not _HOST_GLOB.fullmatch(item) for item in normalized):
            raise ValueError("domain_controllers must contain host names, not globs")
        if len(set(normalized)) != len(normalized):
            raise ValueError("domain_controllers must not contain duplicates")
        return normalized

    @field_validator("directory_sync_accounts")
    @classmethod
    def _directory_sync_accounts(cls, value):
        if any(not isinstance(item, str) for item in value):
            raise ValueError("directory_sync_accounts entries must be text")
        normalized = tuple(canonical_account(item) for item in value)
        if len(set(normalized)) != len(normalized):
            raise ValueError("directory_sync_accounts must not contain duplicates")
        return normalized

    @model_validator(mode="after")
    def _unique_groups(self):
        selectors: set[str] = set()
        for group in self.collection:
            group_selectors = ("all",) if group.hosts == "all" else group.hosts
            repeated = selectors.intersection(group_selectors)
            if repeated:
                raise ValueError(f"duplicate host group selector(s): {', '.join(sorted(repeated))}")
            selectors.update(group_selectors)
        return self


@dataclass(frozen=True)
class SiteFacts:
    present: bool
    digest: str
    content: dict
    groups: tuple[CollectionGroup, ...]
    domain_controllers: tuple[str, ...]
    directory_sync_accounts: tuple[str, ...]

    def _groups_for(self, host: str) -> tuple[CollectionGroup, ...]:
        matches = tuple(group for group in self.groups if group.hosts != "all" and group.matches(host))
        if matches:
            return matches
        return tuple(group for group in self.groups if group.hosts == "all")

    def attests(
        self,
        host: str,
        fact: str,
        *,
        event_id: int | None = None,
        subcategory: str | None = None,
        outcome: Literal["success", "failure"] | None = None,
    ) -> bool:
        """Conservatively require every equally specific matching group to attest the requested fact."""
        groups = self._groups_for(host)
        if not groups:
            return False
        values = []
        for group in groups:
            if fact == "host_group":
                values.append(True)
            elif fact == "sysmon":
                values.append(bool(group.sysmon and group.sysmon.installed and event_id in group.sysmon.event_ids))
            elif fact == "audit_policy":
                setting = group.audit_policy.get((subcategory or "").casefold())
                values.append(setting == "both" or setting == outcome)
            elif fact in {
                "security_4688_command_line",
                "powershell_script_block",
                "defender_operational",
                "task_scheduler_operational",
                "system_event_log",
            }:
                values.append(bool(getattr(group, fact)))
            else:
                return False
        return all(values)

    def manifest_entry(self) -> dict | None:
        if not self.present:
            return None
        return {"path": COLLECTION_PATH.as_posix(), "digest": self.digest, "content": self.content}


def _digest(content: dict) -> str:
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _absent() -> SiteFacts:
    return SiteFacts(False, "", {}, (), (), ())


def absent_site_facts() -> SiteFacts:
    """An explicit unattested value for callers that have no site file in scope."""
    return _absent()


def load_site_facts(home: Path) -> SiteFacts:
    path = Path(home) / COLLECTION_PATH
    if not path.exists():
        return _absent()
    try:
        loaded = yaml.load(path.read_text(encoding="utf-8-sig"), Loader=_UniqueKeyLoader)
        if not isinstance(loaded, dict):
            raise SiteValidationError("collection.yaml must contain one mapping")
        document = _SiteDocument.model_validate(loaded)
    except SiteValidationError:
        raise
    except (OSError, yaml.YAMLError, ValueError) as exc:
        detail = str(exc)
        if "Extra inputs are not permitted" in detail:
            detail = f"unknown key: {detail}"
        raise SiteValidationError(f"invalid {COLLECTION_PATH.as_posix()}: {detail}") from exc
    content = document.model_dump(mode="json")
    return SiteFacts(
        True,
        _digest(content),
        content,
        document.collection,
        document.domain_controllers,
        document.directory_sync_accounts,
    )


def ensure_site_unchanged(home: Path, recorded: dict | None) -> SiteFacts:
    current = load_site_facts(home)
    expected = str((recorded or {}).get("digest") or "")
    if current.digest != expected or current.present != bool(recorded):
        raise SiteChangedError(
            f"{COLLECTION_PATH.as_posix()} changed since the hunt was created; start a new hunt"
        )
    return current
