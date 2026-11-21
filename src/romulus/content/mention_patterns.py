"""Mention patterns: curated, sourced text patterns the mention sweep looks for in unparsed text.

Each file in the mention directory (`content/mentions/*.yaml`, or `ROMULUS_MENTION_DIR`) is a YAML list of patterns:

    - id: mention.<slug>            # unique across every file
      title: str
      match: {literal: [str, ...]} | {anchored: str}
      case_sensitive: bool
      strength: strong | medium | weak
      attack: [T1059.004, ...]      # optional: the pattern's own metadata, never an observed technique
      telemetry: [linux_text, windows_text, any]
      source: {name: str, url: str, license: str, upstream_id: str | null}
      rationale: str
      examples: {positive: [str, ...], negative: [str, ...]}

A file is validated strictly as a whole before any of its patterns run: an unknown key, a missing field, a duplicate
id, an expression outside the admitted subset, or an example that does not behave as stated (every positive must match
and no negative may) refuses the whole file, with an error naming the file, the pattern and the reason. A refused file
is reported (its patterns did not run); it never makes a hunt read as having no mentions.

An anchored expression must be linear-time to run on attacker-written text. It must start with `^` or with a literal
prefix of at least four characters (the matcher runs it only where that prefix occurs), be at most 512 characters, and
use only literals, character classes, `.`, groups, alternation, repeats and `^`/`\\A`/`\\b`/`\\B`. It may not use back
references, lookaround, conditionals, atomic groups, possessive repeats, inline flags or end anchors (the matcher reads
a bounded window, where an end anchor would also match at the window's edge). No repeat may hold another repeat or an
alternation, and the backtracking product of its repeats and alternations must stay within the matcher's bound (two
unbounded repeats at most).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from romulus.evidence.mention_match import (
    BACKTRACK_BOUND,
    REGEX_WINDOW,
    CompiledPattern,
    MentionMatcher,
    bound_text,
)

try:  # the regex parser the standard library compiles with
    from re import _constants as _sre
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover - older interpreters
    import sre_constants as _sre
    import sre_parse as _sre_parse

MAX_ANCHORED_CHARS = 512
MIN_PREFIX_CHARS = 4
MIN_LITERAL_CHARS = 4
MAX_LITERAL_CHARS = 512
MAX_LITERALS = 256
MAX_EXAMPLE_CHARS = 4_096
MAX_FILE_BYTES = 4_000_000
_ID = r"^mention\.[a-z0-9][a-z0-9_.-]{0,126}$"
_TECHNIQUE = r"^T[0-9]{4}(?:\.[0-9]{3})?$"


class MentionPatternError(ValueError):
    """A mention pattern file that may not run, with the reason."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class MatchSpec(_Strict):
    literal: list[str] | None = None
    anchored: str | None = None

    @model_validator(mode="after")
    def _one(self):
        if (self.literal is None) == (self.anchored is None):
            raise ValueError("match takes exactly one of literal and anchored")
        if self.literal is not None:
            if not self.literal or len(self.literal) > MAX_LITERALS:
                raise ValueError(f"match.literal needs 1 to {MAX_LITERALS} strings")
            for value in self.literal:
                if not MIN_LITERAL_CHARS <= len(value) <= MAX_LITERAL_CHARS or not value.strip():
                    raise ValueError(f"literal {value!r}: {MIN_LITERAL_CHARS} to {MAX_LITERAL_CHARS} characters, "
                                     "not only whitespace")
            if len(set(self.literal)) != len(self.literal):
                raise ValueError("match.literal repeats a string")
        return self


class Source(_Strict):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=1000)
    license: str = Field(min_length=1, max_length=200)
    upstream_id: str | None = Field(max_length=500)


class Examples(_Strict):
    positive: list[str] = Field(min_length=1, max_length=50)
    negative: list[str] = Field(min_length=1, max_length=50)

    @field_validator("positive", "negative")
    @classmethod
    def _bounded(cls, values: list[str]) -> list[str]:
        if any(len(value) > MAX_EXAMPLE_CHARS for value in values):
            raise ValueError(f"an example is longer than {MAX_EXAMPLE_CHARS} characters")
        return values


class MentionPattern(_Strict):
    id: str = Field(pattern=_ID)
    title: str = Field(min_length=1, max_length=200)
    match: MatchSpec
    case_sensitive: bool
    strength: Literal["strong", "medium", "weak"]
    attack: list[str] = Field(default_factory=list, max_length=20)
    telemetry: list[Literal["linux_text", "windows_text", "any"]] = Field(min_length=1, max_length=3)
    source: Source
    rationale: str = Field(min_length=1, max_length=2000)
    examples: Examples

    @field_validator("attack")
    @classmethod
    def _techniques(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(_TECHNIQUE, value):
                raise ValueError(f"attack: {value!r} is not an ATT&CK technique id (T1234 or T1234.001)")
        if len(set(values)) != len(values):
            raise ValueError("attack repeats a technique")
        return values

    @field_validator("telemetry")
    @classmethod
    def _telemetry(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("telemetry repeats a class")
        return values


@dataclass
class PatternSet:
    """The patterns a hunt runs, and every file that was refused (its patterns did not run)."""
    patterns: list[MentionPattern] = field(default_factory=list)
    compiled: list[CompiledPattern] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)       # {name, digest, patterns}
    refused: list[dict] = field(default_factory=list)     # {name, error}
    directory: str = ""
    digest: str = "none"

    def summary(self) -> dict:
        return {"directory": self.directory, "digest": self.digest, "patterns": len(self.patterns),
                "files": list(self.files), "refused": list(self.refused)}


def mention_dir() -> Path:
    override = os.environ.get("ROMULUS_MENTION_DIR")
    return Path(override) if override else Path(__file__).resolve().parents[3] / "content" / "mentions"


# ---- anchored expressions -------------------------------------------------------------------------------------------
_ATOMS = {_sre.LITERAL, _sre.NOT_LITERAL, _sre.ANY, _sre.IN}
_ALLOWED_AT = {_sre.AT_BEGINNING, _sre.AT_BEGINNING_STRING, _sre.AT_BOUNDARY, _sre.AT_NON_BOUNDARY}
_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT}


def _ways(items, in_repeat: bool) -> int:
    """The backtracking product of a parsed sequence; raises ValueError on anything outside the subset."""
    product = 1
    for op, arg in items:
        if op in _ATOMS:
            continue
        if op == _sre.AT:
            if arg not in _ALLOWED_AT:
                raise ValueError("end anchors ($, \\Z) are refused: the matcher reads a bounded window")
            continue
        if op == _sre.SUBPATTERN:
            _group, add_flags, del_flags, body = arg
            if add_flags or del_flags:
                raise ValueError("inline flags are refused: case is set by case_sensitive")
            product *= _ways(body, in_repeat)
        elif op == _sre.BRANCH:
            if in_repeat:
                raise ValueError("an alternation inside a repeat is refused (it can backtrack exponentially)")
            alternatives = arg[1]
            product *= max(1, sum(_ways(alt, in_repeat) for alt in alternatives))
        elif op in _REPEATS:
            low, high, body = arg
            if in_repeat:
                raise ValueError("a repeat inside a repeat is refused (nested quantifiers)")
            unbounded = high == _sre.MAXREPEAT
            _ways(body, True)
            if unbounded and not (len(body) == 1 and body[0][0] in _ATOMS):
                raise ValueError("an unbounded repeat must be of one character, class or '.'")
            # the ways a repeat can stop inside the window: never more than the window's characters
            product *= REGEX_WINDOW if unbounded else max(1, min(int(high) - int(low) + 1, REGEX_WINDOW))
        else:
            raise ValueError(f"{str(op).lower()} is refused (back references, lookaround, conditionals, atomic "
                             "groups and possessive repeats are outside the admitted subset)")
        if product > BACKTRACK_BOUND:
            raise ValueError(f"the expression may backtrack more than {BACKTRACK_BOUND} ways from one place "
                             "(at most two unbounded repeats)")
    return product


def compile_anchored(expression: str, case_sensitive: bool) -> tuple[re.Pattern, str | None]:
    """The compiled expression and its literal prefix (None when it starts with ^); ValueError when refused."""
    if not expression or len(expression) > MAX_ANCHORED_CHARS:
        raise ValueError(f"an anchored expression is 1 to {MAX_ANCHORED_CHARS} characters")
    try:
        parsed = _sre_parse.parse(expression, 0)
        compiled = re.compile(expression, 0 if case_sensitive else re.IGNORECASE)
    except re.error as error:
        raise ValueError(f"the expression does not compile: {error}") from None
    if parsed.state.flags & ~(_sre.SRE_FLAG_UNICODE):
        raise ValueError("inline flags are refused: case is set by case_sensitive")
    items = list(parsed)
    _ways(items, False)
    if items and items[0][0] == _sre.AT and items[0][1] in {_sre.AT_BEGINNING, _sre.AT_BEGINNING_STRING}:
        return compiled, None
    prefix = []
    for op, arg in items:
        if op != _sre.LITERAL:
            break
        prefix.append(chr(arg))
    # (a repeated last character, as in abcd+, is parsed into the repeat: it is never part of the prefix)
    if len(prefix) < MIN_PREFIX_CHARS:
        raise ValueError(f"an anchored expression must start with ^ or with a literal prefix of at least "
                         f"{MIN_PREFIX_CHARS} characters")
    return compiled, "".join(prefix)


def compile_pattern(index: int, pattern: MentionPattern) -> CompiledPattern:
    if pattern.match.anchored is not None:
        regex, prefix = compile_anchored(pattern.match.anchored, pattern.case_sensitive)
        return CompiledPattern(index=index, id=pattern.id, case_sensitive=pattern.case_sensitive, regex=regex,
                               prefix=prefix)
    return CompiledPattern(index=index, id=pattern.id, case_sensitive=pattern.case_sensitive,
                           literals=tuple(pattern.match.literal))


def _check_examples(name: str, patterns: list[MentionPattern], compiled: list[CompiledPattern]) -> None:
    """Every positive example matches its pattern and no negative does, through the matcher the sweep runs."""
    matcher = MentionMatcher(compiled)
    for pattern, built in zip(patterns, compiled, strict=True):
        for kind, values, wanted in (("positive", pattern.examples.positive, True),
                                     ("negative", pattern.examples.negative, False)):
            for value in values:
                if (built.index in matcher.match(bound_text(value)[0])) != wanted:
                    raise MentionPatternError(
                        f"{name}: {pattern.id}: {kind} example {value[:120]!r} "
                        f"{'does not match' if wanted else 'matches'}")


def load_pattern_file(path: Path, *, taken: set[str] | frozenset[str] = frozenset(),
                      start: int = 0) -> tuple[list[MentionPattern], list[CompiledPattern]]:
    """The validated patterns of one file (indexes from `start`); MentionPatternError when the file is refused.
    `taken` holds the ids earlier files already define."""
    name = path.name
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise MentionPatternError(f"{name}: larger than {MAX_FILE_BYTES} bytes")
    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as error:
        raise MentionPatternError(f"{name}: not valid UTF-8 YAML: {str(error)[:300]}") from None
    if not isinstance(document, list) or not document:
        raise MentionPatternError(f"{name}: the file must be a non-empty YAML list of patterns")
    patterns: list[MentionPattern] = []
    compiled: list[CompiledPattern] = []
    seen: set[str] = set()
    for position, item in enumerate(document):
        label = item.get("id") if isinstance(item, dict) and isinstance(item.get("id"), str) else f"#{position}"
        try:
            pattern = MentionPattern.model_validate(item)
        except ValidationError as error:
            problems = "; ".join(f"{'.'.join(str(part) for part in e['loc']) or '(pattern)'}: {e['msg']}"
                                 for e in error.errors(include_url=False))
            raise MentionPatternError(f"{name}: {label}: {problems[:600]}") from None
        if pattern.id in seen or pattern.id in taken:
            raise MentionPatternError(f"{name}: {pattern.id}: the id is defined twice")
        seen.add(pattern.id)
        try:
            compiled.append(compile_pattern(start + len(patterns), pattern))
        except ValueError as error:
            raise MentionPatternError(f"{name}: {pattern.id}: {error}") from None
        patterns.append(pattern)
    _check_examples(name, patterns, compiled)
    return patterns, compiled


def load_mention_patterns(directory: Path | None = None) -> PatternSet:
    """Every valid pattern file of the directory, in file-name order; a refused file is listed with its error. A
    missing directory or one without files gives an empty set, which the sweep reports as not scanned."""
    root = directory or mention_dir()
    out = PatternSet(directory=str(root))
    files = sorted(root.glob("*.yaml")) if root.is_dir() else []
    taken: set[str] = set()
    whole = hashlib.sha256()
    for path in files:
        try:
            patterns, compiled = load_pattern_file(path, taken=frozenset(taken), start=len(out.patterns))
        except (MentionPatternError, OSError) as error:
            out.refused.append({"name": path.name, "error": str(error)[:800]})
            continue
        raw = path.read_bytes()
        file_digest = hashlib.sha256(raw).hexdigest()
        whole.update(json.dumps([path.name, file_digest]).encode())
        taken.update(pattern.id for pattern in patterns)
        out.patterns.extend(patterns)
        out.compiled.extend(compiled)
        out.files.append({"name": path.name, "digest": file_digest, "patterns": len(patterns)})
    if out.files:
        out.digest = whole.hexdigest()
    return out
