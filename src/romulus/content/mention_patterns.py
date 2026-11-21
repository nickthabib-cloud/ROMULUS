"""Mention patterns: curated, sourced text patterns the mention sweep looks for in unparsed text.

Each file in the mention directory (`content/mentions/*.yaml`, or `ROMULUS_MENTION_DIR`) is a YAML list of patterns:

    - id: mention.<slug>            # unique across every file; slug: lowercase words joined by _
      title: str
      match: {literal: [str, ...]} | {anchored: str}
      case_sensitive: bool
      strength: strong | medium | weak
      attack: [T1059.004, ...]      # optional: the pattern's own metadata, never an observed technique
      telemetry: [linux_text, windows_text] | [any]            # any stands alone
      source: {name: str, url: str, license: str, upstream_id: str | null}   # upstream_id may be left out
      rationale: str
      examples: {positive: [str, ...], negative: [str, ...]}                 # one positive at least

A file is validated strictly as a whole before any of its patterns run: an unknown key, a missing field, a duplicate
id, an expression outside the admitted subset, or an example that does not behave as stated (every positive must match
and no negative may) refuses the whole file, with an error naming the file, the pattern and the reason. A refused file
is reported (its patterns did not run); it never makes a hunt read as having no mentions.

A literal matches as a substring, under the pattern's case flag. An anchored expression runs as a regular-expression
search (case-insensitive unless case_sensitive): it must start with `^`, or with a literal prefix of at least four
characters (after any leading `\b`), which may occur anywhere in the line (the matcher runs the expression only where
that prefix occurs).

A literal is 3 to 512 characters. An anchored expression must stay fast on attacker-written text. It is at most 512
characters and uses only literals, character classes, `.`, groups, alternation, repeats and the anchors `^`, `$`,
`\\A`, `\\Z`, `\\b` and `\\B`: no back references, lookaround, conditionals, atomic groups, possessive repeats or inline
flags. A repeat that can match more than once may hold neither another repeat nor an alternation (an optional group
may hold both), and at most four repeats may each match more than 16 characters. The upper bounds of its open gaps
(`.`, a negated class such as `[^\\n]`, or a negated character, each repeated) along any path sum to at most
MAX_GAP_SUM: an unbounded open gap is refused. Each expression is then timed at
load against lines built to make it backtrack (from its own examples), and refused when one takes longer than
`PROBE_LIMIT_SECONDS`. The matcher reads an expression over at most 512 characters from where it is tried; a line it
could not rule out there is counted in the pool's coverage.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from romulus.evidence.mention_match import (
    MAX_SCAN_CHARS,
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
MIN_LITERAL_CHARS = 3
MAX_LITERAL_CHARS = 512
MAX_LITERALS = 256
MAX_EXAMPLE_CHARS = 4_096
MAX_FILE_BYTES = 4_000_000
_ID = r"^mention\.[a-z0-9]+(?:_[a-z0-9]+)*$"
# repeats that may each match more than WIDE_REPEAT characters, at most this many per expression
WIDE_REPEAT = 16
MAX_WIDE_REPEATS = 4
# the sum of the upper bounds of the open gaps along any path through an anchored expression: each is where a
# backtracking engine re-scans, so keeping their sum small keeps the work from one place small
MAX_GAP_SUM = 360
# the longest one hostile probe line may take an anchored expression at load, its fastest of PROBE_RUNS runs (the
# curated corpus's worst is under 1 ms; the margin keeps a loaded machine from refusing a sound expression, while an
# expression that backtracks catastrophically takes seconds)
PROBE_LIMIT_SECONDS = 0.1
PROBE_RUNS = 3
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
    upstream_id: str | None = Field(default=None, max_length=500)


class Examples(_Strict):
    positive: list[str] = Field(min_length=1, max_length=50)
    negative: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("positive", "negative")
    @classmethod
    def _bounded(cls, values: list[str]) -> list[str]:
        if any(len(value) > MAX_EXAMPLE_CHARS for value in values):
            raise ValueError(f"an example is longer than {MAX_EXAMPLE_CHARS} characters")
        return values


class MentionPattern(_Strict):
    id: str = Field(pattern=_ID, max_length=128)
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
        if "any" in values and len(values) > 1:
            raise ValueError("telemetry: any stands alone")
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
    _matcher: MentionMatcher | None = field(default=None, repr=False, compare=False)

    def match(self, line: str) -> list[str]:
        """The ids of the patterns whose text occurs in `line`, strongest first (the earliest loaded among equals),
        matched exactly as the sweep matches: the line bounded at the scan bound, every pattern whatever its
        telemetry classes. `load_mention_patterns(directory).match(line)` is the whole API a corpus test needs."""
        if not self.compiled:
            return []
        if self._matcher is None:
            self._matcher = MentionMatcher(self.compiled)
        text, past = bound_text(line)
        found = self._matcher.match(text, cut=bool(past))
        order = {"strong": 0, "medium": 1, "weak": 2}
        return [self.patterns[i].id for i in sorted(found, key=lambda i: (order[self.patterns[i].strength], i))]

    def summary(self) -> dict:
        # no directory: a stored summary never depends on where the content is installed
        return {"digest": self.digest, "patterns": len(self.patterns), "files": list(self.files),
                "refused": list(self.refused)}


def mention_dir() -> Path:
    override = os.environ.get("ROMULUS_MENTION_DIR")
    return Path(override) if override else Path(__file__).resolve().parents[3] / "content" / "mentions"


# ---- anchored expressions -------------------------------------------------------------------------------------------
_ATOMS = {_sre.LITERAL, _sre.NOT_LITERAL, _sre.ANY, _sre.IN}
_ALLOWED_AT = {_sre.AT_BEGINNING, _sre.AT_BEGINNING_STRING, _sre.AT_BOUNDARY, _sre.AT_NON_BOUNDARY,
               _sre.AT_END, _sre.AT_END_STRING}
_END_AT = {_sre.AT_END, _sre.AT_END_STRING}
_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT}


def _check(items, multiplies: bool) -> int:
    """The number of wide repeats in a parsed sequence; ValueError on anything outside the subset. `multiplies`: the
    sequence sits inside a repeat that can match more than once."""
    wide = 0
    for op, arg in items:
        if op in _ATOMS:
            continue
        if op == _sre.AT:
            if arg not in _ALLOWED_AT:
                raise ValueError(f"the anchor {str(arg).lower()} is refused")
            continue
        if op == _sre.SUBPATTERN:
            _group, add_flags, del_flags, body = arg
            if add_flags or del_flags:
                raise ValueError("inline flags are refused: case is set by case_sensitive")
            wide += _check(body, multiplies)
        elif op == _sre.BRANCH:
            if multiplies:
                raise ValueError("an alternation inside a repeat is refused (it can backtrack exponentially)")
            wide += max((_check(alt, multiplies) for alt in arg[1]), default=0)
        elif op in _REPEATS:
            _low, high, body = arg
            unbounded = high == _sre.MAXREPEAT
            if multiplies:
                raise ValueError("a repeat inside a repeat is refused (nested quantifiers)")
            wide += _check(body, multiplies or unbounded or int(high) > 1)
            if unbounded or int(high) * max(1, _width(body)) > WIDE_REPEAT:
                wide += 1
        else:
            raise ValueError(f"{str(op).lower()} is refused (back references, lookaround, conditionals, atomic "
                             "groups and possessive repeats are outside the admitted subset)")
    if wide > MAX_WIDE_REPEATS:
        raise ValueError(f"more than {MAX_WIDE_REPEATS} repeats may each match more than {WIDE_REPEAT} characters")
    return wide


def _open_gap(body) -> bool:
    """A repeat body that matches almost any character: `.`, a negated class, or a negated character."""
    if len(body) != 1:
        return False
    op, arg = body[0]
    return op in (_sre.ANY, _sre.NOT_LITERAL) or (op == _sre.IN and any(item[0] == _sre.NEGATE for item in arg))


def _gap_sum(items) -> int:
    """The sum of the open gaps' upper bounds along the widest path (an alternation counts its widest branch)."""
    total = 0
    for op, arg in items:
        if op in _REPEATS:
            _low, high, body = arg
            if _open_gap(list(body)):
                total += int(high)
            else:
                inner = _gap_sum(body)
                total += int(high) * inner if inner else 0
        elif op == _sre.SUBPATTERN:
            total += _gap_sum(arg[3])
        elif op == _sre.BRANCH:
            total += max((_gap_sum(alt) for alt in arg[1]), default=0)
    return total


def _width(items) -> int:
    widest = _sre_parse.SubPattern(_sre_parse.State(), list(items)).getwidth()[1]
    return min(int(widest), MAX_SCAN_CHARS)


def _probe_lines(examples: list[str]) -> list[str]:
    """Lines built to make an expression backtrack: each example cut before its last character and repeated, and
    each example with a run of each of its own characters inserted after each of its first characters."""
    lines = []
    for example in examples[:5]:
        if not example:
            continue
        cut = example[:-1] or example
        lines.append(cut * (MAX_SCAN_CHARS // len(cut) + 1))
        for split in range(1, min(len(example), 24)):
            head, tail = example[:split], example[split:]
            for char in sorted(set(example))[:24]:
                lines.append(head + char * REGEX_WINDOW + tail[:-1])
    return [line[:MAX_SCAN_CHARS] for line in lines]


def probe(regex: re.Pattern, examples: list[str]) -> float:
    """The longest time the expression takes over one hostile probe line, searched over its window: for each line
    the fastest of PROBE_RUNS runs, so a busy machine's pauses are not counted against the expression."""
    worst = 0.0
    for line in _probe_lines(examples):
        fastest = None
        for _ in range(PROBE_RUNS):
            began = time.perf_counter()
            regex.search(line, 0, REGEX_WINDOW)
            took = time.perf_counter() - began
            fastest = took if fastest is None else min(fastest, took)
            if fastest <= PROBE_LIMIT_SECONDS:
                break
        worst = max(worst, fastest)
    return worst


def _ends(items) -> bool:
    """Whether a parsed sequence uses an end anchor anywhere."""
    for op, arg in items:
        if op == _sre.AT and arg in _END_AT:
            return True
        if op == _sre.SUBPATTERN and _ends(arg[3]):
            return True
        if op == _sre.BRANCH and any(_ends(alt) for alt in arg[1]):
            return True
        if op in _REPEATS and _ends(arg[2]):
            return True
    return False


@dataclass(frozen=True)
class Anchored:
    regex: re.Pattern
    prefix: str | None              # None: it starts with ^
    end_anchored: bool
    max_width: int | None           # the longest text it can match; None when unbounded
    lead: str = ""                  # for one that starts with ^: the literal text right after it


def compile_anchored(expression: str, case_sensitive: bool) -> Anchored:
    """The compiled expression, its literal prefix and its shape; ValueError when refused."""
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
    _check(items, False)
    if (gaps := _gap_sum(items)) > MAX_GAP_SUM:
        shown = "unbounded" if gaps >= _sre.MAXREPEAT else str(gaps)
        raise ValueError(f"its open gaps ('.', negated classes) sum to {shown} characters, above {MAX_GAP_SUM}")
    widest = parsed.getwidth()[1]
    shape = {"end_anchored": _ends(items), "max_width": None if widest >= _sre.MAXREPEAT else int(widest)}
    if items and items[0][0] == _sre.AT and items[0][1] in {_sre.AT_BEGINNING, _sre.AT_BEGINNING_STRING}:
        lead = []
        for op, arg in items[1:]:
            if op != _sre.LITERAL:
                break
            lead.append(chr(arg))
        return Anchored(compiled, None, **shape, lead="".join(lead))
    prefix = []
    # a leading word boundary (\b, \B) takes no character: the prefix is the literal text after it
    lead = 0
    while lead < len(items) and items[lead][0] == _sre.AT and items[lead][1] in {_sre.AT_BOUNDARY,
                                                                                  _sre.AT_NON_BOUNDARY}:
        lead += 1
    for op, arg in items[lead:]:
        if op != _sre.LITERAL:
            break
        prefix.append(chr(arg))
    # (a repeated last character, as in abcd+, is parsed into the repeat: it is never part of the prefix)
    if len(prefix) < MIN_PREFIX_CHARS:
        raise ValueError(f"an anchored expression must start with ^ or with a literal prefix of at least "
                         f"{MIN_PREFIX_CHARS} characters")
    return Anchored(compiled, "".join(prefix), **shape)


def compile_pattern(index: int, pattern: MentionPattern) -> CompiledPattern:
    if pattern.match.anchored is not None:
        built = compile_anchored(pattern.match.anchored, pattern.case_sensitive)
        took = probe(built.regex, [*pattern.examples.positive, *pattern.examples.negative])
        if took > PROBE_LIMIT_SECONDS:
            raise ValueError(f"the expression took {took * 1000:.0f} ms on one hostile probe line (the limit is "
                             f"{PROBE_LIMIT_SECONDS * 1000:.0f} ms): it can backtrack too far")
        return CompiledPattern(index=index, id=pattern.id, case_sensitive=pattern.case_sensitive, regex=built.regex,
                               prefix=built.prefix, end_anchored=built.end_anchored, max_width=built.max_width,
                               lead=built.lead)
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
        except MentionPatternError as error:
            out.refused.append({"name": path.name, "error": str(error)[:800]})
            continue
        except OSError as error:
            out.refused.append({"name": path.name, "error": f"{path.name}: could not be read ({type(error).__name__})"})
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
