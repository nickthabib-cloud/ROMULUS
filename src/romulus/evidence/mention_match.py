"""The mention matcher: every curated pattern whose text occurs in a line.

Literals are found in time linear in the line:

- a gate regex finds whether any literal occurs. Each literal is anchored at its rarest character (by a fixed table of
  how common characters are in log text), so the regex engine skips at C speed over every position whose character
  anchors no literal, and checks the literal's other characters only at anchor positions;
- on a line the gate passes, an Aho-Corasick automaton (pure Python) lists every literal occurrence, starting where
  the first possible one could begin.

An anchored expression runs only where its literal prefix occurs (at most `MAX_PREFIX_TRIES` places per line, each over
at most `REGEX_WINDOW` characters), or at the line's start for one that begins with `^`. The pattern loader admits only
a linear-time subset of expressions whose backtracking is bounded (`content.mention_patterns`).

A line is scanned up to `MAX_SCAN_CHARS` characters; the rest is counted as not scanned.
"""
from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass

# the characters of a line the matcher reads; the rest of a longer line is counted as not scanned
MAX_SCAN_CHARS = 8_192
# an anchored expression sees at most this many characters from where it is tried
REGEX_WINDOW = 512
# and is tried at most at this many occurrences of its literal prefix in one line
MAX_PREFIX_TRIES = 4
# the backtracking bound an anchored expression may have: the product, over its repeats and alternations, of how many
# ways each can match (an unbounded repeat counts REGEX_WINDOW ways); two unbounded repeats fit, three do not
BACKTRACK_BOUND = REGEX_WINDOW * REGEX_WINDOW

# Characters from most to least common in log text: a literal is anchored at the character of it latest in this order
# (one not listed counts as rarest). Digits, separators and common letters come first, so the gate's anchor characters
# are mostly rare punctuation and rare letters.
_COMMON = " eatoinsrlhdcu0123456789.:/-=_,mpfgybw()[]\"'vkxjqz"
_RANK = {char: index for index, char in enumerate(_COMMON)}


def _rarity(char: str) -> int:
    return _RANK.get(char, len(_COMMON))


def bound_text(text: str) -> tuple[str, int]:
    """The part of a line the matcher reads, and how many characters past it were not scanned."""
    if len(text) <= MAX_SCAN_CHARS:
        return text, 0
    return text[:MAX_SCAN_CHARS], len(text) - MAX_SCAN_CHARS


def normalized_line(text: str) -> str:
    """The line a group of identical mentions shares: its whitespace runs collapsed, its ends stripped."""
    return " ".join(text.split())


def line_digest(text: str) -> str:
    return hashlib.sha256(normalized_line(text).encode("utf-8", errors="replace")).hexdigest()[:32]


class LiteralSet:
    """Every occurrence of a fixed set of literals in a text (see the module docstring)."""

    def __init__(self, literals: Sequence[str]):
        self.literals = list(literals)
        if any(not literal for literal in self.literals):
            raise ValueError("a literal must not be empty")
        self.longest = max((len(literal) for literal in self.literals), default=0)
        self.gate = self._gate() if self.literals else None
        self._automaton()

    def _gate(self) -> re.Pattern:
        groups: dict[str, list[tuple[str, str]]] = {}
        for literal in self.literals:
            anchor = max(range(len(literal)), key=lambda i: (_rarity(literal[i]), -i))
            groups.setdefault(literal[anchor], []).append((literal[:anchor], literal[anchor + 1:]))
        branches = []
        for char, parts in sorted(groups.items()):
            alternatives = []
            for before, after in sorted(set(parts), key=lambda part: (-len(part[0]) - len(part[1]), part)):
                # the regex stands on the anchor character; the characters before it are checked looking back
                behind = f"(?<={re.escape(before + char)})" if before else ""
                alternatives.append(behind + re.escape(after))
            branches.append(re.escape(char) + "(?:" + "|".join(alternatives) + ")")
        return re.compile("|".join(branches), re.DOTALL)

    def _automaton(self) -> None:
        goto: list[dict[str, int]] = [{}]
        out: list[tuple[int, ...]] = [()]
        for index, literal in enumerate(self.literals):
            state = 0
            for char in literal:
                nxt = goto[state].get(char)
                if nxt is None:
                    goto.append({})
                    out.append(())
                    nxt = goto[state][char] = len(goto) - 1
                state = nxt
            out[state] = (*out[state], index)
        fail = [0] * len(goto)
        queue = deque(goto[0].values())
        while queue:
            state = queue.popleft()
            for char, nxt in goto[state].items():
                queue.append(nxt)
                back = fail[state]
                while back and char not in goto[back]:
                    back = fail[back]
                target = goto[back].get(char, 0)
                fail[nxt] = target if target != nxt else 0
                out[nxt] = out[nxt] + out[fail[nxt]]
        self._goto, self._fail, self._out = goto, fail, out

    def find(self, text: str, positions: int = MAX_PREFIX_TRIES) -> dict[int, list[int]]:
        """{literal index: its first `positions` start offsets in `text`} for every literal that occurs."""
        if self.gate is None:
            return {}
        first = self.gate.search(text)
        if first is None:
            return {}
        goto, fail, out = self._goto, self._fail, self._out
        found: dict[int, list[int]] = {}
        state = 0
        # no literal occurrence can start before the first anchor match less the longest literal
        start = max(0, first.start() - self.longest)
        for offset in range(start, len(text)):
            char = text[offset]
            while state and char not in goto[state]:
                state = fail[state]
            state = goto[state].get(char, 0)
            for index in out[state]:
                starts = found.setdefault(index, [])
                if len(starts) < positions:
                    starts.append(offset - len(self.literals[index]) + 1)
        return found


@dataclass(frozen=True)
class CompiledPattern:
    """What the matcher needs of one pattern (built by `content.mention_patterns`)."""
    index: int
    id: str
    case_sensitive: bool
    literals: tuple[str, ...] = ()
    regex: re.Pattern | None = None
    prefix: str | None = None             # the literal an anchored expression starts with (None: it starts with ^)


class MentionMatcher:
    """The patterns whose text occurs in a line. `match` takes a line already bounded by `bound_text`."""

    def __init__(self, patterns: Sequence[CompiledPattern]):
        self.patterns = list(patterns)
        self._views = []
        for sensitive in (True, False):
            literals: dict[str, int] = {}
            owners: list[list[tuple[int, bool]]] = []
            at_start: list[CompiledPattern] = []
            for pattern in self.patterns:
                if pattern.case_sensitive != sensitive:
                    continue
                if pattern.regex is not None and pattern.prefix is None:
                    at_start.append(pattern)
                    continue
                keys = [pattern.prefix] if pattern.regex is not None else list(pattern.literals)
                for key in keys:
                    key = key if sensitive else key.lower()
                    slot = literals.setdefault(key, len(literals))
                    if slot == len(owners):
                        owners.append([])
                    owners[slot].append((pattern.index, pattern.regex is not None))
            if literals or at_start:
                self._views.append((sensitive, LiteralSet(list(literals)), owners, at_start))
        self._by_index = {pattern.index: pattern for pattern in self.patterns}

    def match(self, text: str) -> list[int]:
        matched: set[int] = set()
        lowered = None
        for sensitive, literals, owners, at_start in self._views:
            if sensitive:
                view = text
            else:
                view = lowered = text.lower() if lowered is None else lowered
            for slot, starts in literals.find(view).items():
                for index, gated in owners[slot]:
                    if index in matched:
                        continue
                    if not gated:
                        matched.add(index)
                        continue
                    regex = self._by_index[index].regex
                    if any(regex.match(view, start, start + REGEX_WINDOW) for start in starts[:MAX_PREFIX_TRIES]):
                        matched.add(index)
            for pattern in at_start:
                if pattern.index not in matched and pattern.regex.match(view, 0, REGEX_WINDOW):
                    matched.add(pattern.index)
        return sorted(matched)
