"""The AI agent's own source queries: validated, wrapped in the hunt's scope, and bounded.

The agent may write an Elasticsearch/OpenSearch Query DSL query (with optional aggregations, sort, size and the
fields it wants shown) for one of the hunt's indices, or an Arkime expression for one Arkime viewer. Nothing it
writes is passed through. This module is the boundary:

- Allowlists, never a denylist alone. A query position takes only the clause types in QUERY_CLAUSES, each with the
  keys its entry allows (a field leaf's options too); an aggregation takes only the types in AGGREGATIONS, each with
  its own keys. Every number a cap applies to must be a JSON integer (never a string a cluster would coerce, a float
  or a boolean). Field names and labels (aggregation, filter and composite-source names) must match a strict name
  pattern; every structural and option key is also checked against FORBIDDEN_KEYS.
- Lucene's own safety limits stay in force: no query may raise the regex determinization limit, an expansion count
  is capped, a rewrite is constant-score only, and a regular expression, wildcard or regex-bearing query string is
  at most MAX_REGEX_CHARS long. Their cost is paid while the query is built on each node, before any timeout. An
  Arkime expression holds at most MAX_ARKIME_REGEXES regular expressions of at most MAX_ARKIME_REGEX_CHARS each.
- Nothing that runs code, reads another index or reads outside the query is accepted anywhere: scripts of every
  kind, runtime mappings, percolation, wrapped (encoded) queries, terms lookups, more-like-this, indexed shapes,
  inference clauses, global/children/parent aggregations, significant-terms background counts and empty-bucket
  term lists (`min_doc_count: 0`).
- The body is built here, from validated parts only: the model's query becomes one `bool.filter` clause beside the
  hunt window's range on the source's time field, so it can only narrow what the source holds in the window. Size,
  timeout, terminate_after and track_total_hits are fixed caps, and aggregations are bounded by their own sizes and
  by the product of bucket counts along any path.
- A response is bounded before it is kept: at most MAX_BUCKETS_SHOWN buckets of any aggregation, each cut list
  counted.

The endpoint and method are the existing client's (`POST /<target>/_search` through its request allowlist); this
module never chooses a path.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

MAX_QUERY_BYTES = 16_384
MAX_QUERY_DEPTH = 24
MAX_QUERY_NODES = 2_000
MAX_TEXT_CHARS = 4_096
MAX_KEY_CHARS = 256
MAX_QUERY_HITS = 100
MAX_AGGREGATIONS = 10
MAX_AGGREGATION_DEPTH = 3
MAX_TERMS_SIZE = 100
MAX_SHARD_SIZE = 500
MAX_TOP_HITS = 10
# the most documents all top_hits aggregations together can return: a top_hits size times the buckets above it
MAX_TOP_HIT_DOCUMENTS = 100
MAX_LIST_ITEMS = 20            # ranges, filters, percents, multi_terms terms, composite sources
MAX_IDS = 1_000
MAX_DATE_BUCKETS = 500
MAX_TOTAL_BUCKETS = 10_000
MAX_CARDINALITY_PRECISION = 40_000
MAX_SORT_KEYS = 3
MAX_SHOWN_FIELDS = 50
QUERY_TIMEOUT = "10s"
TERMINATE_AFTER = 1_000_000
TRACK_TOTAL_HITS = 10_000
MAX_EXPRESSION_CHARS = 2_000
# A regular expression, wildcard pattern or regex-bearing query string: its automaton is built on each data node while
# the query is parsed, before the search timeout applies.
MAX_REGEX_CHARS = 1_000
# The most terms a fuzzy, prefix-phrase or fuzzy match may expand to (Elasticsearch's default is 50).
MAX_EXPANSIONS = 100
# The rewrites a multi-term query may use: constant-score forms, which never build a scoring clause per term.
CONSTANT_REWRITES = frozenset({"constant_score", "constant_score_blended", "constant_score_boolean"})
MAX_ARKIME_REGEXES = 2
MAX_ARKIME_REGEX_CHARS = 200
MAX_BUCKETS_SHOWN = 100

# Refused at any depth, whatever position they are in: code, other indices, encoded bodies, search features that are
# not a read of this source's records in the window.
FORBIDDEN_KEYS = frozenset({
    "script", "scripts", "_script", "script_score", "script_fields", "scripted_metric", "bucket_script",
    "bucket_selector", "bucket_sort", "script_heuristic", "minimum_should_match_script", "function_score",
    "runtime_mappings", "stored_fields", "percolate", "wrapper", "more_like_this", "mlt", "indexed_shape",
    "template", "search_template", "stored_script", "params", "lang", "pipeline", "rescore", "knn", "semantic",
    "text_expansion", "sparse_vector", "weighted_tokens", "rule", "pinned", "pit", "search_after", "indices_boost",
    "suggest", "profile", "explain", "collapse", "post_filter", "highlight", "global", "children", "parent",
    "has_child", "has_parent", "significant_terms", "significant_text", "background_filter", "geo_shape",
    "shape", "inference",
})

_SCALAR = (str, int, float, bool, type(None))
_NAME = re.compile(r"^[A-Za-z0-9_@.\-]{1,256}$")              # a field name a sort or aggregation reads
_PATTERN = re.compile(r"^[A-Za-z0-9_@.*\-]{1,256}$")          # a field name or pattern shown or matched
_AGG_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_INTERVAL = re.compile(r"^([1-9][0-9]{0,5})(ms|s|m|h|d)$")
_UNIT_SECONDS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86_400}
_CALENDAR_SECONDS = {"minute": 60, "1m": 60, "hour": 3600, "1h": 3600, "day": 86_400, "1d": 86_400,
                     "week": 604_800, "1w": 604_800, "month": 2_419_200, "1M": 2_419_200, "quarter": 7_776_000,
                     "1q": 7_776_000, "year": 31_536_000, "1y": 31_536_000}


class QueryRefused(ValueError):
    """Why a model-written query is not sent: `path` is where in the arguments, `code` a stable reason."""

    def __init__(self, path: str, code: str, message: str):
        super().__init__(message)
        self.path, self.code = path, code


def _refuse(path: str, code: str, message: str):
    raise QueryRefused(path, code, message)


# ---- generic shape -----------------------------------------------------------------------------------------------

def _shape(value: Any, path: str) -> None:
    """Depth, node count, key and text length, at every level. Iterative, so a value nested past any depth is refused
    here and never reaches a recursive step (serialization, the structural checks)."""
    nodes = 0
    stack = [(value, path, 0)]
    while stack:
        node, where, depth = stack.pop()
        nodes += 1
        if nodes > MAX_QUERY_NODES:
            _refuse(where, "too_large", f"the query has more than {MAX_QUERY_NODES} parts")
        if depth > MAX_QUERY_DEPTH:
            _refuse(where, "too_deep", f"the query nests deeper than {MAX_QUERY_DEPTH} levels")
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str) or not key or len(key) > MAX_KEY_CHARS:
                    _refuse(where, "bad_key", f"a key must be a string of 1 to {MAX_KEY_CHARS} characters")
                stack.append((child, f"{where}.{key}", depth + 1))
        elif isinstance(node, list):
            stack.extend((child, f"{where}[{index}]", depth + 1) for index, child in enumerate(node))
        elif isinstance(node, str):
            if len(node) > MAX_TEXT_CHARS:
                _refuse(where, "text_too_long", f"a text value is longer than {MAX_TEXT_CHARS} characters")
            if any(ord(ch) < 0x20 and ch not in "\t\n\r" for ch in node):
                _refuse(where, "control_character", "a text value holds a control character")
        elif not isinstance(node, _SCALAR):
            _refuse(where, "bad_value", "values must be JSON objects, arrays, strings, numbers, booleans or null")


def _forbid(key: str, path: str) -> None:
    """A structural or option key is never one of FORBIDDEN_KEYS (field names and labels are checked by pattern)."""
    if key in FORBIDDEN_KEYS or key.lower() in FORBIDDEN_KEYS:
        _refuse(f"{path}.{key}", "forbidden_construct",
                f"{key} is not accepted: it runs code, reads outside this source and window, or is not a read of "
                "this source's records")


def _field_name(name: Any, path: str) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        _refuse(path, "bad_field", "a field name is 1 to 256 letters, digits, _, @, . or -")
    return name


def _int(value: Any, path: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _refuse(path, "not_an_integer", "this number must be a JSON integer (not a string, float or boolean)")
    if not low <= value <= high:
        _refuse(path, "out_of_bounds", f"this number must be from {low} to {high}")
    return value


def _one(node: Any, path: str, what: str) -> tuple[str, Any]:
    if not isinstance(node, dict) or len(node) != 1:
        _refuse(path, "bad_shape", f"{what} must be an object with exactly one key")
    (key, body), = node.items()
    return key, body


def _keys(body: Any, path: str, allowed: frozenset[str], what: str) -> dict:
    if not isinstance(body, dict):
        _refuse(path, "bad_shape", f"{what} must be an object")
    for key in body:
        _forbid(key, path)
    extra = sorted(set(body) - allowed)
    if extra:
        _refuse(f"{path}.{extra[0]}", "key_not_allowed",
                f"{what} takes only {', '.join(sorted(allowed))}; {extra[0]} is not accepted")
    return body


# ---- query clauses -----------------------------------------------------------------------------------------------

_LEAF_OPTIONS = frozenset({"boost", "_name"})
# The leaf clauses a query position takes. Each is `{clause: {field: value-or-options}}` or, for the
# multi-field and whole-query clauses, `{clause: {options}}`; their keys are field names or the options listed.
_FIELD_LEAVES = frozenset({"term", "terms", "prefix", "wildcard", "regexp", "fuzzy", "range", "match",
                           "match_phrase", "match_phrase_prefix", "match_bool_prefix"})
_OPTION_LEAVES = {
    "exists": frozenset({"field", *_LEAF_OPTIONS}),
    "ids": frozenset({"values", *_LEAF_OPTIONS}),
    "match_all": _LEAF_OPTIONS,
    "match_none": _LEAF_OPTIONS,
    "multi_match": frozenset({"query", "fields", "type", "operator", "minimum_should_match", "analyzer", "lenient",
                              "fuzziness", "prefix_length", "max_expansions", "tie_breaker", "zero_terms_query",
                              "auto_generate_synonyms_phrase_query", "slop", *_LEAF_OPTIONS}),
    "combined_fields": frozenset({"query", "fields", "operator", "minimum_should_match", "zero_terms_query",
                                  "auto_generate_synonyms_phrase_query", *_LEAF_OPTIONS}),
    "query_string": frozenset({"query", "default_field", "fields", "default_operator", "analyzer",
                               "allow_leading_wildcard", "analyze_wildcard", "lenient", "minimum_should_match",
                               "phrase_slop", "fuzziness", "time_zone", "type", "quote_field_suffix",
                               "auto_generate_synonyms_phrase_query", "rewrite",
                               "fuzzy_max_expansions", "fuzzy_prefix_length", "fuzzy_transpositions",
                               "enable_position_increments", "tie_breaker", *_LEAF_OPTIONS}),
    "simple_query_string": frozenset({"query", "fields", "default_operator", "analyzer", "flags",
                                      "analyze_wildcard", "lenient", "minimum_should_match", "quote_field_suffix",
                                      "auto_generate_synonyms_phrase_query", "fuzzy_max_expansions",
                                      "fuzzy_prefix_length", "fuzzy_transpositions", *_LEAF_OPTIONS}),
}
_COMPOUND = {
    "bool": {"queries": frozenset({"must", "filter", "should", "must_not"}),
             "scalars": frozenset({"minimum_should_match", *_LEAF_OPTIONS})},
    "constant_score": {"query": frozenset({"filter"}), "scalars": _LEAF_OPTIONS},
    "dis_max": {"list": frozenset({"queries"}), "scalars": frozenset({"tie_breaker", *_LEAF_OPTIONS})},
    "boosting": {"query": frozenset({"positive", "negative"}), "scalars": frozenset({"negative_boost", "boost"})},
    "nested": {"query": frozenset({"query"}), "scalars": frozenset({"path", "score_mode", "ignore_unmapped",
                                                                    *_LEAF_OPTIONS})},
}
QUERY_CLAUSES = frozenset({*_FIELD_LEAVES, *_OPTION_LEAVES, *_COMPOUND})
# The options each field leaf takes, as {clause: {field: {options}}}. `max_determinized_states` is never accepted (the
# cluster's own limit applies), and the expansion and rewrite options are bounded (_option_limits).
_FIELD_LEAF_OPTIONS = {
    "term": frozenset({"value", "case_insensitive", *_LEAF_OPTIONS}),
    "prefix": frozenset({"value", "rewrite", "case_insensitive", *_LEAF_OPTIONS}),
    "wildcard": frozenset({"value", "wildcard", "rewrite", "case_insensitive", *_LEAF_OPTIONS}),
    "regexp": frozenset({"value", "flags", "case_insensitive", "rewrite", *_LEAF_OPTIONS}),
    "fuzzy": frozenset({"value", "fuzziness", "max_expansions", "prefix_length", "transpositions", "rewrite",
                        *_LEAF_OPTIONS}),
    "range": frozenset({"gt", "gte", "lt", "lte", "format", "relation", "time_zone", *_LEAF_OPTIONS}),
    "match": frozenset({"query", "analyzer", "auto_generate_synonyms_phrase_query", "fuzziness", "max_expansions",
                        "prefix_length", "fuzzy_transpositions", "fuzzy_rewrite", "lenient", "operator",
                        "minimum_should_match", "zero_terms_query", *_LEAF_OPTIONS}),
    "match_phrase": frozenset({"query", "analyzer", "slop", "zero_terms_query", *_LEAF_OPTIONS}),
    "match_phrase_prefix": frozenset({"query", "analyzer", "max_expansions", "slop", "zero_terms_query",
                                      *_LEAF_OPTIONS}),
    "match_bool_prefix": frozenset({"query", "analyzer", "operator", "minimum_should_match", "fuzziness",
                                    "prefix_length", "max_expansions", "fuzzy_transpositions", "fuzzy_rewrite",
                                    *_LEAF_OPTIONS}),
}
# The leaves whose value is compiled to an automaton: its pattern is bounded.
_PATTERN_LEAVES = frozenset({"regexp", "wildcard"})
_PATTERN_VALUE_KEYS = ("value", "wildcard")


def _option_limits(body: dict, path: str) -> None:
    """The bounded options any clause may carry: expansion counts and constant-score rewrites."""
    for key in ("max_expansions", "fuzzy_max_expansions"):
        if key in body:
            _int(body[key], f"{path}.{key}", 1, MAX_EXPANSIONS)
    for key in ("rewrite", "fuzzy_rewrite"):
        if key in body and body[key] not in CONSTANT_REWRITES:
            _refuse(f"{path}.{key}", "rewrite_not_allowed",
                    f"{key} takes a constant-score form only: {', '.join(sorted(CONSTANT_REWRITES))}")


def _pattern_text(value: Any, path: str, what: str) -> None:
    if isinstance(value, str) and len(value) > MAX_REGEX_CHARS:
        _refuse(path, "pattern_too_long", f"{what} is longer than {MAX_REGEX_CHARS} characters")


def _scalars(body: dict, keys, path: str) -> None:
    for key in keys:
        if key in body and not isinstance(body[key], _SCALAR):
            _refuse(f"{path}.{key}", "bad_shape", f"{key} takes a single value")


def _query(node: Any, path: str) -> None:
    """One query position: a clause from QUERY_CLAUSES, recursively."""
    clause, body = _one(node, path, "a query")
    where = f"{path}.{clause}"
    _forbid(clause, path)
    if clause not in QUERY_CLAUSES:
        _refuse(where, "clause_not_allowed",
                f"{clause} is not an accepted query clause; accepted: {', '.join(sorted(QUERY_CLAUSES))}")
    if clause in _COMPOUND:
        rule = _COMPOUND[clause]
        allowed = frozenset().union(*(rule.get(kind, frozenset()) for kind in ("queries", "query", "list",
                                                                                 "scalars")))
        body = _keys(body, where, allowed, clause)
        _scalars(body, rule["scalars"], where)
        for key in rule.get("query", ()):
            if key in body:
                _query(body[key], f"{where}.{key}")
        for key in rule.get("queries", ()):
            if key in body:
                items = body[key] if isinstance(body[key], list) else [body[key]]
                if len(items) > MAX_QUERY_NODES:
                    _refuse(f"{where}.{key}", "too_large", "too many clauses")
                for index, item in enumerate(items):
                    _query(item, f"{where}.{key}[{index}]")
        for key in rule.get("list", ()):
            if key in body:
                if not isinstance(body[key], list) or not body[key]:
                    _refuse(f"{where}.{key}", "bad_shape", f"{key} takes a non-empty list of queries")
                for index, item in enumerate(body[key]):
                    _query(item, f"{where}.{key}[{index}]")
        return
    if clause in _OPTION_LEAVES:
        body = _keys(body, where, _OPTION_LEAVES[clause], clause)
        if clause == "ids":
            values = body.get("values")
            if not isinstance(values, list) or len(values) > MAX_IDS or not all(isinstance(v, str) for v in values):
                _refuse(f"{where}.values", "bad_shape", f"ids takes a list of at most {MAX_IDS} id strings")
        if clause == "exists":
            _field_name(body.get("field"), f"{where}.field")
        if clause == "query_string" and "default_field" in body:
            _field_name(str(body["default_field"]).split("^", 1)[0].replace("*", "x"), f"{where}.default_field")
        if clause in ("query_string", "simple_query_string") and "/" in str(body.get("query", "")):
            # a query string's /regex/ is compiled like a regexp query
            _pattern_text(body.get("query"), f"{where}.query", "a query string holding a regular expression")
        _option_limits(body, where)
        for key in ("fields",):
            if key in body and (not isinstance(body[key], list)
                                or not all(isinstance(v, str) and _PATTERN.fullmatch(v.split("^", 1)[0])
                                           for v in body[key])):
                _refuse(f"{where}.{key}", "bad_shape", "fields takes a list of field names or patterns")
        _scalars(body, [key for key in body if key != "fields" and not (clause == "ids" and key == "values")], where)
        return
    # a field leaf: {clause: {field: value or {options}}}
    if not isinstance(body, dict) or not body:
        _refuse(where, "bad_shape", f"{clause} takes an object naming a field")
    fields = [key for key in body if key not in _LEAF_OPTIONS]
    if len(fields) != 1:
        _refuse(where, "bad_shape", f"{clause} names exactly one field")
    field = _field_name(fields[0], f"{where}.{fields[0]}")
    value = body[field]
    if clause == "terms":
        # a list of values only: an object here is a terms lookup, which reads another index
        if not isinstance(value, list) or len(value) > MAX_IDS or not all(isinstance(v, _SCALAR) for v in value):
            _refuse(f"{where}.{field}", "terms_lookup",
                    f"terms takes a list of at most {MAX_IDS} values; a lookup from another index is not accepted")
    elif isinstance(value, dict):
        options = _keys(value, f"{where}.{field}", _FIELD_LEAF_OPTIONS[clause], f"{clause} on a field")
        _scalars(options, options.keys(), f"{where}.{field}")
        _option_limits(options, f"{where}.{field}")
        if clause in _PATTERN_LEAVES:
            for key in _PATTERN_VALUE_KEYS:
                _pattern_text(options.get(key), f"{where}.{field}.{key}", f"a {clause} pattern")
    elif not isinstance(value, _SCALAR):
        _refuse(f"{where}.{field}", "bad_shape", f"{clause} takes a value or an object of options")
    elif clause in _PATTERN_LEAVES:
        _pattern_text(value, f"{where}.{field}", f"a {clause} pattern")
    for key in body:
        if key != field:
            _forbid(key, where)
    _scalars(body, _LEAF_OPTIONS, where)


# ---- aggregations ------------------------------------------------------------------------------------------------

_METRIC_KEYS = frozenset({"field", "missing", "format"})
AGGREGATIONS = {
    # bucket aggregations
    "terms": frozenset({"field", "size", "shard_size", "min_doc_count", "shard_min_doc_count", "order", "missing",
                        "include", "exclude", "show_term_doc_count_error", "execution_hint", "value_type"}),
    "multi_terms": frozenset({"terms", "size", "shard_size", "min_doc_count", "shard_min_doc_count", "order",
                              "show_term_doc_count_error"}),
    "composite": frozenset({"size", "sources", "after"}),
    "filter": None,                                   # the body is a query
    "filters": frozenset({"filters", "other_bucket", "other_bucket_key"}),
    "range": frozenset({"field", "ranges", "keyed", "missing", "format"}),
    "date_range": frozenset({"field", "ranges", "keyed", "missing", "format", "time_zone"}),
    "ip_range": frozenset({"field", "ranges", "keyed"}),
    "date_histogram": frozenset({"field", "fixed_interval", "calendar_interval", "min_doc_count", "time_zone",
                                 "format", "order", "keyed", "offset", "missing"}),
    "missing": frozenset({"field"}),
    # metric aggregations
    "cardinality": frozenset({*_METRIC_KEYS, "precision_threshold"}),
    "value_count": _METRIC_KEYS, "min": _METRIC_KEYS, "max": _METRIC_KEYS, "avg": _METRIC_KEYS,
    "sum": _METRIC_KEYS, "stats": _METRIC_KEYS, "extended_stats": frozenset({*_METRIC_KEYS, "sigma"}),
    "percentiles": frozenset({*_METRIC_KEYS, "percents", "keyed"}),
    "top_hits": frozenset({"size", "sort", "_source"}),
}
_METRICS = frozenset({"cardinality", "value_count", "min", "max", "avg", "sum", "stats", "extended_stats",
                      "percentiles", "top_hits"})
_COMPOSITE_SOURCES = {"terms": frozenset({"field", "missing_bucket", "order"}),
                      "date_histogram": frozenset({"field", "fixed_interval", "calendar_interval", "time_zone",
                                                   "format", "order", "missing_bucket", "offset"})}


def _field(body: dict, path: str, required: bool = True) -> None:
    value = body.get("field")
    if value is None and not required:
        return
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        _refuse(f"{path}.field", "bad_field", "field takes one field name")


def _interval_seconds(body: dict, path: str) -> float:
    fixed, calendar = body.get("fixed_interval"), body.get("calendar_interval")
    if (fixed is None) == (calendar is None):
        _refuse(path, "bad_shape", "a date histogram takes exactly one of fixed_interval or calendar_interval")
    if fixed is not None:
        match = _INTERVAL.fullmatch(fixed) if isinstance(fixed, str) else None
        if match is None:
            _refuse(f"{path}.fixed_interval", "bad_interval", "fixed_interval is a whole number and ms, s, m, h or d")
        return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]
    if not isinstance(calendar, str) or calendar not in _CALENDAR_SECONDS:
        _refuse(f"{path}.calendar_interval", "bad_interval",
                "calendar_interval is one of " + ", ".join(sorted(_CALENDAR_SECONDS)))
    return _CALENDAR_SECONDS[calendar]


def _min_doc_count(body: dict, path: str) -> None:
    # 0 lists terms of records outside the query and window, from the whole index
    if "min_doc_count" in body:
        _int(body["min_doc_count"], f"{path}.min_doc_count", 1, 1_000_000_000)


def _ranges(body: dict, path: str) -> int:
    ranges = body.get("ranges")
    if not isinstance(ranges, list) or not 0 < len(ranges) <= MAX_LIST_ITEMS:
        _refuse(f"{path}.ranges", "bad_shape", f"ranges takes 1 to {MAX_LIST_ITEMS} ranges")
    for index, item in enumerate(ranges):
        _keys(item, f"{path}.ranges[{index}]", frozenset({"from", "to", "key", "mask"}), "a range")
        _scalars(item, item.keys(), f"{path}.ranges[{index}]")
    return len(ranges)


def _sort(value: Any, path: str) -> None:
    """A sort: a list of at most MAX_SORT_KEYS field names (or _score, _doc), each alone, with a direction, or with
    order, missing, unmapped_type or mode."""
    items = value if isinstance(value, list) else [value]
    if not items or len(items) > MAX_SORT_KEYS:
        _refuse(path, "bad_shape", f"sort takes 1 to {MAX_SORT_KEYS} keys")
    for index, item in enumerate(items):
        where = f"{path}[{index}]"
        if isinstance(item, str):
            name, options = item, None
        else:
            name, options = _one(item, where, "a sort key")
        if not _NAME.fullmatch(name) or (name.startswith("_") and name not in ("_score", "_doc")):
            _refuse(where, "bad_field", "a sort key is a field name, _score or _doc")
        if isinstance(options, str):
            if options not in ("asc", "desc"):
                _refuse(where, "bad_shape", "a sort direction is asc or desc")
        elif options is not None:
            options = _keys(options, where, frozenset({"order", "missing", "unmapped_type", "mode"}), "a sort key")
            _scalars(options, options.keys(), where)
            if options.get("order", "asc") not in ("asc", "desc"):
                _refuse(f"{where}.order", "bad_shape", "order is asc or desc")


def _aggs(node: Any, path: str, depth: int, counter: list[int], window_seconds: float,
          above: int = 1, documents: list[int] | None = None) -> int:
    """Aggregations at one level; returns the most buckets any one of them can produce along its deepest path.
    `above` is the product of the bucket counts of the aggregations this level sits under; `documents` counts the
    documents the top_hits aggregations can return in all (each one's size times `above`)."""
    documents = documents if documents is not None else [0]
    if not isinstance(node, dict) or not node:
        _refuse(path, "bad_shape", "aggregations take an object of named aggregations")
    if depth > MAX_AGGREGATION_DEPTH:
        _refuse(path, "too_deep", f"aggregations nest at most {MAX_AGGREGATION_DEPTH} levels")
    worst = 1
    for name, agg in node.items():
        where = f"{path}.{name}"
        if not _AGG_NAME.fullmatch(name):
            _refuse(where, "bad_name", "an aggregation name is 1 to 64 letters, digits, _ or -")
        counter[0] += 1
        if counter[0] > MAX_AGGREGATIONS:
            _refuse(where, "too_many_aggregations", f"at most {MAX_AGGREGATIONS} aggregations")
        if not isinstance(agg, dict):
            _refuse(where, "bad_shape", "an aggregation is an object")
        subs = [key for key in agg if key in ("aggs", "aggregations")]
        kinds = [key for key in agg if key not in ("aggs", "aggregations")]
        if len(kinds) != 1 or len(subs) > 1:
            _refuse(where, "bad_shape", "an aggregation names one type, with at most one aggs object")
        kind = kinds[0]
        _forbid(kind, where)
        if kind not in AGGREGATIONS:
            _refuse(f"{where}.{kind}", "aggregation_not_allowed",
                    f"{kind} is not an accepted aggregation; accepted: {', '.join(sorted(AGGREGATIONS))}")
        body = agg[kind]
        at = f"{where}.{kind}"
        if kind == "filter":
            _query(body, at)
            buckets = 1
        else:
            body = _keys(body, at, AGGREGATIONS[kind], kind)
            buckets = _agg_body(kind, body, at, window_seconds)
            if kind == "top_hits":
                documents[0] += above * buckets
                if documents[0] > MAX_TOP_HIT_DOCUMENTS:
                    _refuse(at, "too_many_documents",
                            f"top_hits can return {documents[0]} documents here; at most {MAX_TOP_HIT_DOCUMENTS} in all")
                buckets = 1
        if subs:
            if kind in _METRICS:
                _refuse(f"{where}.{subs[0]}", "bad_shape", f"{kind} takes no sub-aggregations")
            buckets *= _aggs(agg[subs[0]], f"{where}.{subs[0]}", depth + 1, counter, window_seconds,
                             above * buckets, documents)
        if buckets > MAX_TOTAL_BUCKETS:
            _refuse(where, "too_many_buckets",
                    f"these aggregations can produce {buckets} buckets; at most {MAX_TOTAL_BUCKETS}")
        worst = max(worst, buckets)
    return worst


def _agg_body(kind: str, body: dict, at: str, window_seconds: float) -> int:
    """Check one aggregation's options; return how many buckets it can produce (1 for a metric)."""
    if kind in ("terms", "multi_terms"):
        size = _int(body.get("size", 10), f"{at}.size", 1, MAX_TERMS_SIZE)
        if "shard_size" in body:
            _int(body["shard_size"], f"{at}.shard_size", 1, MAX_SHARD_SIZE)
        _min_doc_count(body, at)
        if kind == "terms":
            _field(body, at)
            for key in ("include", "exclude"):
                value = body.get(key)
                if value is not None and not (isinstance(value, str) or (
                        isinstance(value, list) and len(value) <= MAX_IDS
                        and all(isinstance(v, (str, int, float)) for v in value))):
                    _refuse(f"{at}.{key}", "bad_shape", f"{key} takes a pattern or a list of values")
                # a string include or exclude is a regular expression
                _pattern_text(value, f"{at}.{key}", f"a terms {key} pattern")
        else:
            terms = body.get("terms")
            if not isinstance(terms, list) or not 1 < len(terms) <= 4:
                _refuse(f"{at}.terms", "bad_shape", "multi_terms takes 2 to 4 terms")
            for index, item in enumerate(terms):
                item = _keys(item, f"{at}.terms[{index}]", frozenset({"field", "missing"}), "a term source")
                _field(item, f"{at}.terms[{index}]")
        _order(body, at)
        return size
    if kind == "composite":
        size = _int(body.get("size", 10), f"{at}.size", 1, MAX_TERMS_SIZE)
        sources = body.get("sources")
        if not isinstance(sources, list) or not 0 < len(sources) <= 4:
            _refuse(f"{at}.sources", "bad_shape", "composite takes 1 to 4 sources")
        for index, source in enumerate(sources):
            name, inner = _one(source, f"{at}.sources[{index}]", "a composite source")
            if not _AGG_NAME.fullmatch(name):
                _refuse(f"{at}.sources[{index}]", "bad_name", "a composite source name is 1 to 64 letters")
            kind_name, options = _one(inner, f"{at}.sources[{index}].{name}", "a composite source")
            if kind_name not in _COMPOSITE_SOURCES:
                _refuse(f"{at}.sources[{index}].{name}.{kind_name}", "aggregation_not_allowed",
                        "a composite source is terms or date_histogram")
            options = _keys(options, f"{at}.sources[{index}].{name}.{kind_name}", _COMPOSITE_SOURCES[kind_name],
                            kind_name)
            _field(options, f"{at}.sources[{index}].{name}.{kind_name}")
            _scalars(options, options.keys(), f"{at}.sources[{index}].{name}.{kind_name}")
            if kind_name == "date_histogram":
                _interval_seconds(options, f"{at}.sources[{index}].{name}.{kind_name}")
        if "after" in body:
            after = body["after"]
            if not isinstance(after, dict) or not all(isinstance(v, _SCALAR) for v in after.values()) or not all(
                    _AGG_NAME.fullmatch(key) for key in after):
                _refuse(f"{at}.after", "bad_shape", "after takes the after_key a previous page returned")
        return size
    if kind == "filters":
        filters = body.get("filters")
        items = (list(filters.items()) if isinstance(filters, dict)
                 else list(enumerate(filters)) if isinstance(filters, list) else None)
        if not items or len(items) > MAX_LIST_ITEMS:
            _refuse(f"{at}.filters", "bad_shape", f"filters takes 1 to {MAX_LIST_ITEMS} named queries")
        for key, item in items:
            if isinstance(key, str) and not _AGG_NAME.fullmatch(key):
                _refuse(f"{at}.filters.{key}", "bad_name", "a filter name is 1 to 64 letters, digits, _ or -")
            _query(item, f"{at}.filters.{key}")
        _scalars(body, ("other_bucket", "other_bucket_key"), at)
        return len(items) + 1
    if kind in ("range", "date_range", "ip_range"):
        _field(body, at)
        _scalars(body, [key for key in body if key != "ranges"], at)
        return _ranges(body, at)
    if kind == "date_histogram":
        _field(body, at)
        seconds = _interval_seconds(body, at)
        if "min_doc_count" in body:
            _int(body["min_doc_count"], f"{at}.min_doc_count", 0, 1_000_000_000)
        _scalars(body, [key for key in body if key != "order"], at)
        _order(body, at)
        # the window is the only bound (no extended or hard bounds are accepted): its buckets are counted from it
        buckets = int(window_seconds // max(seconds, 0.001)) + 2
        if buckets > MAX_DATE_BUCKETS:
            _refuse(at, "too_many_buckets",
                    f"this interval makes {buckets} buckets over the window; at most {MAX_DATE_BUCKETS}: widen it")
        return buckets
    if kind == "missing":
        _field(body, at)
        return 1
    if kind == "top_hits":
        size = _int(body.get("size", 3), f"{at}.size", 1, MAX_TOP_HITS)
        if "sort" in body:
            _sort(body["sort"], f"{at}.sort")
        _shown(body.get("_source"), f"{at}._source")
        return size
    # the other metrics
    _field(body, at)
    if kind == "cardinality" and "precision_threshold" in body:
        _int(body["precision_threshold"], f"{at}.precision_threshold", 1, MAX_CARDINALITY_PRECISION)
    if kind == "percentiles" and "percents" in body:
        percents = body["percents"]
        if not isinstance(percents, list) or not 0 < len(percents) <= MAX_LIST_ITEMS or not all(
                isinstance(v, (int, float)) and not isinstance(v, bool) for v in percents):
            _refuse(f"{at}.percents", "bad_shape", f"percents takes 1 to {MAX_LIST_ITEMS} numbers")
    _scalars(body, [key for key in body if key != "percents"], at)
    return 1


def _order(body: dict, at: str) -> None:
    order = body.get("order")
    if order is None:
        return
    items = order if isinstance(order, list) else [order]
    for index, item in enumerate(items[:MAX_SORT_KEYS + 1]):
        key, direction = _one(item, f"{at}.order[{index}]", "an order")
        if direction not in ("asc", "desc") or not _NAME.fullmatch(key.lstrip("_")):
            _refuse(f"{at}.order[{index}]", "bad_shape", "an order is {key: asc or desc}")
    if len(items) > MAX_SORT_KEYS:
        _refuse(f"{at}.order", "bad_shape", f"order takes at most {MAX_SORT_KEYS} keys")


def _shown(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if not isinstance(value, list) or len(value) > MAX_SHOWN_FIELDS or not all(
            isinstance(v, str) and _PATTERN.fullmatch(v) for v in value):
        _refuse(path, "bad_shape", f"fields to show take a list of at most {MAX_SHOWN_FIELDS} names or patterns")


# ---- the boundary ------------------------------------------------------------------------------------------------

def validate_es_query(query: dict | None, aggs: dict | None, sort: list | None, size: Any,
                      shown_fields: list | None, *, window_seconds: float) -> None:
    """Refuse (QueryRefused) anything outside what an agent query may hold; return when every part is accepted."""
    parts = {"query": query, "aggs": aggs, "sort": sort, "source_fields": shown_fields}
    # depth, size and text first and without recursion: nothing below (serialization included) meets a deep value
    for name, value in parts.items():
        if value is not None:
            _shape(value, name)
    try:
        encoded = json.dumps(parts, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        _refuse("$", "bad_value", "the query must be plain JSON")
    if len(encoded.encode("utf-8")) > MAX_QUERY_BYTES:
        _refuse("$", "too_large", f"the query, aggregations and sort exceed {MAX_QUERY_BYTES} bytes together")
    if query is not None:
        _query(query, "query")
    if aggs is not None:
        _aggs(aggs, "aggs", 1, [0], window_seconds)
    if sort is not None:
        _sort(sort, "sort")
    _int(size, "size", 0, MAX_QUERY_HITS)
    _shown(shown_fields, "source_fields")
    if query is None and aggs is None:
        _refuse("query", "nothing_asked", "give a query, aggregations, or both")


def validate_expression(expression: Any) -> str:
    """An Arkime expression as the viewer takes it: text of 1 to MAX_EXPRESSION_CHARS characters without control
    characters. The viewer parses it; the window is sent beside it, never inside it."""
    if not isinstance(expression, str) or not expression.strip() or len(expression) > MAX_EXPRESSION_CHARS:
        _refuse("expression", "bad_expression", f"an expression is 1 to {MAX_EXPRESSION_CHARS} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in expression):
        _refuse("expression", "control_character", "an expression holds no control characters")
    regexes = arkime_regexes(expression)
    if len(regexes) > MAX_ARKIME_REGEXES:
        _refuse("expression", "too_many_regexes",
                f"an expression holds at most {MAX_ARKIME_REGEXES} regular expressions (/.../); it holds "
                f"{len(regexes)}")
    for length in regexes:
        if length < 0:
            _refuse("expression", "unclosed_regex", "a regular expression (/.../) in the expression is not closed")
        if length > MAX_ARKIME_REGEX_CHARS:
            _refuse("expression", "pattern_too_long",
                    f"a regular expression in the expression is longer than {MAX_ARKIME_REGEX_CHARS} characters")
    return expression


def arkime_regexes(expression: str) -> list[int]:
    """The length of each regular expression literal (/.../) in an Arkime expression, -1 for one never closed. A
    literal starts with a / that follows an operator (== or !=), a list opening or a list comma, outside a quoted
    string; a / elsewhere (an address's /24, inside "a/b") is not one."""
    found: list[int] = []
    index, quoted, last = 0, False, ""
    while index < len(expression):
        char = expression[index]
        if quoted:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quoted = False
            index += 1
            continue
        if char == '"':
            quoted, last = True, '"'
            index += 1
            continue
        if char == "/" and last in ("==", "!=", "[", ","):
            end = index + 1
            while end < len(expression) and expression[end] != "/":
                end += 2 if expression[end] == "\\" else 1        # a backslash escapes the next character only
            end = min(end, len(expression))
            found.append(end - index - 1 if end < len(expression) else -1)
            index, last = end + 1, "/"
            continue
        if char in "=!" and expression[index + 1:index + 2] == "=":
            last = char + "="
            index += 2
            continue
        if not char.isspace():
            last = char if char in "[," else "x"
        index += 1
    return found


def es_body(query: dict | None, aggs: dict | None, sort: list | None, size: int, *, window_clause: dict,
            time_field: str) -> dict:
    """The search body sent for a validated agent query: the window clause and the model's query as filters of one
    bool (so the query can only narrow the window's records), the fixed caps, the model's aggregations and sort. Every
    record's whole _source is read (what the model asked to see is applied to the preview only)."""
    filters = [window_clause] + ([query] if query is not None else [])
    body: dict = {"query": {"bool": {"filter": filters}}, "size": size, "timeout": QUERY_TIMEOUT,
                  "terminate_after": TERMINATE_AFTER, "track_total_hits": TRACK_TOTAL_HITS,
                  "sort": sort if sort is not None else [{time_field: {"order": "asc"}}]}
    if aggs is not None:
        body["aggs"] = aggs
    return body


def aggregation_caveats(value: Any, limit: int = 10) -> list[str]:
    """Each terms-like result that is a top N with other values left out (sum_other_doc_count above 0) or whose
    counts may be off (doc_count_error_upper_bound above 0), named by its aggregation path; at most `limit`, the rest
    counted."""
    out: list[str] = []
    stack = [(value, "aggs")]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            other = node.get("sum_other_doc_count")
            error = node.get("doc_count_error_upper_bound")
            if isinstance(other, int) and not isinstance(other, bool) and other > 0:
                out.append(f"{path}: top {len(node.get('buckets') or [])} shown; other values exist "
                           f"({other} records in values not shown)")
            if isinstance(error, int) and not isinstance(error, bool) and error > 0:
                out.append(f"{path}: bucket counts may be low by up to {error} (shard-level top lists)")
            stack.extend((child, f"{path}.{key}") for key, child in node.items() if isinstance(child, (dict, list)))
        elif isinstance(node, list):
            stack.extend((child, f"{path}[{index}]") for index, child in enumerate(node))
    out = sorted(out)
    return out[:limit] + ([f"{len(out) - limit} more aggregation caveats"] if len(out) > limit else [])


def bound_aggregations(value: Any) -> tuple[Any, int]:
    """Aggregation results with every bucket list cut to MAX_BUCKETS_SHOWN (and top hits to MAX_TOP_HITS), each cut
    list counted beside it; and how many buckets were cut in all."""
    cut = 0

    def walk(node):
        nonlocal cut
        if isinstance(node, dict):
            out = {}
            for key, child in node.items():
                if key == "buckets" and isinstance(child, list) and len(child) > MAX_BUCKETS_SHOWN:
                    cut += len(child) - MAX_BUCKETS_SHOWN
                    out["buckets_not_shown"] = len(child) - MAX_BUCKETS_SHOWN
                    child = child[:MAX_BUCKETS_SHOWN]
                elif key == "buckets" and isinstance(child, dict) and len(child) > MAX_BUCKETS_SHOWN:
                    cut += len(child) - MAX_BUCKETS_SHOWN
                    out["buckets_not_shown"] = len(child) - MAX_BUCKETS_SHOWN
                    child = dict(list(child.items())[:MAX_BUCKETS_SHOWN])
                elif key == "hits" and isinstance(child, list) and len(child) > MAX_TOP_HITS:
                    out["hits_not_shown"] = len(child) - MAX_TOP_HITS
                    child = child[:MAX_TOP_HITS]
                out[key] = walk(child)
            return out
        if isinstance(node, list):
            return [walk(child) for child in node]
        return node

    return walk(value), cut


def window_seconds(start: datetime, end: datetime) -> float:
    return max(0.0, (end - start).total_seconds())
