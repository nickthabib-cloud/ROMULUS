"""A response proved free of lone UTF-16 surrogates lets normalization skip looking for one; anything else is searched.

The proof must be sound: whenever `surrogate_free` says a body is free, nothing parsed from it (records, or text a
normalizer parses out of a record again, such as an EVE line) holds a lone surrogate.
"""
import json
import random
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from romulus.config import Settings
from romulus.errors import SourceError
from romulus.evidence import surrogates
from romulus.evidence.normalize import normalize_hits
from romulus.sources.compile import compile_es
from romulus.sources.es import ElasticClient, last_response_surrogate_free, surrogate_free
from romulus.sources.execute import execute
from romulus.sources.models import Completeness, SearchIntent, SearchOutcome, Window
from romulus.sources.profile import contract_from_types
from tests.test_raw_scrub import SWEPT

BACKSLASH = "\\"
W = Window(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 1, 1, tzinfo=UTC))
C = contract_from_types("idx", {"@timestamp": "date", "n": "long"})


def _escape(code: str) -> bytes:
    return (BACKSLASH + "u" + code).encode()


@pytest.mark.parametrize("body,free", [
    (b'{"a": "plain ascii"}', True),
    (b'{"a": "caf' + _escape("00e9") + b'"}', True),                     # an escape outside the surrogate range
    ('{"a": "한글"}'.encode(), True),                            # Hangul: 0xED with a 0x80-0x9F second byte
    (b'{"a": "x' + _escape("d800") + b'"}', False),
    (b'{"a": "x' + _escape("DFFF") + b'"}', False),
    (b'{"a": "x' + _escape("dB12") + b'"}', False),
    (b'{"a": "' + _escape("d83d") + _escape("de00") + b'"}', False),     # a valid pair is searched, never skipped
    (b'{"a": "nested ' + BACKSLASH.encode() + _escape("d800") + b'"}', False),   # an escape inside parsed text
    (b'{"a": "raw \xed\xa0\x80"}', False),                               # UTF-8 bytes of a surrogate
    (b'\xef\xbb\xbf{"a": 1}', False),                                    # not plain UTF-8: never free
    (b'{"a": "cut ' + BACKSLASH.encode() + b'u', False),                 # an escape cut short
    (b'{"a": "cut ' + BACKSLASH.encode() + b'ud', False),
    # a nested layer spelling the inner backslash as an escape: the inner text parses to a lone surrogate
    (b'{"t": "' + BACKSLASH.encode() + b'"' + _escape("005c") + b'ud800' + BACKSLASH.encode() + b'""}', False),
    (b'{"a": "' + _escape("0041") + b'"}', False),                       # an escaped hex digit is never free
    (b'{"a": "' + _escape("0075") + b'"}', False),                       # nor an escaped "u"
    (b'{"a": "' + _escape("005C") + b'"}', False),                       # nor an escaped backslash
    (b'{"a": "' + _escape("001b") + b'"}', True),                        # a control-character escape stays free
    (b'{"a": "a' + _escape("0026") + b'b' + _escape("003c") + b'"}', True),   # Go/.NET HTML-safe escapes stay free
    (b'{"a": "' + _escape("0067") + b'"}', True),                        # an escaped letter outside hex digits
])
def test_byte_forms_of_a_lone_surrogate(body, free):
    assert surrogate_free(body) is free


def _lone(value) -> bool:
    if isinstance(value, str):
        return surrogates.has_surrogate(value)
    if isinstance(value, dict):
        return any(_lone(key) or _lone(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_lone(item) for item in value)
    return False


def _parsed_texts(value):
    """Every string in a parsed value, and every value parsed again out of a string that is itself JSON."""
    yield value
    if isinstance(value, str):
        try:
            inner = json.loads(value)
        except ValueError:
            return
        yield from _parsed_texts(inner)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _parsed_texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _parsed_texts(item)


def _text(rng: random.Random) -> str:
    pool = ["a", "Z", "é", "한", "😀", "\x1b", "\\", '"', "\ud800", "\udbff", "\udc00", "\udfff", "한"]
    return "".join(rng.choice(pool) for _ in range(rng.randint(0, 6)))


def _value(rng: random.Random, depth: int = 0):
    kind = rng.randint(0, 5 if depth < 3 else 2)
    if kind <= 1:
        return _text(rng)
    if kind == 2:
        return rng.randint(-5, 5)
    if kind == 3:
        return {_text(rng): _value(rng, depth + 1) for _ in range(rng.randint(0, 3))}
    if kind == 4:
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return json.dumps(_value(rng, depth + 1), ensure_ascii=rng.random() < 0.5)      # JSON text inside text


def test_a_body_called_free_never_parses_to_a_lone_surrogate():
    rng = random.Random(20261105)
    checked = free = 0
    for _ in range(4000):
        value = {"hits": {"hits": [{"_source": _value(rng)} for _ in range(rng.randint(1, 3))]}}
        encodings = [json.dumps(value).encode(),
                     json.dumps(value, ensure_ascii=False).encode("utf-8", "surrogatepass")]
        for body in encodings:
            checked += 1
            if not surrogate_free(body):
                continue
            free += 1
            assert not any(_lone(item) for item in _parsed_texts(json.loads(body)))
    assert checked == 8000 and 0 < free < checked              # both outcomes are exercised


def _client(bodies: list[bytes]) -> ElasticClient:
    pages = iter(bodies)

    def handler(request: httpx.Request):
        if request.url.path == "/":
            return httpx.Response(200, json={"version": {"number": "9.5.5"}})
        if request.url.path.endswith("/_pit") and request.method == "POST":
            return httpx.Response(200, json={"id": "pit1"})
        if request.url.path == "/_pit":
            return httpx.Response(200, json={"succeeded": True})
        body = next(pages, None)
        if body is None:
            return httpx.Response(503, json={"error": "no more pages"})
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})
    return ElasticClient(Settings(es_url="http://es"), transport=httpx.MockTransport(handler))


def _page(ns: list[int], total: int, text: str = "ok") -> bytes:
    hits = ",".join(f'{{"_id":"d{n}","_index":"idx","_source":{{"n":{n},"t":"{text}"}},"sort":[{n},{n}]}}'
                    for n in ns)
    return (f'{{"pit_id":"pit1","timed_out":false,"_shards":{{"failed":0}},'
            f'"hits":{{"total":{{"value":{total},"relation":"eq"}},"hits":[{hits}]}}}}').encode()


def test_each_page_carries_its_own_response_flag():
    client = _client([_page([1, 2], 3), _page([3], 3, BACKSLASH + "ud800")])
    q = compile_es(SearchIntent(kind="raw", target="idx", window=W, max_records=10), C)
    pages = list(client.iterate(q, 10, page_size=2))
    assert [len(hits) for hits, _meta in pages] == [2, 1]
    assert [meta["surrogate_free"] for _hits, meta in pages] == [True, False]


class _Pages:
    settings = Settings(es_url="http://es")
    version = "test"

    def __init__(self, flags):
        self.flags = flags

    def iterate(self, q, max_records, **kwargs):
        for n, flag in enumerate(self.flags):
            yield ([{"_id": f"d{n}", "_index": "idx", "_source": {"n": n}}],
                   {"problems": [], "total": len(self.flags), "total_relation": "eq", "surrogate_free": flag})


@pytest.mark.parametrize("flags,free", [([True, True], True), ([True, False], False), ([False], False), ([], True)])
def test_an_outcome_is_free_only_when_every_page_was(flags, free):
    out = execute(_Pages(flags), SearchIntent(kind="raw", target="idx", window=W, max_records=10), C)
    assert out.returned == len(flags) and out.surrogate_free is free


def test_the_flag_is_per_thread():
    results = {}
    barrier = threading.Barrier(2)

    def run(name, body):
        client = _client([body])
        client.request("POST", "/idx/_search", {"query": {"match_all": {}}})
        barrier.wait()
        results[name] = last_response_surrogate_free()

    threads = [threading.Thread(target=run, args=("clean", _page([1], 1))),
               threading.Thread(target=run, args=("dirty", _page([1], 1, BACKSLASH + "udfff")))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == {"clean": True, "dirty": False}


def test_a_failed_request_never_leaves_a_stale_free_flag():
    client = _client([_page([1], 1)])
    client.request("POST", "/idx/_search", {"query": {"match_all": {}}})
    assert last_response_surrogate_free() is True
    with pytest.raises(SourceError):
        client.request("POST", "/idx/_search", {"query": {"match_all": {}}})
    assert last_response_surrogate_free() is False


def test_the_flag_is_never_serialized_and_defaults_to_searching():
    outcome = SearchOutcome(target="t", fingerprint="f", started_at=W.start, ended_at=W.start + timedelta(seconds=1),
                            completeness=Completeness.complete)
    assert outcome.surrogate_free is False
    outcome._surrogate_free = True
    assert outcome.model_copy(update={"records": []}).surrogate_free is True
    assert "surrogate" not in outcome.model_dump_json()


def test_a_free_batch_normalizes_exactly_as_a_searched_one(monkeypatch):
    hits = [json.loads(json.dumps(h)) for _name, h in SWEPT]
    searched = normalize_hits([json.loads(json.dumps(h)) for h in hits])
    monkeypatch.setattr(surrogates, "sanitize", lambda *a, **k: pytest.fail("a free batch is not searched"))
    monkeypatch.setattr(surrogates, "event_paths", lambda *a, **k: pytest.fail("a free batch is not searched"))
    skipped = normalize_hits(hits, surrogate_free=True)
    assert [e.model_dump(mode="json") for e in skipped[0]] == [e.model_dump(mode="json") for e in searched[0]]
    assert skipped[1:] == searched[1:]


def _encode(value, rng: random.Random) -> str:
    """JSON text as any valid encoder may write it: printable ASCII, quotes and backslashes sometimes as escapes,
    other characters as escapes or as themselves (a lone surrogate as itself is encoded with surrogatepass)."""
    if isinstance(value, str):
        out = ['"']
        for ch in value:
            code = ord(ch)
            if ch == '"':
                out.append(BACKSLASH + '"' if rng.random() < 0.7 else BACKSLASH + "u0022")
            elif ch == BACKSLASH:
                out.append(BACKSLASH * 2 if rng.random() < 0.7 else BACKSLASH + "u005c")
            elif code < 0x20:
                out.append(f"{BACKSLASH}u{code:04x}")
            elif code < 0x80:
                out.append(ch if rng.random() < 0.8 else f"{BACKSLASH}u{code:04x}")
            elif code <= 0xFFFF and rng.random() < 0.5:
                out.append(f"{BACKSLASH}u{code:04x}")
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    if isinstance(value, dict):
        return "{" + ",".join(_encode(str(key), rng) + ":" + _encode(item, rng) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_encode(item, rng) for item in value) + "]"
    return json.dumps(value)


def _value_any(rng: random.Random, depth: int = 0):
    kind = rng.randint(0, 5 if depth < 3 else 2)
    if kind <= 1:
        return _text(rng) + rng.choice(["", "u", "ud800", BACKSLASH + "u", "d8", "005c"])
    if kind == 2:
        return rng.randint(-5, 5)
    if kind == 3:
        return {_text(rng): _value_any(rng, depth + 1) for _ in range(rng.randint(0, 3))}
    if kind == 4:
        return [_value_any(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return _encode(_value_any(rng, depth + 1), rng)              # JSON text inside text, written by any encoder


def test_no_encoder_hides_a_lone_surrogate_at_any_depth():
    rng = random.Random(51105)
    checked = free = 0
    for _ in range(6000):
        value = {"hits": {"hits": [{"_source": _value_any(rng)} for _ in range(rng.randint(1, 3))]}}
        body = _encode(value, rng).encode("utf-8", "surrogatepass")
        checked += 1
        if not surrogate_free(body):
            continue
        free += 1
        assert not any(_lone(item) for item in _parsed_texts(json.loads(body)))
    assert 0 < free < checked


def test_opensearch_tie_group_pages_carry_their_own_flags():
    from tests.test_sources_opensearch import SimSearch, query

    sim = SimSearch.from_counts([3, 4, 1, 5])
    dirty = BACKSLASH.encode() + b"udc00"

    def handler(request):
        response = sim(request)
        body = json.loads(request.content) if request.content else {}
        if request.url.path == "/_search" and body.get("from", None) == 0:
            raw = response.content.replace(b'"_source":{}', b'"_source":{"t":"x' + dirty + b'"}', 1)
            return httpx.Response(200, content=raw, headers={"content-type": "application/json"})
        return response

    client = ElasticClient(Settings(es_url="http://os.invalid", es_flavor="opensearch"),
                           transport=httpx.MockTransport(handler))
    pages = list(client.iterate(query(), max_records=10_000, page_size=4))
    assert pages and any(not meta["surrogate_free"] for _hits, meta in pages)
    for hits, meta in pages:
        assert meta["surrogate_free"] is not any("t" in hit.get("_source", {}) for hit in hits)


def test_the_sweep_hands_the_outcome_flag_to_normalization(monkeypatch, tmp_path):
    from romulus.hunt import sweep as sw
    from tests import test_sweep as ts
    from tests.test_raw_scrub import _sweep

    seen = []
    real = sw.normalize_hits

    def spy(*args, **kwargs):
        seen.append(kwargs.get("surrogate_free"))
        return real(*args, **kwargs)

    records = [json.loads(json.dumps(h)) for _name, h in SWEPT[:5]]
    sweep, _repo, engine, window, contract = _sweep(monkeypatch, tmp_path, records)

    def complete(client, intent, contract):
        out = ts._complete(intent, records)
        out._surrogate_free = True
        return out

    monkeypatch.setattr(sw, "execute", complete)
    monkeypatch.setattr(sw, "normalize_hits", spy)
    sweep.run_partition("net", contract, [], window, est=len(records), any_of=[])
    assert seen and seen[0] is True
    sweep.close_stage()
    engine.dispose()

