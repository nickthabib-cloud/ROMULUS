"""The ASCII optimization preserves the unconditional-IDNA name semantics."""
import random
import re
import string
import sys

from romulus.detect.service_catalog import NameTrie, canonical_name


def reference_name(value, *, host=False):
    """Frozen pre-optimization canonicalizer, including the Host/DNS envelope."""
    if not isinstance(value, str) or not value or len(value) > 260:
        return None
    if host and ":" in value:
        if value.startswith("["):
            return None
        value, separator, port = value.rpartition(":")
        if not separator or not port.isascii() or not port.isdecimal() or not 0 <= int(port) <= 65535:
            return None
    if len(value) > 254 or re.search(r"[\s/:\\\[\]*?#@]", value):
        return None
    try:
        name = value.casefold().encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    name = name.removesuffix(".")
    if len(name) > 253 or not name or any(not label or len(label) > 63 for label in name.split(".")):
        return None
    return name


def encode_calls(value):
    calls = []

    def record(frame, event, operation):
        if event == "c_call" and getattr(operation, "__name__", "") == "encode":
            calls.append(operation)

    previous = sys.getprofile()
    try:
        sys.setprofile(record)
        result = canonical_name(value)
    finally:
        sys.setprofile(previous)
    return result, len(calls)


def test_plain_ascii_names_skip_the_idna_codec():
    assert encode_calls("SVC_APP.ABC.OAST.FUN.") == ("svc_app.abc.oast.fun", 0)


def test_non_ascii_and_punycode_names_keep_the_idna_codec():
    for name in ("BÜCHER.example", "XN--BCHER-KVA.example"):
        canonical, calls = encode_calls(name)
        assert canonical == "xn--bcher-kva.example" and calls > 0


def generated_names(count=100_000):
    """Half ASCII and half non-ASCII; include malformed and boundary cases."""
    rng = random.Random(0xC0FFEE)
    alphabet = string.ascii_letters + string.digits + "-_!$%&()+=,;~\x00"
    suffixes = ("ngrok-free.app", "oast.fun", "bücher.example", "xn--bcher-kva.example", "unlisted.test")
    unicode_labels = ("BÜCHER", "café", "例え", "ß", "K", "а", "💡", "e\u0301", "\ud800", "\u200d")
    for index in range(count):
        label = "".join(rng.choices(alphabet, k=rng.choice((1, 8, 20, 63, 64, 250))))
        suffix = rng.choice(suffixes if index % 2 else ("ngrok-free.app", "oast.fun", "unlisted.test"))
        if index % 2:
            label += rng.choice(unicode_labels)
        name = label + "." + suffix
        mode = index % 12
        if mode == 0:
            name = name.upper() + "."
        elif mode == 1:
            name = name.replace(".", "\u3002")
        elif mode == 2:
            name = "xn--" + name
        elif mode == 3:
            name = "." + name
        elif mode == 4:
            name = name.replace(".", "..", 1)
        elif mode == 5:
            name += ":" + str(rng.choice((0, 443, 8080, 65535, 65536)))
        elif mode == 6:
            name = "https://" + name + "/"
        elif mode == 7:
            name += ".."
        elif mode == 8:
            name = "*." + name
        elif mode == 9:
            name = "\t" + name
        elif mode == 10:
            name = "[::1]:443" if index % 4 == 0 else name + ".invalid"
        yield name, bool(index % 3)


def test_one_hundred_thousand_randomized_names_equal_pre_optimization():
    suffixes = (("ngrok-free.app", "ngrok"), ("oast.fun", "callback"),
                ("bücher.example", "books"), ("special.oast.fun", "nested"))
    trie = NameTrie(suffixes)
    normalized = sorted(((reference_name(suffix), entry) for suffix, entry in suffixes),
                        key=lambda pair: pair[0].count("."))
    count = 0
    for name, host in generated_names():
        expected = reference_name(name, host=host)
        assert canonical_name(name, host=host) == expected, repr(name)
        # This independent suffix scan checks trie output, including boundary
        # and opaque-prefix handling, rather than calling the optimized walker.
        dns_name = reference_name(name)
        entries = tuple(entry for suffix, entry in normalized
                        if dns_name is not None and (dns_name == suffix or dns_name.endswith("." + suffix)))
        assert trie.lookup(name) == entries, repr(name)
        count += 1
    assert count == 100_000
