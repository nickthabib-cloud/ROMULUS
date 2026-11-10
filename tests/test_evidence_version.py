"""Normalization changes must change the evidence version.

Typed events are stored once per event id. When normalization improved without a version change, a new hunt
silently reused an older hunt's rows (no `process.session_id`), and every login-session link went unsupported.
Event ids now carry the version of the producer that made them. These tests pin each producer's source to its
version: if you changed how raw records become typed events, bump the version and record the new digest here. If
you only changed comments or formatting, record the new digest under the same version.
"""
import hashlib
import inspect
from pathlib import Path

from romulus.detect import packets as packet_rules
from romulus.evidence import typed
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.typed import EVIDENCE_VERSION, RawRef, event_id
from romulus.evidence.windows import WINDOWS_NORMALIZER
from romulus.evidence.zeek import ZEEK_NORMALIZER
from romulus.hunt import packets as packet_stage
from romulus.sources import packets as packet_sources

# The files that turn ES/OpenSearch records into typed events (not shellparse.py, which only detectors use).
EVIDENCE_FILES = ("__init__.py", "auditd.py", "certificates.py", "community.py", "linux_catalog.py",
                  "linux_text.py", "linux_auth_text.py", "linux_service_text.py", "linux_text_types.py",
                  "normalize.py", "raw_scrub.py",
                  "surrogates.py", "typed.py")
PINNED_EVIDENCE = {9: "4e9103b2e1eab468361e1cde83127dd13cd5d87a4c7a0926ac35cf2116524009",
                   10: "e4dffd0944b86200b3c94aa301bead206967c58f565b30d426ee0071bd4f1aa9",
                   11: "150e5e4d74cb0f4891ef4cca7114a709f2038a42fc456e69f7952dcf0f6c9b32",
                   12: "fcda4d383cdb9d9d56aadffc237dcab81d4902dd3893e7b673aafd6cb6bdfb64",
                   # Suricata TCP/ICMP, Arkime ICMP and Zeek ICMP conn fields gained strict typed contracts.
                   13: "faf22327da69e63f594c999c9c5c68b909408308e37b0d1ab22ad86da1111b44",
                   # Arkime ICMP lists and Zeek ICMP type/address-family semantics are normalized truthfully.
                   # Then Zeek records moved to their own producer (zeek-ecs); no other record's output changed
                   # (tests/test_zeek_dispatch.py compares every previous shape with its output before the move).
                   # The certificate contract moved to certificates.py, shared with the Zeek producer, and the
                   # observer families gained app_tx and x509_certificate: no output of this producer changed (the
                   # same golden compares every one of its records). So too when they gained the Windows-protocol
                   # families (smb_tx, rpc_tx, kerberos_tx, ntlm_tx, remote_session, ldap_tx, address_assignment,
                   # asset_observed), which this producer never writes.
                   # Then lone UTF-16 surrogates were replaced at the normalization boundary (surrogates.py) and raw
                   # digests became the digest of the stored form (raw_scrub.py): only inputs that used to crash (a
                   # lone surrogate) change, and a non-Zeek record's stored form and digest are the record as read.
                   # Then normalize_hits gained an optional report of the families a skipped record could have fed,
                   # and the package registers its cleaners with the store on import: no output changed.
                   # The observer families also include sensor_health, and an explicit source declaration may
                   # route plain Zeek through its own producer. Every previous generic/native shape stays
                   # identical; only the Zeek producer changes its epoch and adds health records.
                   # Then normalize_hits may skip looking for lone surrogates in a batch whose every response was
                   # proved free of them (sources.es.surrogate_free): output is identical for every input.
                   14: "8d11cab49e970e0840b796080224e11d00b47edf37b78229108fa651f06bc3c3",
                   15: "476048cddffe2557e45a3c71a2e1e0a5e8f878bc96d858ff15c095730aa11971",
                   # Linux host records are read in every shipper's shape (Filebeat, Elastic Agent, Auditbeat,
                   # journald fields, syslog lines) through linux_catalog's shape table; records rebuilt from a
                   # shipper's parsed fields name their indexed paths and say so. The dev importer's records
                   # normalize exactly as before (tests/test_throughput_equality.py's normalization goldens).
                   16: "6e3812d30f1bb0011172854e2d47d2113cba533a17e857bdf65ee92af39b8935",
                   # Suricata records that Filebeat's suricata module or the Agent's Suricata integration indexed
                   # without their EVE line are rebuilt from the shipper's fields (normalize.ELASTIC_SURICATA_MOVES)
                   # instead of failing, and NXLog's flat Windows records are dispatched to the Windows producer (an
                   # error names its channel's dataset); every other record normalizes exactly as before (with the
                   # version set back to 16 the throughput and dispatch goldens are the earlier ones).
                   # Unreleased: re-pinned when Filebeat's template escapes were inverted as JSON, the alert action
                   # was read only from "allowed"/"denied", and a non-http record's dropped HTTP fields gained a
                   # caveat; only shipped Suricata records changed.
                   17: "7371e27837df2e31f0b02e0a29d427184dc72855d9b9efb0c32b0254a289e9d7"}
WINDOWS_EVIDENCE_FILES = ("community.py", "windows.py", "windows_catalog.py", "windows_reassembly.py", "rpc_catalog.py")
PINNED_WINDOWS = {
    # NXLog's flat im_msvistalog records are read (windows.nxlog_to_winlog); Winlogbeat and Agent records normalize
    # exactly as before (the public sample corpus is identical with the versions held at their earlier values).
    # Unreleased: re-pinned when a zoneless @timestamp became an error, an Eventlog record whose Channel data replaced
    # NXLog's kept its class, and a catalogued event under another channel was counted against its families; only
    # NXLog records changed.
    "windows-ecs@18": "9947e9cc0db37f00210965d9485253a9b3282eb5101481184f5da0124a18a51a",
    "windows-ecs@17": "c022428db9afea396a8420febde66b10e3d934b2f1472732f22a9e29c60247d6",
    "windows-ecs@16": "1f06783de9c4bcc48be2807bfbf26aa83f35d0c9b6eabf147567f3b3b07191e3",
    "windows-ecs@15": "25b5a842851ea66af4086d63dc5aac56fe8d0ec486396a456ed6330cc8ed721b",
    "windows-ecs@14": "167de2e4eade937df0f30ea8b82da2b81e5c3923e40707190c55240a53480bf5",
    "windows-ecs@13": "82231992a4a67abefc57f4c0b4bb7c3df0bbef1d63a21cef6303371b7b84ad70",
    "windows-ecs@12": "f77b93e9fb7012437e7b1e158cbfd4675e1381bfe3985a3b783f3c75ffdea223",
    "windows-ecs@11": "89b0392c0b506597732e45f1ada089cfee28c773f6f346d4993286a239c47f54",
    "windows-ecs@10": "3253f9ad37fe28bbede48043781594a03152874e8875094b0abea9cede271dcf",
    "windows-ecs@1": "8c2f1668700a3f7d0a143eef00473770e2e5c746fadf6ce3b2c95ae6bbe6a419",
    "windows-ecs@2": "c8931d60bb8eeb86c02b50d07950baea0e4225e01d3b9999cd12454609093255",
    "windows-ecs@3": "f0a941924e4c0b95b0e2f9dbc2635ae325708c7739b3fcf780e803e7dbfdf203",
    "windows-ecs@4": "6d31ffa710c230e79dc39509fd40740e69c35240028cfbc0a4759cb587dafd7d",
    "windows-ecs@5": "7ee0edd8506debc8fe682226a6ce8b87a9dc689e56e0fe58363a01e50262b0d6",
    "windows-ecs@6": "ce4b42e3ec76bc710b30631b261e0a6b78cab03539066d7237a9f86097e9cecc",
    "windows-ecs@7": "46edd73e96683bc4762130b48ad158c13664101a185fb3cd9f361b2ba66c0f78",
    "windows-ecs@9": "c7c70f9618344ea9ec418499d03747524e2b187491de32420da96002a35dbddc",
    "windows-ecs@8": "1d6de025af778e584dfc052227555d628b830af0735a61f4b26e61787905cdee",
}
ZEEK_EVIDENCE_FILES = ("certificates.py", "community.py", "ics_catalog.py", "rpc_catalog.py", "zeek.py", "zeek_catalog.py",
                       "zeek_credentials.py")
PINNED_ZEEK = {
    "zeek-ecs@4": "6b6092641e997f293f9e3ca160c77a65769f1106c8027d2941705875545147bc",
    "zeek-ecs@3": "93c7a682f05558dcfaab69f49444d90bf095fc7652efa1c62d5c9777081b99fa",
    # unreleased: re-pinned when the zeek_record precheck (a record with no Zeek marker skips the full recognition)
    # merged in; every recognition result is unchanged.
    "zeek-ecs@2": "7ade7bb451eb4cfa7b271def32593544c4beae76573676336eee896a6d00fff4",
    # unreleased: re-pinned when a Zeek record's raw digest became the digest of its stored form, credentials masked
    # (scrub_zeek_source); typed values are unchanged. Re-pinned again when zeek_record gained a precheck that turns
    # away a record carrying no Zeek marker before the full recognition: every recognition result is unchanged.
    "zeek-ecs@1": "a0913ccf746ede45a5f39255d94aca832da9a95dbb3276729f53bc1be6c4d085",
}
# The packet stage's normalizer: HTTP bodies rebuilt by TShark -> http_body events, and TCP connections rebuilt
# from per-segment payload -> tcp_stream events (with the shell analysis and the tables it reads).
PACKET_FUNCTIONS = (packet_stage._body_event, packet_rules.analyze_body, packet_rules._text, packet_rules._shebang,
                    packet_sources.decode_hex_body, packet_stage._stream_event, packet_sources.addresses,
                    packet_sources._endpoint, packet_sources.reassemble_tcp, packet_sources.TcpStreams,
                    packet_sources._flag, packet_stage._StreamTarget._judge,
                    packet_rules._echo, packet_sources._address, packet_sources._port, packet_sources.stream_key,
                    packet_sources._first, packet_sources._last, packet_stage._first, packet_stage._canon,
                    packet_rules.analyze_stream, packet_rules._Side, packet_rules._clean, packet_rules._lines,
                    packet_rules._bursts, packet_rules._texty, packet_rules._tokens, packet_rules._args_fit,
                    packet_rules._command_name, packet_rules.ShellIndicator)
PACKET_TABLES = (packet_sources.STREAM_PREFS, packet_sources.QUERIES["tcp_payload"],
                 [p.pattern for p in (*packet_rules.PROMPTS, *packet_rules.BANNERS, *packet_rules.SHELL_ERRORS,
                                      packet_rules.BARE_PROMPT, packet_rules.LOGIN_PROMPT,
                                      packet_rules.PASSWORD_PROMPT, packet_rules._IAC, packet_rules._ANSI,
                                      packet_rules._LINE_END)],
                 packet_rules.OUTPUT_SIGNATURES, sorted(packet_rules.WINDOWS_COMMANDS), packet_rules.OPENING_BYTES,
                 packet_rules.OUTPUT_WINDOW_BYTES, packet_rules.MAX_COMMAND_CHARS, packet_rules.MAX_COMMANDS,
                 packet_rules.PROMPT_SCAN_BYTES, packet_rules.MIN_INDICATORS, sorted(packet_rules.TYPED_TEXT_KINDS),
                 packet_sources.MAX_ADDRESS_CHARS, packet_stage.STREAM_DIRECTION_BYTES)
PINNED_PACKETS = {"tshark-packets@5": "1d6045c6230687d41dd4c0d6b541dd16b23031598fa5eb2fea1bc17e7388054d"}


def _files_digest() -> str:
    h = hashlib.sha256()
    for name in EVIDENCE_FILES:
        path = Path(typed.__file__).parent / name
        h.update(name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def _windows_files_digest() -> str:
    h = hashlib.sha256()
    for name in WINDOWS_EVIDENCE_FILES:
        path = Path(typed.__file__).parent / name
        h.update(name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def _zeek_files_digest() -> str:
    h = hashlib.sha256()
    for name in ZEEK_EVIDENCE_FILES:
        path = Path(typed.__file__).parent / name
        h.update(name.encode() + b"\0" + path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def _functions_digest() -> str:
    h = hashlib.sha256()
    for fn in PACKET_FUNCTIONS:
        h.update(fn.__qualname__.encode() + b"\0" + inspect.getsource(fn).replace("\r\n", "\n").encode() + b"\0")
    h.update(repr(PACKET_TABLES).encode())
    return h.hexdigest()


def test_evidence_normalization_matches_the_pinned_version():
    assert PINNED_EVIDENCE.get(EVIDENCE_VERSION) == _files_digest(), (
        "evidence normalization changed: if its output changed, bump EVIDENCE_VERSION in evidence/typed.py; then "
        f"record {_files_digest()} for version {EVIDENCE_VERSION} in tests/test_evidence_version.py")


def test_windows_normalization_matches_the_pinned_producer_version():
    assert PINNED_WINDOWS.get(WINDOWS_NORMALIZER) == _windows_files_digest(), (
        "Windows evidence normalization changed: bump WINDOWS_NORMALIZER, then record "
        f"{_windows_files_digest()} for {WINDOWS_NORMALIZER} in tests/test_evidence_version.py"
    )


def test_zeek_normalization_matches_the_pinned_producer_version():
    assert PINNED_ZEEK.get(ZEEK_NORMALIZER) == _zeek_files_digest(), (
        "Zeek evidence normalization changed: bump ZEEK_NORMALIZER, then record "
        f"{_zeek_files_digest()} for {ZEEK_NORMALIZER} in tests/test_evidence_version.py"
    )


def test_packet_normalization_matches_the_pinned_version():
    version = packet_stage.PACKET_NORMALIZER
    assert PINNED_PACKETS.get(version) == _functions_digest(), (
        "packet normalization changed: if its output changed, bump PACKET_NORMALIZER in hunt/packets.py; then "
        f"record {_functions_digest()} for {version} in tests/test_evidence_version.py")


def test_event_ids_carry_the_producer_and_version():
    ref = RawRef(target="idx", native_id="doc-1")
    assert NORMALIZER_VERSION.endswith(f"@{EVIDENCE_VERSION}")
    legacy = hashlib.sha256(b"process_exec|" + ref.key.encode()).hexdigest()[:24]
    assert event_id("process_exec", [ref]) != legacy                    # never collides with pre-versioned rows
    assert event_id("process_exec", [ref], WINDOWS_NORMALIZER) != event_id("process_exec", [ref])
    assert event_id("net_flow", [ref], ZEEK_NORMALIZER) != event_id("net_flow", [ref])
    assert event_id("http_body", [ref], "tshark-http@3") != event_id("http_body", [ref], "tshark-http@4")
    assert event_id("http_body", [ref], "tshark-http@4") != event_id("http_body", [ref], "tshark-packets@5")
