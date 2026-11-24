"""web.access_log_web_shell: a web shell read from a web server's access log alone."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.registry import ALL_PLAYBOOKS
from romulus.detect.web_access_shell import AccessLogWebShell, command_in, request_path, script_kind
from romulus.evidence.typed import RawRef, TypedEvent, fv
from tests.claim_citations import finding_problems

T0 = datetime(2024, 11, 18, 10, 0, tzinfo=UTC)
ATTACKER = "203.0.113.50"
_n = 0


def req(minutes, url, *, method="GET", status=200, src=ATTACKER, host="web01", **extra):
    global _n
    _n += 1
    fields = {"url.original": url, "http.request.method": method, "http.response.status_code": status,
              "source.ip": src, "user_agent.original": "Mozilla/5.0", **extra}
    return TypedEvent(id=f"ws{_n:07d}", family="http_access", ts=T0 + timedelta(minutes=minutes), host=host,
                      outcome="success" if isinstance(status, int) and status < 400 else "failure",
                      fields={k: fv(v, f"ws{_n}:{k}") for k, v in fields.items() if v is not None},
                      raw=[RawRef(target="fx", native_id=f"ws{_n}")], normalizer="fixture")


def history(hours=30, host="web01"):
    """Ordinary traffic from well before the attack, so the rule has a day of the host's log behind it."""
    return [req(-60 * hours + 7 * i, "/index.php", src="192.0.2.10", host=host) for i in range(hours * 60 // 7)]


def run(*batches):
    rule = AccessLogWebShell()
    try:
        out = []
        for batch in batches:
            out += rule.consume(list(batch))
        out += rule.finalize()
        return rule, out
    finally:
        rule.close_spill()


def clean(matches):
    for match in matches:
        assert not finding_problems(match.claim, match.notes, match.events), finding_problems(
            match.claim, match.notes, match.events)


def test_the_rule_is_registered_with_a_card():
    assert AccessLogWebShell in ALL_PLAYBOOKS
    assert {"behavior", "telemetry", "fidelity", "benign_and_cost", "query_cost", "next_pivot", "adds",
            "research_basis", "retrieval", "lanes"} <= set(AccessLogWebShell.card)


def test_upload_then_new_script_with_commands_is_high():
    events = history() + [
        req(0, "/wp-admin/async-upload.php", method="POST"),
        req(2, "/wp-content/uploads/2024/11/cache.php"),
        req(3, "/wp-content/uploads/2024/11/cache.php?cmd=whoami"),
        req(4, "/wp-content/uploads/2024/11/cache.php?cmd=cat+%2Fetc%2Fpasswd"),
    ]
    rule, [m] = run(events)
    clean([m])
    assert (m.proposed_lane, m.severity) == ("high", "high") and m.attack == ("T1505.003", "T1190", "T1059")
    assert "the script /wp-content/uploads/2024/11/cache.php under the 'uploads' directory was first answered" in m.claim
    assert "the same client sent an upload-style request, POST /wp-admin/async-upload.php (status 200)" in m.claim
    assert "2 answered request(s) to it carried a command in a query parameter" in m.claim
    assert "parameter `cmd` decoding to `whoami`" in m.claim
    assert "new in that history" in m.claim and "not what the script ran" in m.claim
    assert m.claim_type == "correlated_observation" and rule.missing_required == 0


def test_a_put_of_the_script_itself_then_its_first_answer_is_high_without_commands():
    events = history() + [req(0, "/files/x.jsp", method="PUT", status=201), req(1, "/files/x.jsp")]
    _rule, [m] = run(events)
    clean([m])
    assert m.proposed_lane == "high" and "the write targeted the script itself" in m.claim
    assert any("POST body" in note for note in m.notes)


def test_an_upload_link_alone_is_a_lead_and_another_client_is_named():
    events = history() + [req(0, "/upload.php", method="POST", src="198.51.100.9"), req(30, "/uploads/a.php")]
    _rule, [m] = run(events)
    clean([m])
    assert m.proposed_lane == "lead" and "another client (198.51.100.9)" in m.claim


def test_commands_alone_on_a_new_writable_path_script_are_a_lead():
    events = history() + [req(0, "/images/thumbs/i.php?c=id"), req(1, "/images/thumbs/i.php?c=ls+-la+%2Fvar%2Fwww")]
    _rule, [m] = run(events)
    clean([m])
    assert m.proposed_lane == "lead" and any("rests on the command parameters" in note for note in m.notes)


@pytest.mark.parametrize("minutes, linked", [(60, True), (60 + 1 / 60, False)])
def test_the_upload_window_is_inclusive_at_one_hour(minutes, linked):
    events = history() + [req(0, "/upload", method="POST"), req(minutes, "/tmp/sh.php?cmd=uname+-a")]
    _rule, [m] = run(events)
    assert (m.proposed_lane == "high") is linked


def test_hidden_extensions_are_scripts():
    assert script_kind("/uploads/a.php.jpg") == ("php", True)
    assert script_kind("/uploads/shell.jsp;.png") == ("jsp", True)
    assert script_kind("/uploads/photo.jpg") is None and script_kind("/uploads/.htaccess") is None
    events = history() + [req(0, "/media/upload", method="POST"), req(1, "/media/avatar.php.jpg?cmd=id")]
    _rule, [m] = run(events)
    assert m.proposed_lane == "high" and "hides the .php extension" in m.claim


@pytest.mark.parametrize("name, value, command", [
    ("cmd", "whoami", True), ("x", "uname -a", True), ("q", "cat /etc/passwd", True), ("c", "id", True),
    ("p", "cmd.exe /c dir C:\\", True), ("a", "powershell -enc SQBFAFgA", True), ("f", "1;id", True),
    ("sort", "id", False), ("type", "echo", False), ("cat", "books", False), ("lang", "dir", False),
    ("q", "how to use ls", False), ("page", "net", False), ("search", "whoami command meaning", True),
])
def test_command_parameters_are_typed_by_program_and_operand(name, value, command):
    assert bool(command_in(name, value)) is command


@pytest.mark.parametrize("events", [
    # a resizer under an images directory requested long before an editor's upload: not new after the upload
    lambda: history() + [req(-600, "/images/resize.php?src=a.jpg&w=100"), req(0, "/upload.php", method="POST"),
                         req(5, "/images/resize.php?src=b.jpg&w=100")],
    # scanner probes for known shell names answered 404: nothing appeared
    lambda: history() + [req(0, f"/uploads/{name}.php?cmd=id", status=404, src="198.51.100.66")
                         for name in ("shell", "cmd", "c99", "r57", "wso", "b374k")],
    # a failed upload and a 403 on the script: neither stored nor answered
    lambda: history() + [req(0, "/upload.php", method="POST", status=403), req(1, "/uploads/x.php", status=403)],
    # a command word in a search on an application script outside upload-style directories
    lambda: history() + [req(0, "/search.php?q=cat+%2Fetc%2Fpasswd"), req(1, "/admin/upload.php", method="POST")],
    # a tool name in a static file's path, and a static upload after an upload
    lambda: history() + [req(0, "/upload", method="POST"), req(1, "/uploads/webshell-detection.pdf"),
                         req(2, "/uploads/php-logo.png")],
    # a proxy's absolute-form request for a remote script
    lambda: history() + [req(0, "http://evil.example.test/uploads/x.php?cmd=id", host="proxy01")],
    # a login POST before a new script without commands is not an upload
    lambda: history() + [req(0, "/login.php", method="POST"), req(1, "/cache/page.php")],
])
def test_hard_benign_lookalikes_are_not_reported(events):
    _rule, out = run(events())
    assert out == []


def test_missing_fields_are_counted_never_a_clean_no_match():
    events = [req(0, None), req(0, "/uploads/a.php?cmd=id", method=None), req(0, "/uploads/a.php", status="-")]
    rule, out = run(events)
    assert out == [] and rule.missing_required == 3 and rule.evaluated == 0


def test_with_short_history_only_the_same_clients_upload_links():
    events = [req(0, "/upload.php", method="POST", src="198.51.100.9"), req(1, "/uploads/resize.php?w=1")]
    rule, out = run(events)
    assert out == [] and any("were not linked (1 record(s) not evaluated)" in r for r in rule.limit_reasons())


def test_short_history_states_newness_unresolved():
    events = [req(0, "/upload", method="POST"), req(1, "/uploads/z.php?cmd=whoami")]
    _rule, [m] = run(events)
    assert m.proposed_lane == "high" and "whether it was requested before is unresolved" in m.claim


def test_the_result_does_not_depend_on_read_order():
    events = history() + [req(0, "/upload", method="POST"), req(2, "/tmp/k.php"), req(3, "/tmp/k.php?cmd=id")]
    _rule, forward = run(events)
    _rule, backward = run(list(reversed(events[-3:])), events[:-3])
    assert [(m.proposed_lane, m.claim) for m in forward] == [(m.proposed_lane, m.claim) for m in backward]


def test_request_paths_are_decoded_and_normalised():
    assert request_path("/a/../uploads/%2e%2e/uploads/x.php?y=1") == "/uploads/x.php"
    assert request_path("http://host/x.php") is None and request_path("host:443") is None


def test_mission_scale_traffic_keeps_state_per_script_path_only():
    """A week of a busy site: many clients, a hot resizer under /images, editors' uploads; one shell."""
    rule = AccessLogWebShell()
    rule.HOT = 32
    out = []
    try:
        for hour in range(24 * 7):
            batch = []
            for i in range(600):
                minute = hour * 60 + i / 10
                src = f"10.{i % 200}.{hour % 250}.{i % 250}"
                if i % 50 == 0:
                    batch.append(req(minute, "/wp-admin/async-upload.php", method="POST", src="192.0.2.20"))
                    batch.append(req(minute + 0.1, f"/wp-content/uploads/2024/11/img{hour}_{i}.jpg"))
                elif i % 3 == 0:
                    batch.append(req(minute, f"/images/resize.php?src=p{i}.jpg&w=200", src=src))
                else:
                    batch.append(req(minute, f"/product.php?id={i}", src=src))
            if hour == 100:
                batch += [req(hour * 60 + 30, "/wp-admin/async-upload.php", method="POST"),
                          req(hour * 60 + 31, "/wp-content/uploads/2024/11/x.php?cmd=id")]
            out += rule.consume(batch)
        out += rule.finalize()
        assert len(rule.scripts) == 2                       # the resizer and the shell: one state per script path
    finally:
        rule.close_spill()
    assert [(m.proposed_lane, "x.php" in m.claim) for m in out] == [("high", True)]
