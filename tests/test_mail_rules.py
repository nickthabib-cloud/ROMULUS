"""Synthetic MTA field contracts based on Exim/Postfix logging and Microsoft outbound policy docs."""
import pytest

from romulus.evidence.typed import Outcome, fv
from tests.test_service_auth import event, rule, run


def mail(n, *, recipients=None, user="alice", direction="delivered", **kwargs):
    return event(n, family="mail_message", outcome=Outcome.success, extra={
        "mail.service": "exim", "mail.direction": direction, "mail.message_id": f"q{n}",
        "mail.authenticated_user": user, "mail.to": recipients or [f"r{n}@external.test"],
    }, **kwargs)


def burst():
    return rule("mail.outbound_burst", internal_domains=("internal.test",))


def test_outbound_burst_is_lead_and_counts_distinct_external_recipients():
    pb = burst()
    out = run(pb, [mail(i) for i in range(50)])
    assert len(out) == 1 and out[0].proposed_lane == "lead"
    assert "50" in out[0].claim and "external recipients" in out[0].claim


@pytest.mark.parametrize("mode", ["below", "repeated", "internal", "deferred", "spread", "other_user"])
def test_mail_burst_adversarial_negatives(mode):
    rows = [mail(i) for i in range(50)]
    if mode == "below":
        rows.pop()
    elif mode == "repeated":
        rows = [mail(i, recipients=["same@external.test"]) for i in range(100)]
    elif mode == "internal":
        rows = [mail(i, recipients=[f"r{i}@internal.test"]) for i in range(100)]
    elif mode == "deferred":
        rows = [mail(i, direction="deferred") for i in range(100)]
    elif mode == "spread":
        rows[-1] = mail(49, seconds=601)
    else:
        rows[-1] = mail(49, user="bob")
    assert run(burst(), rows) == []


@pytest.mark.parametrize("user,service,seconds,lane", [("alice", "exim", -10, "high"),
                                                     ("bob", "exim", -10, "lead"),
                                                     ("alice", "mysql", -10, "lead"),
                                                     ("alice", "exim", 100, "lead")])
def test_mail_high_needs_same_account_preceding_mail_auth_burst(user, service, seconds, lane):
    failures = [event(1000+i, seconds=seconds+i, service=service, user=user) for i in range(10)]
    out = run(burst(), failures + [mail(i) for i in range(50)])
    assert len(out) == 1 and out[0].proposed_lane == lane


def test_mail_without_external_domain_definition_is_unresolved():
    pb = rule("mail.outbound_burst")
    assert run(pb, [mail(1)]) == []
    assert pb.missing_required == 1


def test_mail_missing_recipient_and_truncated_recipient_list_are_honest():
    row = mail(1)
    del row.fields["mail.to"]
    pb = burst()
    assert run(pb, [row]) == [] and pb.missing_required == 1
    row = mail(2)
    row.fields["mail.to_count"] = fv(40, "synthetic")
    pb = burst()
    assert run(pb, [row]) == [] and pb.missing_required == 1


def test_executable_attachment_uses_only_logged_names_and_groups_message():
    rows = [mail(i) for i in range(3)]
    for row in rows:
        row.fields["mail.message_id"] = fv("same-queue", "synthetic")
        row.fields["mail.attachment_names"] = fv(["invoice.pdf", "invoice.PDF.EXE"], "MTA filename")
    out = run(rule("mail.executable_attachment"), rows)
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "invoice.PDF.EXE" in out[0].claim


def test_attachment_body_mentions_benign_extensions_and_missing_names_do_not_match():
    plain = mail(1)
    plain.fields["mail.subject"] = fv("please run malware.exe", "synthetic")
    harmless = mail(2)
    harmless.fields["mail.attachment_names"] = fv(["script.sh.txt", "report.pdf"], "synthetic")
    pb = rule("mail.executable_attachment")
    assert run(pb, [plain, harmless]) == []
    assert pb.missing_required == 1


def test_queue_metadata_on_received_line_attributes_later_deliveries_and_failures():
    failures = [event(1000+i, seconds=-20+i, service="exim") for i in range(10)]
    rows = []
    for i in range(50):
        metadata = mail(2000+i, seconds=-10, direction="received")
        metadata.fields["mail.message_id"] = fv(f"q{i}", "synthetic")
        rows += [metadata, mail(i, user=None)]
    out = run(burst(), failures + rows)
    assert len(out) == 1 and out[0].proposed_lane == "high"
    assert "account 'alice'" in out[0].claim


def test_attachment_basename_without_dot_is_not_an_extension():
    row = mail(0)
    row.fields["mail.attachment_names"] = fv(["exe", "bash"], "synthetic")
    assert run(rule("mail.executable_attachment"), [row]) == []


def test_site_mail_domains_bind_frozen_configuration_without_changing_old_snapshots():
    from romulus.detect.registry import bind_windows_site
    from romulus.site import COLLECTION_SCHEMA, validate_site_content

    original = validate_site_content({"schema": COLLECTION_SCHEMA})
    assert "mail_domains" not in original.content
    assert validate_site_content(original.content).digest == original.digest
    configured = validate_site_content({"schema": COLLECTION_SCHEMA, "mail_domains": ["INTERNAL.Test."]})
    assert configured.mail_domains == ("internal.test",)
    assert validate_site_content(configured.content).digest == configured.digest
    pb = rule("mail.outbound_burst")
    bind_windows_site([pb], configured)
    assert len(run(pb, [mail(i) for i in range(50)])) == 1


@pytest.mark.parametrize("domains", [["*.test"], ["user@example.test"], ["bad domain"], [""],
                                     ["good.test", "GOOD.TEST"], ["203.0.113.8"], "domain.test"])
def test_site_mail_domains_reject_ambiguous_or_malformed_boundaries(domains):
    from romulus.site import COLLECTION_SCHEMA, SiteValidationError, validate_site_content

    with pytest.raises(SiteValidationError):
        validate_site_content({"schema": COLLECTION_SCHEMA, "mail_domains": domains})


def test_executable_attachment_survives_unavailable_optional_deduplication_state(tmp_path):
    from romulus.detect.bounded import StateBudget

    pb = rule("mail.executable_attachment")
    pb.budget = StateBudget(tmp_path, reserve=0)
    pb.budget.broken = "synthetic unavailable disk"
    row = mail(0)
    row.fields["mail.attachment_names"] = fv(["payload.exe"], "synthetic")
    out = run(pb, [row])
    assert len(out) == 1 and out[0].proposed_lane == "high"


def test_queue_account_join_cites_each_delivery_account_witness():
    rows = []
    for i in range(50):
        metadata = mail(2000+i, seconds=-10, direction="received")
        metadata.fields["mail.message_id"] = fv(f"q{i}", "synthetic")
        rows += [metadata, mail(i, user=None)]
    out = run(burst(), rows)
    assert len(out) == 1
    assert {f"e{2000+i}" for i in range(50)} <= {event.id for event in out[0].events}


def test_malformed_recipient_domain_cannot_be_counted_as_external():
    pb = burst()
    assert run(pb, [mail(i, recipients=[f"r{i}@internal.test>"]) for i in range(50)]) == []
    assert pb.missing_required == 50


@pytest.mark.parametrize("state", ["positive_only", "no_match_complete"])
def test_attachment_coverage_and_catalog_name_the_missing_mta_producer(state):
    from romulus.catalog import CoverageStrength, build_catalog, strength_for_rule
    from romulus.detect.mail import MailExecutableAttachment
    from romulus.report.manifest import _coverage

    pb = MailExecutableAttachment()
    assert run(pb, [mail(1)]) == [] and pb.missing_required == 1
    metadata = build_catalog(playbooks=[MailExecutableAttachment]).rule(pb.id)
    assert strength_for_rule(metadata) is CoverageStrength.POSITIVE_ONLY
    reason = "No parsed MTA log currently supplies attachment names"
    assert reason in metadata.positive_only_reason
    cells = [{"rule_id": pb.id, "target": "mail-logs", "partition": "part", "state": state,
              "evaluated": 0, "matched": 0, "detail": {}}]
    coverage = _coverage(cells, targets=["mail-logs"], rule_ids=[pb.id])
    result = coverage["rules"][0]["search_result"]
    assert "positive-only" in result and reason in result
    assert "searched in full" not in result
