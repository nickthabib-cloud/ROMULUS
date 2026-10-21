"""A relative argv path operand with no recorded working directory cannot be placed.

Audit exec records often carry no CWD record, so `cat shadow` or `tar czf x.tgz .ssh` names a file whose directory
is unknown. Every consumer of argv path operands must count such a record as missing a required field (its coverage
cell is then partial), never treat it as a record that was evaluated and did not match.
"""
from datetime import UTC, datetime

import pytest

from romulus.detect.base import ContextAnchor, ContextLink
from romulus.detect.context import (
    CredentialAccessInContext,
    PostAccessDiscovery,
    PrivilegeProbing,
    StagingAndTransfer,
)
from romulus.detect.hijack import NonRootWriteRootExecutedFile
from romulus.detect.host import AuthorizedKeysWrite, CredentialStoreRead, ScriptFromTempDir
from romulus.detect.linux_argv import read_operand_paths, read_operands
from romulus.evidence.typed import Outcome, RawRef, TypedEvent, fv

T0 = datetime(2024, 11, 18, 14, 0, tzinfo=UTC)


def exec_event(argv, *, cwd=None, uid="1000", event_id="e1"):
    fields = {"process.executable": fv(f"/usr/bin/{argv[0]}", f"{event_id}:exe"),
              "process.argv": fv(argv, f"{event_id}:argv"), "process.session_id": fv(42, f"{event_id}:ses"),
              "process.uid": fv(uid, f"{event_id}:uid"), "process.euid": fv(uid, f"{event_id}:euid"),
              "process.pid": fv(500, f"{event_id}:pid"), "process.ppid": fv(400, f"{event_id}:ppid")}
    if cwd is not None:
        fields["process.cwd"] = fv(cwd, f"{event_id}:cwd")
    return TypedEvent(id=event_id, family="process_exec", ts=T0, host="web1", outcome=Outcome.success,
                      fields=fields, raw=[RawRef(target="host-x", native_id=event_id, digest="d")],
                      normalizer="test@1")


def anchor():
    evidence = exec_event(["sh"], event_id="anchor-event")
    return ContextAnchor(id="F-anchor", anchor_class="web_shell", lane="urgent", claim="a web-service shell",
                         events=[evidence])


def link():
    evidence = exec_event(["sshd"], event_id="link-event")
    return ContextLink(id="L-session", link_type="login_session", strength="observed",
                       key={"host": "web1", "process.session_id": 42}, evidence_events=[evidence],
                       status="complete")


# ---- the operand reader itself -------------------------------------------------------------------------

@pytest.mark.parametrize("name,args,cwd,paths,unresolved", [
    ("cat", ["shadow"], None, [], True),
    ("cat", ["shadow"], "/etc", ["/etc/shadow"], False),
    ("cat", ["/etc/shadow"], None, ["/etc/shadow"], False),
    ("cat", ["-"], None, [], False),                                   # stdin is not a file operand
    ("head", ["-n", "5", "/etc/passwd"], None, ["/etc/passwd"], False),  # the value of -n is not a file
    ("grep", ["root", "passwd"], None, [], True),                      # the pattern is not a file; the file is
    ("grep", ["-e", "root", "/etc/passwd"], None, ["/etc/passwd"], False),
    ("dd", ["if=shadow", "of=/tmp/x"], None, [], True),
    ("cat", ["../etc/shadow"], "/root", ["/etc/shadow"], False),
    ("ls", ["x"], None, [], False),                                    # not a file reader
])
def test_read_operand_paths_reports_unplaceable_operands(name, args, cwd, paths, unresolved):
    assert read_operand_paths(name, args, cwd) == (paths, unresolved)
    assert read_operands(name, args, cwd) == paths


# ---- sweep rules ---------------------------------------------------------------------------------------

def _consume(rule, event):
    matches = rule.consume([event])
    return matches, rule.missing_required


def test_credential_store_read_counts_a_relative_operand_without_cwd_as_missing():
    matches, missing = _consume(CredentialStoreRead(), exec_event(["cat", "shadow"]))
    assert matches == [] and missing == 1


@pytest.mark.parametrize("argv,cwd", [
    (["cat", "/etc/shadow"], None),
    (["cat", "notes.txt"], "/home/u"),
    (["head", "-n", "5", "/etc/hosts"], None),
])
def test_credential_store_read_placed_operands_are_fully_evaluated(argv, cwd):
    _matches, missing = _consume(CredentialStoreRead(), exec_event(argv, cwd=cwd))
    assert missing == 0


@pytest.mark.parametrize("argv,cwd", [
    (["cat", "shadow"], "/etc"),
    (["cat", "./shadow"], "/etc"),
    (["cat", "/etc/../etc/shadow"], None),
    (["head", "-n", "3", "../etc/gshadow"], "/root"),
])
def test_credential_store_read_matches_the_resolved_path(argv, cwd):
    matches, missing = _consume(CredentialStoreRead(), exec_event(argv, cwd=cwd))
    assert len(matches) == 1 and missing == 0
    assert "resolves to /etc/" in matches[0].claim


def test_credential_store_read_still_matches_beside_an_unplaced_operand():
    matches, missing = _consume(CredentialStoreRead(), exec_event(["cat", "notes", "/etc/shadow"]))
    assert len(matches) == 1 and missing == 1


@pytest.mark.parametrize("argv", [["tee", "-a", "authorized_keys"], ["cp", "k.pub", ".ssh/authorized_keys"]])
def test_authorized_keys_write_is_found_from_a_relative_operand(argv):
    """The rule's predicate is the file name, which a relative operand still shows: no CWD is needed."""
    matches, missing = _consume(AuthorizedKeysWrite(), exec_event(argv))
    assert len(matches) == 1 and missing == 0


def test_script_from_temp_dir_counts_a_relative_script_without_cwd_as_missing():
    matches, missing = _consume(ScriptFromTempDir(), exec_event(["bash", "x.sh"]))
    assert matches == [] and missing == 1


def test_root_executed_file_rule_counts_an_unplaced_write_as_missing():
    rule = NonRootWriteRootExecutedFile()
    rule.consume([exec_event(["cp", "payload", "job"])])
    assert rule.missing_required == 1


# ---- context rules -------------------------------------------------------------------------------------

@pytest.mark.parametrize("rule_cls,argv", [
    (CredentialAccessInContext, ["cat", ".ssh/id_rsa"]),
    (PrivilegeProbing, ["cat", "sudoers"]),
    (PostAccessDiscovery, ["cat", "passwd"]),
    (PostAccessDiscovery, ["ls", ".ssh"]),
    (StagingAndTransfer, ["tar", "czf", "/tmp/x.tgz", ".ssh"]),
    (StagingAndTransfer, ["base64", "id_rsa"]),
])
def test_context_rule_counts_a_relative_operand_without_cwd_as_missing(rule_cls, argv):
    rule = rule_cls()
    matches = rule.consume_linked(anchor(), link(), [exec_event(argv)])
    assert matches == [] and rule.missing_required == 1


@pytest.mark.parametrize("rule_cls,argv,cwd", [
    (CredentialAccessInContext, ["cat", ".ssh/id_rsa"], "/root"),
    (PrivilegeProbing, ["cat", "sudoers"], "/etc"),
    (PostAccessDiscovery, ["cat", "passwd"], "/etc"),
    (PostAccessDiscovery, ["ls", ".ssh"], "/root"),
    (StagingAndTransfer, ["tar", "czf", "/tmp/x.tgz", ".ssh"], "/root"),
])
def test_context_rule_matches_the_same_operand_once_the_cwd_places_it(rule_cls, argv, cwd):
    rule = rule_cls()
    matches = rule.consume_linked(anchor(), link(), [exec_event(argv, cwd=cwd)])
    assert len(matches) == 1 and rule.missing_required == 0


@pytest.mark.parametrize("rule_cls,argv", [
    (CredentialAccessInContext, ["cat", "/var/log/syslog"]),
    (PrivilegeProbing, ["cat", "/etc/hosts"]),
    (PostAccessDiscovery, ["cat", "/tmp/notes"]),
    (StagingAndTransfer, ["tar", "czf", "/tmp/x.tgz", "/tmp/build"]),
])
def test_context_rule_absolute_non_matching_operands_are_a_clean_evaluation(rule_cls, argv):
    rule = rule_cls()
    assert rule.consume_linked(anchor(), link(), [exec_event(argv)]) == [] and rule.missing_required == 0
