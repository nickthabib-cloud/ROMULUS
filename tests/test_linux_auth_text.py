"""Synthetic records from vendor log statements; no telemetry-derived fixtures.

Sources (paths are the upstream source, not examples from third-party detectors):
PAM: https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/support.c
     https://github.com/linux-pam/linux-pam/blob/master/modules/pam_unix/pam_unix_sess.c
logind: https://github.com/systemd/systemd/blob/main/src/login/logind-session.c
Dovecot: https://doc.dovecot.org/2.4.1/howto/fail2ban.html
         https://github.com/dovecot/core/blob/main/src/login-common/client-common.c
Postfix: https://github.com/vdukhovni/postfix/blob/master/postfix/src/smtpd/smtpd_sasl_glue.c
Exim: https://www.exim.org/exim-html-current/doc/html/spec_html/ch-log_files.html
      https://github.com/Exim/exim/blob/master/src/src/smtp_in.c
Cyrus: https://github.com/cyrusimap/cyrus-imapd/blob/master/docsrc/reference/manpages/systemcommands/cyr_dbtool.rst
VPN: https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_verify.c
     https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/plugin.c
     https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/multi.c
IKE: https://docs.strongswan.org/docs/latest/interop/windowsEapServerStatus.html
PPP: https://github.com/ppp-project/ppp/blob/master/pppd/upap.c
     https://github.com/ppp-project/ppp/blob/master/pppd/chap.c
FTP: https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz (logging.c:263-343)
     https://github.com/proftpd/proftpd/blob/master/modules/mod_auth.c
SMB: https://github.com/samba-team/samba/blob/master/source3/auth/auth.c
DB: https://github.com/mysql/mysql-server/blob/trunk/share/messages_to_clients.txt
    https://github.com/postgres/postgres/blob/master/src/backend/libpq/auth.c
Roundcube: program/include/rcmail.php, tag 1.6.9, lines 1536 and 1548:
https://github.com/roundcube/roundcubemail/blob/1.6.9/program/include/rcmail.php#L1536
Horde: login.php, FRAMEWORK_5_2, lines 158 and 193 (read from GitHub API):
https://github.com/horde/base/blob/FRAMEWORK_5_2/login.php#L158
https://github.com/horde/base/blob/FRAMEWORK_5_2/login.php#L193
Logger envelopes:
https://github.com/roundcube/roundcubemail/blob/1.6.9/program/lib/Roundcube/rcube.php#L1328
https://github.com/horde/Core/blob/FRAMEWORK_5_2/lib/Horde/Core/Log/Object.php
SASL: https://github.com/cyrusimap/cyrus-sasl/blob/master/saslauthd/saslauthd-main.c#L426
https://github.com/cyrusimap/cyrus-sasl/blob/master/saslauthd/utils.c#L83
IKE failures:
https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/authenticators/eap_authenticator.c#L749
https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/authenticators/psk_authenticator.c#L190
ProFTPD envelopes: https://github.com/proftpd/proftpd/blob/master/src/log.c#L491
"""
from __future__ import annotations

import pytest

from romulus.evidence.linux_auth_text import identify_auth, parse_auth
from romulus.evidence.typed import Outcome

# Changing a decision prefix, confusing a lifecycle for login, losing a typed
# peer, or reading a result phrase out of the user field breaks these assertions.
CASES = [
    ("login", ("pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 "
     "tty=tty1 ruser= rhost=2001:db8::10  user=alice"), "failure",
     {"auth.service": "login", "auth.method": "pam_unix", "user.name": "alice",
      "source.ip": "2001:db8::10"}),
    ("su", "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)",
     "success", {"auth.service": "su", "auth.phase": "session_open", "user.name": "root"}),
    ("CRON", "pam_unix(cron:session): session closed for user alice", "success",
     {"auth.service": "cron", "auth.phase": "session_close", "user.name": "alice"}),
    ("systemd-logind", "New session 42 of user alice.", "success",
     {"auth.phase": "session_open", "user.name": "alice"}),
    ("systemd-logind", "Removed session 42.", "success", {"auth.phase": "session_close"}),
    ("dovecot", ("imap-login: Login: user=<alice>, method=PLAIN, rip=2001:db8::10, "
     "lip=2001:db8::20, mpid=17, TLS, session=<s1>"), "success",
     {"auth.service": "dovecot", "auth.method": "PLAIN", "user.name": "alice",
      "source.ip": "2001:db8::10", "destination.ip": "2001:db8::20"}),
    ("dovecot", ("pop3-login: Aborted login (auth failed, 1 attempts in 2 secs): "
     "user=<alice>, method=PLAIN, rip=192.0.2.1, lip=192.0.2.2"), "failure",
     {"auth.service": "dovecot", "user.name": "alice", "source.ip": "192.0.2.1"}),
    ("dovecot", ("imap-login: Disconnected (auth failed, 2 attempts in 4 secs): "
     "user=<alice>, method=LOGIN, rip=192.0.2.1"), "failure", {"auth.method": "LOGIN"}),
    ("dovecot", ("imap-login: Disconnected: Connection closed (auth failed, 2 attempts in 4 secs): "
     "user=<alice>, method=PLAIN, rip=192.0.2.1"), "failure", {"user.name": "alice"}),
    ("postfix/smtpd", ("warning: client.example[2001:db8::10]: SASL LOGIN authentication failed: "
     "authentication failure, sasl_username=alice"), "failure",
     {"auth.service": "postfix", "auth.method": "LOGIN", "source.ip": "2001:db8::10",
      "user.name": "alice"}),
    ("exim", ("plain authenticator failed for client.example [2001:db8::10]:45001: "
     "535 Incorrect authentication data (set_id=alice)"), "failure",
     {"auth.method": "plain", "source.ip": "2001:db8::10", "source.port": 45001,
      "user.name": "alice"}),
    ("exim4", ("1abcde-000001-AB <= sender@example.test H=client.example [192.0.2.1] "
     "P=esmtpsa A=plain:alice S=1234 id=example"), "success",
     {"auth.service": "exim", "auth.method": "plain", "user.name": "alice",
      "source.ip": "192.0.2.1"}),
    ("cyrus/imap", ("badlogin: client.example [2001:db8::10] plaintext alice "
     "SASL(-13): authentication failure: checkpass failed"), "failure",
     {"auth.service": "cyrus", "user.name": "alice", "source.ip": "2001:db8::10",
      "auth.method": "plaintext"}),
    ("openvpn", "192.0.2.1:45001 TLS Auth Error: Auth Username/Password verification failed for peer",
     "failure", {"auth.service": "openvpn", "source.ip": "192.0.2.1", "source.port": 45001}),
    ("openvpn", "AUTH: Received control message: AUTH_FAILED", "failure", {}),
    ("openvpn", "TLS: Username/Password authentication succeeded for username 'alice' [CN SET]",
     "success", {"user.name": "alice", "auth.method": "password"}),
    ("openvpn", "PLUGIN_CALL: plugin function PLUGIN_AUTH_USER_PASS_VERIFY failed with status 1: /etc/auth.so",
     "failure", {"auth.method": "plugin"}),
    ("openvpn", ("WARNING: Failed running command (--auth-user-pass-verify): external program exited "
     "with error status: 1"), "failure", {"auth.method": "script"}),
    ("charon", "07[IKE] authentication of 'alice' with EAP successful", "success",
     {"auth.service": "charon", "user.name": "alice", "auth.method": "EAP"}),
    ("pppd", "PAP peer authentication succeeded for alice", "success",
     {"auth.service": "pppd", "auth.method": "PAP", "user.name": "alice"}),
    ("pppd", "PAP peer authentication failed for alice", "failure", {"user.name": "alice"}),
    ("pppd", "CHAP authentication succeeded", "success", {"auth.method": "CHAP"}),
    ("pppd", 'Peer alice failed CHAP authentication', "failure", {"user.name": "alice"}),
    ("vsftpd", '[pid 7] [alice] OK LOGIN: Client "2001:db8::10"', "success",
     {"auth.service": "vsftpd", "user.name": "alice", "source.ip": "2001:db8::10"}),
    ("vsftpd", '[pid 7] [alice] FAIL LOGIN: Client "192.0.2.1"', "failure", {"user.name": "alice"}),
    ("proftpd", "USER alice: Login successful.", "success",
     {"auth.service": "proftpd", "user.name": "alice"}),
    ("proftpd", "USER alice: no such user found from client.example [2001:db8::10] to 192.0.2.2:21",
     "failure", {"user.name": "alice", "auth.user_valid": False, "source.ip": "2001:db8::10"}),
    ("smbd", ("check_ntlm_password:  Authentication for user [alice] -> [alice] FAILED "
     "with error NT_STATUS_WRONG_PASSWORD, authoritative=1"), "failure",
     {"auth.service": "samba", "user.name": "alice", "auth.method": "NTLM"}),
    ("mysqld", "Access denied for user 'alice'@'2001:db8::10' (using password: YES)", "failure",
     {"auth.service": "mysql", "auth.method": "password", "user.name": "alice",
      "source.ip": "2001:db8::10"}),
    ("mariadbd", "Access denied for user 'alice'@'client.example' (using password: NO)", "failure",
     {"auth.service": "mysql", "user.name": "alice"}),
    ("postgres", 'FATAL:  password authentication failed for user "alice"', "failure",
     {"auth.service": "postgresql", "user.name": "alice", "auth.method": "password"}),
    ("roundcube", "Failed login for alice from 2001:db8::10 in session abcdef (error: 0)",
     "failure", {"auth.service": "roundcube", "user.name": "alice", "source.ip": "2001:db8::10"}),
    ("roundcube", "Successful login for alice (ID: 7) from 192.0.2.1 in session abcdef", "success",
     {"user.name": "alice", "source.ip": "192.0.2.1"}),
    ("HORDE", "[horde] FAILED LOGIN for alice to horde (2001:db8::10)", "failure",
     {"auth.service": "horde", "user.name": "alice", "source.ip": "2001:db8::10"}),
    ("horde", "Login success for alice to horde (192.0.2.1)", "success", {"user.name": "alice"}),
]


@pytest.mark.parametrize("program,message,outcome,fields", CASES)
def test_source_documented_auth_records(program, message, outcome, fields):
    event = parse_auth(program, message)
    assert event is not None
    assert event.family == "auth"
    assert event.outcome == Outcome(outcome)
    assert event.fields["auth.phase"] == fields.get("auth.phase", "authentication")
    assert all(event.fields.get(key) == value for key, value in fields.items())


@pytest.mark.parametrize("program,message,outcome,fields", CASES)
def test_quoted_or_debug_mentions_are_not_actions(program, message, outcome, fields):
    assert parse_auth(program, "debug: quoted message: " + message) is None
    assert parse_auth("unrelated-app", message) is None or message.startswith("pam_unix(")


@pytest.mark.parametrize("program,message", [
    ("dovecot", ("imap-login: Disconnected (auth failed, 1 attempts): "
     "user=<Login: authentication succeeded>, method=PLAIN, rip=2001:db8::10")),
    ("postfix/smtpd", ("warning: unknown[192.0.2.1]: SASL PLAIN authentication failed: "
     "generic failure, sasl_username=Successful login for alice")),
    ("exim", ("plain authenticator failed for [192.0.2.1]: 535 Incorrect authentication data "
     "(set_id=A=plain:Login successful)")),
    ("cyrus/imap", "badlogin: host [192.0.2.1] plaintext successful SASL(-13): authentication failure"),
    ("pppd", "PAP peer authentication failed for authentication succeeded"),
    ("vsftpd", '[pid 7] [OK LOGIN: alice] FAIL LOGIN: Client "192.0.2.1"'),
    ("proftpd", "USER Login successful.: no such user found from host [192.0.2.1] to 192.0.2.2:21"),
    ("smbd", ("check_ntlm_password:  Authentication for user [succeeded] -> [succeeded] "
     "FAILED with error NT_STATUS_LOGON_FAILURE, authoritative=1")),
    ("mysqld", "Access denied for user 'Successful login'@'192.0.2.1' (using password: YES)"),
    ("postgres", 'password authentication failed for user "Login successful"'),
    ("roundcube", "Failed login for Successful login for alice from 192.0.2.1 in session s (error: 0)"),
    ("horde", "FAILED LOGIN for Login success for alice to horde (192.0.2.1)"),
])
def test_usernames_cannot_change_failure_outcome(program, message):
    event = parse_auth(program, message)
    assert event is not None
    assert event.outcome == Outcome.failure


@pytest.mark.parametrize("program,message,absent", [
    ("dovecot", "imap-login: Login: user=<>, method=PLAIN", {"source.ip", "user.name"}),
    ("postfix/smtpd", "warning: unknown[192.0.2.1]: SASL PLAIN authentication failed: failure",
     {"user.name", "auth.user_valid"}),
    ("openvpn", "AUTH: Received control message: AUTH_FAILED", {"source.ip", "user.name"}),
    ("pppd", "CHAP authentication failed", {"source.ip", "user.name"}),
    ("postgres", 'password authentication failed for user "alice"', {"source.ip", "auth.user_valid"}),
    ("mysqld", "Access denied for user 'alice'@'host.example' (using password: YES)", {"source.ip"}),
])
def test_missing_fields_stay_missing(program, message, absent):
    event = parse_auth(program, message)
    assert event is not None
    assert absent.isdisjoint(event.fields)


@pytest.mark.parametrize("program,message", [
    ("sshd", "Accepted password for alice from 192.0.2.1 port 22 ssh2"),
    ("dovecot", "imap-login: Disconnected (no auth attempts): user=<auth failed>, rip=192.0.2.1"),
    ("mysqld", "Access denied for user 'alice'@'192.0.2.1' to database 'secret'"),
    ("proftpd", "USER alice: Login successful. extra injected text"),
    ("smbd", "file alice NT_STATUS_WRONG_PASSWORD"),
    ("roundcube", "Failed login for alice from 192.0.2.1"),
    ("horde", "FAILED LOGIN for alice [192.0.2.1]"),
    ("openvpn", "PLUGIN_CALL: plugin function PLUGIN_CLIENT_DISCONNECT failed with status 1: /plugin.so"),
    ("charon", "07[IKE] authentication of 'vpn.example' (myself) with EAP successful"),
])
def test_unsupported_or_non_authentication_shapes_are_not_typed(program, message):
    assert parse_auth(program, message) is None


@pytest.mark.parametrize("program,message", [
    ("roundcube", ("Failed login for x from 192.0.2.77 in session fake (error: 0) from "
     "2001:db8::10 in session real (error: 0)")),
    ("horde", "FAILED LOGIN for x to horde (192.0.2.77) to horde (2001:db8::10)"),
])
def test_user_delimiter_injection_does_not_replace_the_real_peer(program, message):
    event = parse_auth(program, message)
    assert event is not None
    assert event.outcome == Outcome.failure
    assert event.fields.get("source.ip") == "2001:db8::10"


def test_dovecot_delimiter_injection_is_honestly_partial():
    event = parse_auth("dovecot", "imap-login: Login: user=<x>, rip=192.0.2.77>, "
                       "method=PLAIN, rip=2001:db8::10")
    assert event is not None
    assert "user.name" not in event.fields
    assert event.caveats


def test_invalid_ip_is_not_a_typed_peer():
    event = parse_auth("mysqld", "Access denied for user 'alice'@'999.1.1.1' (using password: YES)")
    assert event is not None
    assert "source.ip" not in event.fields


def test_parser_rejects_multiline_and_oversized_records():
    assert parse_auth("openvpn", "AUTH_FAILED\nAUTH_FAILED") is None
    assert parse_auth("openvpn", "AUTH_FAILED" + " " * 65536) is None


@pytest.mark.parametrize("line,program", [
    ('Mon Nov  9 10:20:30 2026 [pid 7] [alice] OK LOGIN: Client "192.0.2.1"', "vsftpd"),
    ('Nov 09 10:20:30 imap-login: Info: Login: user=<alice>, method=PLAIN, rip=192.0.2.1', "dovecot"),
    ('2026-11-09 10:20:30 AUTH: Received control message: AUTH_FAILED', "openvpn"),
    ('Mon Nov  9 10:20:30 2026 AUTH: Received control message: AUTH_FAILED', "openvpn"),
])
def test_fixed_application_envelopes(line, program):
    identified = identify_auth(line)
    assert identified is not None
    assert identified[0] == program
    assert parse_auth(*identified) is not None


def test_no_sniffing_of_arbitrary_embedded_auth_text():
    assert identify_auth("an arbitrary application says AUTH_FAILED") is None
    assert identify_auth('note: [pid 7] [alice] OK LOGIN: Client "192.0.2.1"') is None


@pytest.mark.parametrize("program,message,outcome,fields", [
    ("systemd-logind", "New session '42' of user 'alice' with class 'user' and type 'tty'.", "success",
     {"auth.phase": "session_open", "user.name": "alice"}),
    ("charon", "07[IKE] received EAP_FAILURE, EAP authentication failed", "failure", {"auth.method": "EAP"}),
    ("charon", "07[IKE] tried 1 shared key for 'gateway' - 'alice', but MAC mismatched", "failure",
     {"auth.method": "pre-shared key", "user.name": "alice"}),
    ("saslauthd", ("do_auth         : auth failure: [user=alice] [service=imap] [realm=] "
     "[remote=2001:db8::10] [mech=pam] [reason=bad password]"), "failure",
     {"auth.service": "saslauthd", "auth.method": "pam", "user.name": "alice", "source.ip": "2001:db8::10"}),
    ("saslauthd", ("do_auth         : auth success: [user=alice] [service=imap] [realm=] "
     "[remote=192.0.2.1] [mech=pam]"), "success", {"user.name": "alice"}),
    ("smbd", "check_ntlm_password:  authentication for user [alice] -> [alice] -> [alice] succeeded",
     "success", {"auth.service": "samba", "user.name": "alice"}),
    ("vsftpd", '[pid 7] FAIL LOGIN: Client "192.0.2.1"', "failure", {"source.ip": "192.0.2.1"}),
    ("proftpd", "ftp.example (peer.example[2001:db8::10]): USER alice: Login successful.", "success",
     {"user.name": "alice", "source.ip": "2001:db8::10"}),
    ("proftpd", "USER alice (Login failed): Incorrect password", "failure", {"user.name": "alice"}),
    ("openvpn", ("[AF_INET6][2001:db8::10]:45001 TLS Auth Error: Auth Username/Password "
     "verification failed for peer"), "failure", {"source.ip": "2001:db8::10", "source.port": 45001}),
])
def test_additional_vendor_statement_variants(program, message, outcome, fields):
    event = parse_auth(program, message)
    assert event is not None
    assert event.outcome == Outcome(outcome)
    assert all(event.fields.get(key) == value for key, value in fields.items())
    assert parse_auth(program, "debug: " + message) is None


@pytest.mark.parametrize("metadata", [
    'H=(fake A=plain:intruder S=123) [192.0.2.1] P=esmtp S=123',
    'H=client [192.0.2.1] P=esmtp S=123 T="A=plain:intruder"',
    'H=client [192.0.2.1] P=esmtpsa S=123 T="A=plain:intruder"',
    'H=(fake P=esmtpsa A=plain:intruder S=123) [192.0.2.1] P=esmtp S=123',
])
def test_exim_untrusted_helo_and_subject_do_not_assert_authenticated_sender(metadata):
    assert parse_auth("exim", "1abcde-000001-AB <= sender@example.test " + metadata) is None


def test_sasl_user_injection_cannot_create_a_success():
    event = parse_auth("saslauthd", "do_auth         : auth failure: [user=auth success] [service=imap] "
                       "[realm=] [remote=2001:db8::10] [mech=pam] [reason=bad password]")
    assert event is not None
    assert event.outcome == Outcome.failure


def test_proftpd_native_file_envelope():
    identified = identify_auth("2026-11-09 10:20:30,123 ftp.example proftpd[7] "
                               "ftp.example (peer.example[2001:db8::10]): USER alice: Login successful.")
    assert identified is not None
    assert parse_auth(*identified).fields["source.ip"] == "2001:db8::10"


def test_surrogate_text_does_not_crash_parser():
    assert parse_auth("unknown", "\ud800") is None


def test_long_delimiter_rich_username_is_retained_without_searching_for_actions():
    user = "a by b: no such user found from " * 1500
    event = parse_auth("proftpd", "USER " + user + ": Login successful.")
    assert event is not None
    assert event.fields["user.name"] == user


@pytest.mark.parametrize("program,message", [
    ("roundcube", "<a1b2c3d4> Failed login for alice from 192.0.2.1 in session a1b2c3d4 (error: 0)"),
    ("roundcube", "userlogins: <a1b2c3d4> Failed login for alice from 192.0.2.1 in session s (error: 0)"),
    ("horde", '[horde] FAILED LOGIN for alice to horde (192.0.2.1) [pid 17 on line 193 of "/srv/login.php"]'),
    ("horde", '[horde] FAILED LOGIN for alice to horde (192.0.2.1) [pid 17]'),
])
def test_application_logger_decorations(program, message):
    event = parse_auth(program, message)
    assert event is not None
    assert event.fields["user.name"] == "alice"
    assert event.outcome == Outcome.failure


def test_roundcube_default_file_envelope():
    identified = identify_auth("[09-Nov-2026 10:20:30 +0000]: <a1b2c3d4> Failed login for alice "
                               "from 2001:db8::10 in session s (error: 0)")
    assert identified is not None
    assert identified[0] == "roundcube"
    assert parse_auth(*identified).fields["source.ip"] == "2001:db8::10"


@pytest.mark.parametrize("program,message,outcome,fields", CASES)
def test_incomplete_record_never_guesses_a_missing_peer(program, message, outcome, fields):
    # Depending on the grammar this is either a recognized record with no peer,
    # or a counted skip at the caller; it must never fabricate an address.
    for address in ("2001:db8::10", "2001:db8::20", "192.0.2.1", "192.0.2.2"):
        message = message.replace(address, "")
    event = parse_auth(program, message)
    assert event is None or "source.ip" not in event.fields
