"""Credentials inside the free text Zeek's logs keep: SQL statements, Redis replies, URIs, SIP URIs and IRC rows.

Only the credential is redacted and the rest of the text kept, so what a command did stays visible (a backdoor user's
name, a CONFIG GET of the data directory); a value that can carry a credential but cannot be read is withheld and
flagged as possibly one. Every scan is linear in its text: an adversarial 256 KB value is read in well under 50 ms.
"""
import json
import random
import re
import time

import pytest

from romulus.evidence import certificates, zeek, zeek_catalog, zeek_credentials
from romulus.evidence.normalize import normalize_hits
from romulus.evidence.zeek import ZEEK_IRC_STALE, normalize_plain_zeek
from romulus.evidence.zeek_credentials import (
    REDACTED,
    REDIS_UNREAD,
    SQL_TOKEN_BUDGET,
    SQL_UNREAD,
    scrub_redis_reply,
    scrub_sql,
    strip_sip_password,
    strip_uri_userinfo,
)
from tests.fixtures import zeek_logs as zl

R = REDACTED
S = zl.SECRET


def normalize(h):
    if h["_index"] == zl.INDEX["plain"]:
        return normalize_plain_zeek(h, sensor=zl.SENSOR)
    events, skips, errors = normalize_hits([h])
    assert (skips, errors) == ({}, []) and len(events) == 1
    return events[0]


# ---- SQL -----------------------------------------------------------------------------------------------------------

# (statement, what it reads as after redaction, what is found: a password redacted ("present"), text withheld unread
# ("unread"), "both", or None)
SQL_CASES = [
    # IDENTIFIED [WITH <plugin>] BY|AS, and the current password a REPLACE names
    ("ALTER USER 'root'@'localhost' IDENTIFIED BY 'p4ss'", f"ALTER USER 'root'@'localhost' IDENTIFIED BY {R}",
     "present"),
    ("CREATE USER 'svc'@'%' IDENTIFIED WITH mysql_native_password BY 'p4ss'",
     f"CREATE USER 'svc'@'%' IDENTIFIED WITH mysql_native_password BY {R}", "present"),
    ("CREATE USER 'svc'@'%' IDENTIFIED WITH 'caching_sha2_password' AS '$A$005$abc'",
     f"CREATE USER 'svc'@'%' IDENTIFIED WITH 'caching_sha2_password' AS {R}", "present"),
    ("GRANT USAGE ON *.* TO 'svc'@'%' IDENTIFIED BY PASSWORD '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'",
     f"GRANT USAGE ON *.* TO 'svc'@'%' IDENTIFIED BY PASSWORD {R}", "present"),
    ("ALTER USER svc IDENTIFIED BY 'new' REPLACE 'old' RETAIN CURRENT PASSWORD",
     f"ALTER USER svc IDENTIFIED BY {R} REPLACE {R} RETAIN CURRENT PASSWORD", "present"),
    ("ALTER USER svc IDENTIFIED BY RANDOM PASSWORD", "ALTER USER svc IDENTIFIED BY RANDOM PASSWORD", None),
    # [ENCRYPTED] PASSWORD, PASSWORD(), OLD_PASSWORD(), PASSWORD =, PASSWORD FOR, *_PASSWORD=
    ("CREATE ROLE svc LOGIN SUPERUSER PASSWORD 'p4ss'", f"CREATE ROLE svc LOGIN SUPERUSER PASSWORD {R}", "present"),
    ("ALTER ROLE svc WITH ENCRYPTED PASSWORD 'SCRAM-SHA-256$4096:abc'", f"ALTER ROLE svc WITH ENCRYPTED PASSWORD {R}",
     "present"),
    ("SET PASSWORD FOR 'root'@'localhost' = PASSWORD('p4ss')", f"SET PASSWORD FOR 'root'@'localhost' = PASSWORD({R})",
     "present"),
    ("SET PASSWORD FOR 'root'@'localhost' = 'p4ss'", f"SET PASSWORD FOR 'root'@'localhost' = {R}", "present"),
    ("SET PASSWORD = OLD_PASSWORD('p4ss')", f"SET PASSWORD = OLD_PASSWORD({R})", "present"),
    ("SET PASSWORD = 'p4ss'", f"SET PASSWORD = {R}", "present"),
    ("CHANGE MASTER TO MASTER_HOST='203.0.113.9', MASTER_PASSWORD='p4ss'",
     f"CHANGE MASTER TO MASTER_HOST='203.0.113.9', MASTER_PASSWORD={R}", "present"),
    ("START REPLICA USER='repl' PASSWORD='p4ss'", f"START REPLICA USER='repl' PASSWORD={R}", "present"),
    ("CREATE SERVER s FOREIGN DATA WRAPPER mysql OPTIONS (USER 'u', PASSWORD 'p4ss', HOST '192.0.2.4')",
     f"CREATE SERVER s FOREIGN DATA WRAPPER mysql OPTIONS (USER 'u', PASSWORD {R}, HOST '192.0.2.4')", "present"),
    # comparisons and assignments of a column whose name holds "pass", or authentication_string, either side
    ("SELECT * FROM users WHERE password = 'P@ssw0rd!'", f"SELECT * FROM users WHERE password = {R}", "present"),
    ("SELECT * FROM users WHERE u.passwd <> 'x' AND name = 'bob'",
     f"SELECT * FROM users WHERE u.passwd <> {R} AND name = 'bob'", "present"),
    ("SELECT * FROM users WHERE 'p4ss' = password", f"SELECT * FROM users WHERE {R} = password", "present"),
    ("SELECT * FROM users WHERE password IN ('a', 'b', 3)", f"SELECT * FROM users WHERE password IN ({R}, {R}, {R})",
     "present"),
    ("SELECT * FROM users WHERE password NOT LIKE 'adm%'", f"SELECT * FROM users WHERE password NOT LIKE {R}",
     "present"),
    ("UPDATE users SET password_hash = '$2b$12$abc' WHERE id = 1",
     f"UPDATE users SET password_hash = {R} WHERE id = 1", "present"),
    ("UPDATE mysql.user SET authentication_string = 'hash' WHERE user = 'root'",
     f"UPDATE mysql.user SET authentication_string = {R} WHERE user = 'root'", "present"),
    ("UPDATE users SET password = crypt('p4ss', gen_salt('bf')) WHERE id = 1",
     f"UPDATE users SET password = crypt({R}, gen_salt({R})) WHERE id = 1", "present"),
    # literal forms: '' and \' escapes, "...", dollar quoting, X'', 0x, prefixes, and a bare (unquoted) token
    ("ALTER ROLE svc PASSWORD 'it''s'", f"ALTER ROLE svc PASSWORD {R}", "present"),
    ("ALTER ROLE svc PASSWORD E'it\\'s'", f"ALTER ROLE svc PASSWORD {R}", "present"),
    ('SET PASSWORD = "p4ss"', f"SET PASSWORD = {R}", "present"),
    ("ALTER ROLE svc PASSWORD $$p4ss$$", f"ALTER ROLE svc PASSWORD {R}", "present"),
    ("ALTER ROLE svc PASSWORD $q$p4$$ss$q$", f"ALTER ROLE svc PASSWORD {R}", "present"),
    ("SELECT * FROM t WHERE password = X'70347373'", f"SELECT * FROM t WHERE password = {R}", "present"),
    ("SELECT * FROM t WHERE password = 0x70347373", f"SELECT * FROM t WHERE password = {R}", "present"),
    ("SELECT * FROM t WHERE password = _utf8mb4'p4ss'", f"SELECT * FROM t WHERE password = {R}", "present"),
    ("CREATE USER 'svc'@'%' IDENTIFIED BY Hunter2-unquoted", f"CREATE USER 'svc'@'%' IDENTIFIED BY {R}", "present"),
    # INSERT and REPLACE: the password column's position in each VALUES row
    ("INSERT INTO users (name, password) VALUES ('bob', 'p4ss'), ('al', 'p5ss')",
     f"INSERT INTO users (name, password) VALUES ('bob', {R}), ('al', {R})", "present"),
    ("REPLACE INTO users (password, name) VALUES (PASSWORD('p4ss'), 'bob')",
     f"REPLACE INTO users (password, name) VALUES (PASSWORD({R}), 'bob')", "present"),
    ("INSERT INTO users (name, password) VALUES ('bob', 'p4ss') ON DUPLICATE KEY UPDATE password = 'p5ss'",
     f"INSERT INTO users (name, password) VALUES ('bob', {R}) ON DUPLICATE KEY UPDATE password = {R}", "present"),
    # a row that does not match its columns: every literal of the VALUES
    ("INSERT INTO users (name, password) VALUES ('bob', 'p4ss', 'extra')",
     f"INSERT INTO users (name, password) VALUES ({R}, {R}, {R})", "both"),
    # no column list in a statement that names a password: every VALUES literal
    ("INSERT INTO passwords VALUES ('svc', 'p4ss')", f"INSERT INTO passwords VALUES ({R}, {R})", "both"),
    # a value written as a concatenation, whole
    ("SELECT * FROM users WHERE password = 'p4' || 'ss'", f"SELECT * FROM users WHERE password = {R} || {R}",
     "present"),
    ("SELECT * FROM users WHERE password = 'p4' 'ss' AND id = 1",
     f"SELECT * FROM users WHERE password = {R} {R} AND id = 1", "present"),
    ("UPDATE users SET password = 'p4ss', email = 'ops@example.test' WHERE id = 1",
     f"UPDATE users SET password = {R}, email = 'ops@example.test' WHERE id = 1", "present"),
    # credential positions inside a comment, and a comment joining a column's name
    ("SELECT 1 /* password = 'p4ss' */", f"SELECT 1 /* password = {R} */", "present"),
    ("SELECT * FROM users WHERE name = 'a' -- AND password = 'p4ss'",
     f"SELECT * FROM users WHERE name = 'a' -- AND password = {R}", "present"),
    ("SELECT * FROM users WHERE password = /* c */ 'p4ss'", f"SELECT * FROM users WHERE password = /* c */ {R}",
     "present"),
    ("SELECT * FROM users WHERE pass/**/word = 'p4ss'", f"SELECT * FROM users WHERE pass/**/word = {R}", "present"),
    # a connection string's password inside a literal
    ("SELECT dblink_connect('host=192.0.2.5 user=app password=p4ss dbname=inventory')",
     f"SELECT dblink_connect('host=192.0.2.5 user=app password={R}')", "present"),
    # an unterminated quote: to the end
    ("ALTER USER svc IDENTIFIED BY 'p4ss", f"ALTER USER svc IDENTIFIED BY {R}", "present"),
    ("SELECT 'abc FROM t WHERE password = 'x'", f"SELECT 'abc FROM t WHERE password{R}", "unread"),
    ("SELECT * FROM users WHERE password = 'it's x'", f"SELECT * FROM users WHERE password = {R}", "both"),
    # placeholders and variables are not values: nothing redacted, nothing flagged
    ("SELECT * FROM accounts WHERE password = $1", "SELECT * FROM accounts WHERE password = $1", None),
    ("SELECT * FROM accounts WHERE password = ?", "SELECT * FROM accounts WHERE password = ?", None),
    ("SELECT * FROM accounts WHERE password = :pw", "SELECT * FROM accounts WHERE password = :pw", None),
    ("SET PASSWORD = @new_password", "SET PASSWORD = @new_password", None),
    ("INSERT INTO users (name, password) VALUES (?, ?)", "INSERT INTO users (name, password) VALUES (?, ?)", None),
    ("ALTER ROLE svc PASSWORD NULL", "ALTER ROLE svc PASSWORD NULL", None),
    # an empty literal carries nothing
    ("SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
     "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'", None),
]
# statements that name a password column or table but set or compare none: kept byte for byte, nothing flagged
DUMPING = [
    "SELECT user, password FROM mysql.user",
    "SELECT user, authentication_string, plugin FROM mysql.user",
    "SELECT usename, passwd FROM pg_shadow",
    "SELECT rolname, rolpassword FROM pg_authid WHERE rolcanlogin",
    "SELECT * FROM users ORDER BY password DESC",
    "SELECT password AS pw, COUNT(*) FROM users GROUP BY password",
    "SELECT * FROM users WHERE password IS NULL",
    # an INSERT that names no columns, in a statement that names no password: nothing says which value is one (a
    # limit of reading only statements that name a password)
    "INSERT INTO users VALUES ('bob', 'not-a-named-column')",
    "SELECT 1 /* a comment naming no credential: it's kept */",
    "INSERT INTO audit (event, detail) VALUES ('login', 'password reset requested')",
    "GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION",
    "SELECT * FROM t INTO OUTFILE '/var/www/html/s.php'",
    "COPY t FROM PROGRAM 'gzip -dc /tmp/dump.gz'",
    "SELECT 1",
    "SHOW GRANTS FOR 'root'@'localhost'",
]


@pytest.mark.parametrize("statement,expected,flag", SQL_CASES, ids=[c[0][:60] for c in SQL_CASES])
def test_a_statement_keeps_everything_but_its_password_literals(statement, expected, flag):
    result = scrub_sql(statement)
    assert result.text == expected
    assert result.redacted is (flag in ("present", "both"))
    assert result.unread is (flag in ("unread", "both"))
    assert (SQL_UNREAD in result.caveats) is result.unread


@pytest.mark.parametrize("statement", DUMPING)
def test_a_statement_that_sets_and_compares_no_password_is_kept_byte_for_byte(statement):
    result = scrub_sql(statement)
    assert result.text == statement and not result.redacted and not result.unread
    for shape, h in zl.in_every_shape(zl.MYSQL.with_(arg=statement), "dump-").items():
        event = normalize(h)
        assert event.get("app.arg") == statement, shape
        assert not event.has("auth.cleartext_credentials_present"), shape
        assert not event.has("auth.cleartext_credentials_unknown"), shape


def test_a_redacted_statement_is_typed_in_every_shape_with_its_derivation_and_flag():
    statement = f"CREATE USER 'backdoor'@'%' IDENTIFIED BY '{S}'"
    for log, row in (("mysql", zl.MYSQL.with_(arg=statement)),
                     ("postgresql", zl.POSTGRESQL.with_(frontend_arg=statement))):
        for shape, h in zl.in_every_shape(row, f"sql-{log}-").items():
            event = normalize(h)
            assert event.get("app.arg") == f"CREATE USER 'backdoor'@'%' IDENTIFIED BY {R}", (log, shape)
            assert event.fields["app.arg"].origin.endswith("#derived:credentials-redacted"), (log, shape)
            assert event.get("auth.cleartext_credentials_present") is True, (log, shape)
            assert event.fields["auth.cleartext_credentials_present"].origin.endswith("#sql-credential#present")
            assert S not in event.model_dump_json(), (log, shape)


def test_the_servers_echo_of_a_redacted_password_is_redacted_too():
    """An unquoted password is a syntax error, and MySQL's error quotes the text near it."""
    row = zl.MYSQL.with_(arg=f"CREATE USER 'svc'@'%' IDENTIFIED BY {S}", success=False,
                         response=f"You have an error in your SQL syntax; ... near '{S}' at line 1")
    event = normalize(zl.plain(row, "echo"))
    assert event.get("app.reply") == f"You have an error in your SQL syntax; ... near '{R}' at line 1"
    assert S not in event.model_dump_json()
    # a password holding a quote the client did not escape ends the literal early; what follows is the password's
    # rest, so the statement is withheld from there, and the echo of a statement not read whole is withheld
    unread = zl.MYSQL.with_(arg=f"SELECT * FROM users WHERE password = 'it's {S}'", success=False,
                            response=f"... near 's {S}'' at line 1")
    event = normalize(zl.plain(unread, "echo-unread"))
    assert event.get("app.arg") == f"SELECT * FROM users WHERE password = {R}"
    assert not event.has("app.reply") and S not in event.model_dump_json()
    assert event.get("auth.cleartext_credentials_present") is True and SQL_UNREAD in event.caveats


def test_a_statement_longer_than_the_token_budget_is_withheld_after_its_first_credential_cue():
    statement = "INSERT INTO users (name, password) VALUES " + ", ".join(["('bob', 'p4ss')"] * SQL_TOKEN_BUDGET)
    result = scrub_sql(statement)
    assert result.text == f"INSERT INTO users (name, password{R}" and result.unread
    assert "p4ss" not in result.text


# ---- Redis replies -------------------------------------------------------------------------------------------------

H = "ab" * 32           # a SHA-256 hash as ACL LIST writes it
MONITOR = "1731938400.123456 [0 192.0.2.10:51131]"
# (the row's command, its reply as Zeek stringifies it, the reply typed (None: withheld), what is found: a credential
# redacted ("present"), text that may hold one redacted or withheld ("unread"), "both", or None)
REDIS_CASES = [
    ("CONFIG", "OK", "OK", None),
    ("CONFIG", "[requirepass, S3cr3t]", f"[requirepass, {R}]", "present"),
    ("CONFIG", "[dir, /root/.ssh]", "[dir, /root/.ssh]", None),
    ("CONFIG", "[requirepass, ]", "[requirepass, ]", None),
    # not the full parameter list: a value holding ", <name>, " would read as more pairs, so a credential's value runs
    # to the end of the reply
    ("CONFIG", "[dbfilename, dump.rdb, dir, /var/spool/cron, requirepass, S3cr3t, masterauth, M4ster]",
     f"[dbfilename, dump.rdb, dir, /var/spool/cron, requirepass, {R}]", "both"),
    ("CONFIG", "[requirepass, S3c, dir, r3t]", f"[requirepass, {R}]", "both"),
    ("CONFIG", "{requirepass: S3cr3t, dir: /data}", f"{{requirepass: {R}}}", "both"),
    ("CONFIG", "{dir: /data, requirepass: S3c, dir: r3t}", f"{{dir: /data, requirepass: {R}}}", "unread"),
    # not read as pairs (a module's parameter, an odd list, a name twice): kept up to the first item that is exactly
    # a credential parameter's name; a value that merely holds "auth" or "pass" names none
    ("CONFIG", "[search-timeout, 500, dir, /root/.ssh, dbfilename, authorized_keys]",
     "[search-timeout, 500, dir, /root/.ssh, dbfilename, authorized_keys]", None),
    ("CONFIG", "[search-timeout, 500, dir, /root/.ssh, dbfilename, authorized_keys, requirepass, S3cr3t, port, 6379]",
     f"[search-timeout, 500, dir, /root/.ssh, dbfilename, authorized_keys, requirepass, {R}]", "unread"),
    ("CONFIG", "{search-timeout: 500, dir: /tmp/passwords, requirepass: S3cr3t}",
     f"{{search-timeout: 500, dir: /tmp/passwords, requirepass: {R}}}", "unread"),
    ("CONFIG", "[requirepass, S3c, r3t, masterauth, x]", f"[requirepass, {R}]", "unread"),
    ("CONFIG", "[requirepass, S3cr3t", None, "unread"),
    ("CONFIG", "ERR Invalid argument 'S3cr3t' for CONFIG SET 'requirepass'", None, "unread"),
    ("CONFIG", "ERR CONFIG SET failed for 'dir' (authorized_keys)", "ERR CONFIG SET failed for 'dir' (authorized_keys)",
     None),
    # a credential parameter in a list logged on another row (replies follow commands by count)
    ("GET", "[requirepass, S3cr3t]", f"[requirepass, {R}]", "present"),
    ("GET", "[requirepass, S3c, r3t]", f"[requirepass, {R}]", "unread"),
    ("GET", "[bypass, list]", "[bypass, list]", None),
    # ACL: hashes, plaintext rules, generated passwords
    ("ACL", f"[user default on #{H} ~* &* +@all]", f"[user default on #{R} ~* &* +@all]", "present"),
    ("ACL", f"[flags, [on], passwords, [{H}], commands, +@all]", f"[flags, [on], passwords, [{R}], commands, +@all]",
     "present"),
    ("ACL", "[user ops on >S3cr3t ~* +@all]", f"[user ops on >{R} ~* +@all]", "present"),
    ("ACL", "a3f1c9e07b2d48a6c5f0e1d2b3a49786", R, "present"),
    ("ACL", "[user default on", None, "unread"),
    ("ACL", "1", "1", None),
    ("KEYS", f"[user default on #{H} ~*]", f"[user default on #{R} ~*]", "present"),
    # a MONITOR stream's lines, logged on rows with no command
    ("", f'{MONITOR} "auth" "S3cr3t"', f'{MONITOR} "auth" "{R}"', "present"),
    ("", f'{MONITOR} "AUTH" "ops" "S3cr3t"', f'{MONITOR} "AUTH" "{R}"', "present"),
    ("", f'{MONITOR} "hello" "3" "AUTH" "ops" "S3cr3t"', f'{MONITOR} "hello" "3" "AUTH" "{R}" "{R}"', "present"),
    ("", f'{MONITOR} "migrate" "192.0.2.9" "6379" "" "0" "5000" "AUTH2" "ops" "S3cr3t" "KEYS" "k"',
     f'{MONITOR} "migrate" "192.0.2.9" "6379" "" "0" "5000" "AUTH2" "{R}" "{R}" "KEYS" "k"', "present"),
    ("", f'{MONITOR} "config" "set" "dir" "/var/spool/cron" "requirepass" "S3cr3t"',
     f'{MONITOR} "config" "set" "dir" "/var/spool/cron" "requirepass" "{R}"', "present"),
    ("", f'{MONITOR} "acl" "setuser" "ops" "on" ">S3cr3t" "~*"', f'{MONITOR} "acl" "setuser" "ops" "on" ">{R}" "~*"',
     "present"),
    ("", f'{MONITOR} "auth" "(redacted)"', f'{MONITOR} "auth" "(redacted)"', None),
    ("", f'{MONITOR} "set" "k" "v"', f'{MONITOR} "set" "k" "v"', None),
    ("", f'{MONITOR} "set" "k', None, "unread"),
    ("", f'{MONITOR} "auth" "S3cr', None, "unread"),
    # replies with no credential
    ("GET", "cached", "cached", None),
    ("GET", '{"user": "bob", "auth": "token-free"}', '{"user": "bob", "auth": "token-free"}', None),
    ("HELLO", "{server: redis, version: 7.2.4, proto: 3}", "{server: redis, version: 7.2.4, proto: 3}", None),
    ("AUTH", "WRONGPASS invalid username-password pair", "WRONGPASS invalid username-password pair", None),
]


@pytest.mark.parametrize("command,reply,expected,flag", REDIS_CASES, ids=[f"{c[0]}:{c[1][:50]}" for c in REDIS_CASES])
def test_a_redis_reply_keeps_everything_but_the_credentials_it_carries(command, reply, expected, flag):
    result = scrub_redis_reply(reply, command)
    assert result.text == expected
    assert result.redacted is (flag in ("present", "both"))
    assert result.unread is (flag in ("unread", "both"))
    assert (REDIS_UNREAD in result.caveats) is result.unread
    keyless = zl.REDIS.without("cmd.key", "cmd.name").with_(**{"reply.value": reply})
    row = keyless.with_(**{"cmd.name": command}) if command else keyless
    for shape, h in zl.in_every_shape(row, "reply-").items():
        event = normalize(h)
        assert event.get("app.reply") == expected, shape
        dumped = event.model_dump_json()
        assert not any(secret in dumped for secret in ("S3c", "r3t", "M4ster", H)), shape
        if flag in ("present", "both"):
            assert event.get("auth.cleartext_credentials_present") is True, shape
        if flag == "unread":
            assert event.get("auth.cleartext_credentials_unknown") is True, shape
        assert (REDIS_UNREAD in event.caveats) is (flag in ("unread", "both")), shape
        if flag is None and command not in ("", "AUTH"):
            assert not event.has("auth.cleartext_credentials_present"), shape
            assert not event.has("auth.cleartext_credentials_unknown"), shape


def test_the_full_parameter_list_is_read_pair_by_pair():
    """CONFIG GET * names every parameter once: a password posing as more pairs would repeat a name, so the full list
    keeps every other value and redacts each credential's alone."""
    names = sorted(zeek_credentials.REDIS_CORE_PARAMETERS - {"requirepass", "dir"})
    head = ", ".join(f"{name}, v-{name}" for name in names)
    full = f"[{head}, requirepass, S3cr3t, masterauth, M4ster, dir, /var/spool/cron]"
    result = scrub_redis_reply(full, "CONFIG")
    assert result.text == f"[{head}, requirepass, {R}, masterauth, {R}, dir, /var/spool/cron]"
    assert result.redacted and not result.unread
    # a password posing as more pairs repeats a name: from it to the end
    posing = f"[{head}, dir, /data, requirepass, S3c, dir, r3t]"
    result = scrub_redis_reply(posing, "CONFIG")
    assert result.text == f"[{head}, dir, /data, requirepass, {R}]" and result.unread
    # a list missing a parameter every version names is not the full list
    partial = full.replace("hz, v-hz, ", "")
    assert scrub_redis_reply(partial, "CONFIG").text.endswith(f"requirepass, {R}]")


# ---- IRC rows that hold an earlier command's columns ---------------------------------------------------------------

KEY = f" with channel key: '{S}'"
# (the command, the columns as Zeek's reused record holds them, what is typed of value and addl, whether a key is flagged)
IRC_CASES = [
    ("USER", {"value": "synth", "addl": "localhost irc.example.test Synthetic Bot"},
     ("synth", "localhost irc.example.test Synthetic Bot"), False),
    ("JOIN", {"value": "#ops", "addl": KEY}, ("#ops", None), True),
    ("NICK", {"value": "synthbot2", "addl": "localhost irc.example.test Synthetic Bot"}, ("synthbot2", None), False),
    ("NICK", {"value": "synthbot2", "addl": KEY}, ("synthbot2", None), True),
    ("DCC", {"value": "#ops", "addl": KEY, "dcc_file_name": "update.bin", "dcc_file_size": 1024}, (None, None), True),
    ("DCC", {"value": "#ops", "addl": "", "dcc_file_name": "update.bin", "dcc_file_size": 1024}, (None, None), False),
    ("PRIVMSG", {"value": "#ops", "addl": "hello"}, ("#ops", None), False),
]


@pytest.mark.parametrize("command,columns,typed,key", IRC_CASES, ids=[f"{c[0]}-{c[3]}" for c in IRC_CASES])
def test_an_irc_row_types_only_the_columns_its_own_command_set(command, columns, typed, key):
    for shape, h in zl.in_every_shape(zl.IRC.with_(command=command, **columns), "irc-").items():
        event = normalize(h)
        assert (event.get("app.arg"), event.get("irc.addl")) == typed, shape
        assert S not in event.model_dump_json(), shape
        assert (event.get("auth.cleartext_credentials_present") is True) is key, shape
        if command == "DCC":
            assert (event.get("file.name"), event.get("file.size")) == ("update.bin", 1024), shape
        stale = [c for c in event.caveats if c.startswith(ZEEK_IRC_STALE.split("{", 1)[0])]
        assert bool(stale) is (command == "DCC" or (command not in ("USER", "JOIN") and bool(columns["addl"]))), shape


def test_a_stale_key_makes_the_row_its_own_document():
    rows = [zl.plain(zl.IRC.with_(command="NICK", value="n", addl=KEY), f"nick-{i}") for i in range(2)]
    assert normalize(rows[0]).id != normalize(rows[1]).id
    plain = [zl.plain(zl.IRC.with_(command="NICK", value="n", addl="host srv name"), f"nick-plain-{i}")
             for i in range(2)]
    assert normalize(plain[0]).id == normalize(plain[1]).id


# ---- URIs: the linear scans read as the patterns they replace -----------------------------------------------------

_OLD_URI = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://)([^/?#\s]*)@")
_OLD_SIP = re.compile(r"\b(sips?:)([^:@;>\s/]*):([^;>\s]*)@", re.IGNORECASE)
_SCHEME_BEFORE = re.compile(r"[A-Za-z0-9+.-]*\Z")


def _has_schemes(text: str) -> bool:
    """Whether every "://" follows a scheme (the scan also reads one that does not, which the pattern skipped)."""
    return all(re.search("[A-Za-z]", _SCHEME_BEFORE.search(text, 0, m.start()).group())
               for m in re.finditer("(?=://)", text))


def test_the_userinfo_scans_remove_what_the_patterns_they_replace_removed():
    rng = random.Random(1918)
    uri_parts = ["a://", "b", "x", ":", "/", "@", "?", "#", " ", ".", "a"]
    sip_parts = ["sip:", "SIPS:", "a", "b", ":", "@", ";", ">", " ", "/", "<", "x"]
    for _ in range(20000):
        text = "".join(rng.choice(uri_parts) for _ in range(rng.randint(1, 14)))
        stripped, removed, password = strip_uri_userinfo(text)
        if _has_schemes(text):
            assert stripped == _OLD_URI.sub(r"\1", text), text
            found = _OLD_URI.findall(text)
            assert removed is bool(found) and password is any(":" in info for _scheme, info in found), text
        else:
            assert "@" not in stripped or stripped == _OLD_URI.sub(r"\1", stripped), text
        text = "".join(rng.choice(sip_parts) for _ in range(rng.randint(1, 14)))
        stripped, removed = strip_sip_password(text)
        assert stripped == _OLD_SIP.sub(r"\1\2@", text) and removed is bool(_OLD_SIP.search(text)), text


def test_a_value_with_more_sip_uris_than_are_read_is_withheld():
    value = " ".join(f"<sip:u{i}:pw@example.test>" for i in range(zeek_credentials.SIP_URI_BUDGET + 1))
    assert strip_sip_password(value) == (None, False)
    event = normalize(zl.plain(zl.SIP.with_(request_from=value), "sip-many"))
    assert not event.has("sip.request_from") and event.get("auth.cleartext_credentials_unknown") is True
    assert zeek_credentials.SIP_UNREAD in event.caveats


# ---- linear time ---------------------------------------------------------------------------------------------------

N = 256 * 1024


def _time(fn, limit: float = 0.05) -> float:
    """The fastest of up to three runs (one when the first is within the limit: a busy machine gets two more)."""
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
        if best < limit:
            break
    return best


def _patterns():
    """Every compiled pattern of the Zeek normalizer's modules."""
    for module in (zeek, zeek_credentials, zeek_catalog, certificates):
        for name, value in vars(module).items():
            if isinstance(value, re.Pattern):
                yield f"{module.__name__}.{name}", value


# Inputs that make a backtracking pattern quadratic or worse: long runs of one class, alternations of a class and a
# separator, and repeated prefixes of the forms these patterns look for, each about 256 KB.
ADVERSARIAL = {
    "letters": "a" * N, "digits": "1" * N + "x", "hex": "f" * N + "g", "spaces": " " * N + "x",
    "dotted": "a." * (N // 2), "hyphenated": "a-" * (N // 2), "colons": "a:" * (N // 2), "ats": "a@" * (N // 2),
    "slashes": "a/" * (N // 2), "equals": "a=" * (N // 2), "commas": ", " * (N // 2), "rdns": ",a" * (N // 2),
    "quotes": "'" * N, "dquotes": '"' * N, "backslashes": "\\" * N, "dollars": "$a" * (N // 2),
    "comments": "/*" * (N // 2), "brackets": "[" * N, "schemes": "x://" * (N // 4), "sips": "/sip:a:b" * (N // 8),
    "quoted-args": '"a" ' * (N // 4), "auth-args": '"auth" ' * (N // 7), "pairs": "a: " * (N // 3),
    "hashes": ("#" + "a" * 63 + " ") * (N // 65), "words": "password " * (N // 9),
    "numbers": "1." * (N // 2), "mac": "aa:" * (N // 3), "query-names": "query-" * (N // 6),
}


@pytest.mark.parametrize("name,pattern", list(_patterns()), ids=[name for name, _ in _patterns()])
def test_every_pattern_reads_adversarial_input_in_linear_time(name, pattern):
    for label, text in ADVERSARIAL.items():
        def run(text=text):
            for count, _match in enumerate(pattern.finditer(text)):
                if count == 100_000:
                    break
        assert _time(run) < 0.05, (name, label)


def _fields():
    """(log, columns) of a 256 KB adversarial value in every typed column a scan reads."""
    yield "http", {"uri": "/" + "a." * (N // 4) + "://" + "b" * (N // 2)}
    yield "http", {"referrer": "x://" * (N // 4)}
    yield "http", {"origin": "://a:" * (N // 5)}
    yield "http", {"host": "a@" * (N // 2)}
    yield "ftp", {"command": "RETR", "arg": "ftp://" + "a:" * (N // 2)}
    yield "intel", {"seen.indicator": "http://" + "@" * N}
    yield "sip", {"uri": "/sip:a:b" * (N // 8)}
    yield "sip", {"request_from": " sip:a:@" * (N // 8)}
    yield "sip", {"request_to": "sip:" * (N // 4)}
    yield "sip", {"uri": "sip:a:" + "b" * N}
    yield "irc", {"command": "PRIVMSG", "value": "NickServ", "addl": "IDENTIFY " + "a " * (N // 2)}
    yield "x509", {"certificate.subject": ",a" * (N // 2), "certificate.issuer": "CN=" + ", " * (N // 2)}
    yield "dns", {"query": "a." * (N // 2), "qtype_name": "query-" + "1" * N, "rcode_name": "A" * N + "-"}
    yield "ssl", {"version": "TLSv" + "1" * N}
    for statement in ("SELECT " + "password, " * (N // 10), "password" + "(" * N, "password=" + "a=" * (N // 2),
                      "password = " + "'a' " * (N // 4), "IDENTIFIED BY " * (N // 14), "PASSWORD(" * (N // 9),
                      "INSERT INTO users (name, password) VALUES " + "('a', 'b'), " * (N // 12),
                      "password " + "/*" * (N // 2), "password $a$" + "x" * N, "password " + "a " * (N // 2),
                      "/* password = 'a' */ " * (N // 22), "/* password /* /* " * (N // 18),
                      "-- password = x\n" * (N // 16), "password = " + "'a' || " * (N // 7),
                      "pass/**/word = " * (N // 15),
                      # a statement just inside the token budget: the most work a statement is given
                      "password=" + "a=" * (SQL_TOKEN_BUDGET // 2 - 2)):
        yield "mysql", {"cmd": "query", "arg": statement}
    yield "postgresql", {"frontend_arg": "ALTER ROLE x PASSWORD " + "'a''" * (N // 4)}
    for command, reply in (("", '"auth" ' * (N // 7)), ("", '"hello" ' + '"a" ' * (N // 4)),
                           ("", '"config" "set" ' + '"requirepass" "x" ' * (N // 18)),
                           ("", f'{MONITOR} "set" ' + '"a" ' * (N // 4)),
                           ("CONFIG", "[requirepass, " + "a, " * (N // 3) + "]"),
                           ("GET", "[" + "a, " * (N // 3) + "]"), ("ACL", ("#" + H + " ") * (N // 66)),
                           ("ACL", "[" + ">a," * (N // 3) + "]"), ("ACL", "a " * (N // 2)), ("GET", "[" * N)):
        yield "redis", {"cmd.name": command, "reply.value": reply}


@pytest.mark.parametrize("log,columns", list(_fields()), ids=[f"{log}-{i}" for i, (log, _) in enumerate(_fields())])
def test_an_adversarial_256_kb_value_is_normalized_in_under_50_ms(log, columns):
    row = zl.ROWS[log].with_(**columns)
    h = zl.plain(row, "big")
    event = normalize_plain_zeek(h, sensor=zl.SENSOR)
    assert json.dumps(event.model_dump(mode="json"))
    assert _time(lambda: normalize_plain_zeek(h, sensor=zl.SENSOR)) < 0.05, (log, list(columns))
