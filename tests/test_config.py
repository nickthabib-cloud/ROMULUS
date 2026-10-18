"""Config parsing: inline comments never become values; weak web secrets are refused."""
import pytest

from romulus.config import parse_env_file
from romulus.web.auth import Sessions


def test_inline_comments_are_not_values(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ROMULUS_SECRET_KEY=            # random 32+ chars; signs web sessions\n"
                 "ES_URL=http://127.0.0.1:9200   # lab\n"
                 "QUOTED='a # b'\n"
                 "HASH_IN_VALUE=abc#def\n", encoding="utf-8")
    env = parse_env_file(f)
    assert env["ROMULUS_SECRET_KEY"] == ""
    assert env["ES_URL"] == "http://127.0.0.1:9200"
    assert env["QUOTED"] == "a # b"
    assert env["HASH_IN_VALUE"] == "abc#def"


@pytest.mark.parametrize("secret", ["", "short", "# random 32+ chars; signs web sessions", "x" * 20 + " " + "y" * 20])
def test_weak_or_comment_secrets_refused(secret):
    with pytest.raises(ValueError):
        Sessions(secret)


def test_strong_secret_accepted():
    Sessions("K" * 43)
