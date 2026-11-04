"""Every executive text run admits only XML 1.0 characters."""
from xml.etree import ElementTree
from zipfile import ZipFile

import pytest

from romulus.report import executive
from romulus.report.manifest import publish_revision
from tests.test_report import _repo_with_finding


@pytest.mark.parametrize("invalid_codepoint", [0xfffe, 0xffff, 0xd800, 0xdfff, 0x00, 0x01, 0x0b, 0x1f])
@pytest.mark.parametrize("location", ["claim", "check", "heading", "technical"])
def test_executive_text_runs_strip_xml_forbidden_characters(tmp_path, invalid_codepoint, location):
    invalid = chr(invalid_codepoint)
    repo, _candidate = _repo_with_finding()
    manifest = publish_revision(repo, "h1", "test")
    valid = "before\t\n\r<&>\u00e9\ufffd\U0001f642after"
    value = valid[:6]+invalid+valid[6:]
    technical = "technical.md"
    if location == "claim":
        manifest["findings"][0]["claim"] = value
    elif location == "check":
        manifest["findings"][0]["next_checks"] = [value]
    elif location == "heading":
        manifest["findings"][0]["rule_id"] = value
    else:
        technical = value
    path = tmp_path/"executive.docx"
    executive.write(manifest, path, technical)
    with ZipFile(path) as archive:
        document = ElementTree.fromstring(archive.read("word/document.xml"))
    text = "".join(node.text or "" for node in document.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"))
    assert invalid not in text
    # XML parsers normalize a literal CR, while all other valid characters survive.
    assert valid.replace("\r", "\n") in text
