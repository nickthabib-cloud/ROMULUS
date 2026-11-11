"""Ransom-note observations in the published Zeek and EVE SMB vocabularies."""
from __future__ import annotations

import pytest

from romulus.evidence.normalize import normalize_hits
from tests.fixtures import zeek_logs as zl
from tests.test_smb_impact import finish, smb
from tests.test_smb_impact import rule as impact_rule
from tests.test_suricata_protocols import hit
from tests.test_zeek_windows_protocols import normalize

rule = impact_rule


@pytest.mark.parametrize('shape', ['plain', 'elastic', 'malcolm', 'security_onion'])
@pytest.mark.parametrize('separator', ['/', '\\'])
def test_real_zeek_open_vocabulary_can_observe_note_burst(rule, shape, separator):
    rows = [normalize(getattr(zl, shape)(
        zl.SMB_FILES.with_(name=f'dir{i}{separator}Restore-My-Files.txt'), f'note-{i}')) for i in range(10)]
    assert all(row.get('smb.action') == 'FILE_OPEN' for row in rows)
    [match] = finish(rule, rows)
    assert match.proposed_lane == 'lead' and 'opened or created' in match.claim


@pytest.mark.parametrize('shape', ['original', 'message', 'filebeat', 'agent', 'malcolm'])
@pytest.mark.parametrize('separator', ['/', '\\'])
def test_real_suricata_create_with_share_context_observes_note_burst(rule, shape, separator):
    native = [hit('smb', {'command': 'SMB2_COMMAND_CREATE', 'disposition': 'FILE_CREATE',
                          'filename': f'dir{i}{separator}Restore-My-Files.txt', 'share': r'\\server\docs'},
                  shape=shape, nid=f'note-{i}') for i in range(10)]
    rows, skips, errors = normalize_hits(native)
    assert not skips and not errors
    [match] = finish(rule, rows)
    assert match.proposed_lane == 'lead' and 'opened or created' in match.claim


@pytest.mark.parametrize('name', ['README.html', 'readme.txt', 'README.md', 'readme!!!.txt',
                                 'fn.txt', 'product-readme.txt', 'component.README.txt',
                                 '123456789.README.txt', 'prefix-RyukReadMe.txt',
                                 'RyukReadMe.txt.analysis', 'Restоre-My-Files.txt'])
@pytest.mark.parametrize('action', ['FILE_OPEN', 'FILE_CREATE'])
def test_generic_readmes_substrings_and_unicode_lookalikes_are_not_note_names(rule, name, action):
    assert not finish(rule, [smb(i, action=action, name=f'dir{i}/{name}') for i in range(50)])


def test_fifty_repeated_opens_in_one_directory_count_once(rule):
    assert not finish(rule, [smb(i, action='FILE_OPEN', name='same/Restore-My-Files.txt') for i in range(50)])


def test_admin_copy_and_casefold_remain_a_lead(rule):
    [match] = finish(rule, [smb(i, action='FILE_OPEN', name=f'ir-copy/dir{i}/RESTORE-MY-FILES.TXT')
                            for i in range(10)])
    assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('name', ['akira_readme.txt', 'akiranew.txt', 'readme.BlackSuit.txt',
                                 'CriticalBreachDetected.pdf', '!!!READ_ME_MEDUSA!!!.txt',
                                 'CONTI_README.txt', 'RyukReadMe.txt', 'uax291-readme.txt',
                                 '!!!-Restore-My-Files-!!!.txt', 'RECOVER-a1b2c3d-FILES.txt',
                                 'a1b2c3d4e.README.txt'])
def test_sourced_specific_note_forms_are_recognized(rule, name):
    [match] = finish(rule, [smb(i, action='FILE_OPEN', name=f'dir{i}/{name}') for i in range(10)])
    assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('name', ['RECOVER-a1b2-FILES.txt', 'RECOVER-a1b2c3d4-FILES.txt',
                                 'prefix-RECOVER-a1b2c3d-FILES.txt', 'a1b2c3d4e.README.txt.bak',
                                 'a1b2c3d4eX.README.txt', 'а1b2c3d4e.README.txt'])
def test_note_patterns_are_anchored_ascii_and_bounded(rule, name):
    assert not finish(rule, [smb(i, action='FILE_OPEN', name=f'dir{i}/{name}') for i in range(10)])
