"""Separate temporary-file completion from ransomware-shaped extension changes."""
from __future__ import annotations

import pytest

from tests.test_smb_impact import finish, smb
from tests.test_smb_impact import rule as impact_rule

rule = impact_rule


@pytest.mark.parametrize('before,after', [('mod.obj.tmp', 'mod.obj'), ('archive.tar.gz.part', 'archive.tar.gz'),
                                         ('scan.part', 'scan.pdf'), ('image.partial', 'image.tiff'),
                                         ('report.pdf~', 'report.pdf'), ('data.old', 'data'),
                                         ('document.pdf', 'DOCUMENT.PDF'),
                                         # pipelines and applications completing a temporary name into place
                                         ('in.tmp', 'in.xml'), ('batch.part', 'batch.CSV'),
                                         ('tmpk2j3h4l5', 'out.json'), ('8A3F09C1', 'book.xlsx'),
                                         ('~save', 'notes.txt')])
def test_temporary_completion_and_case_only_renames_never_become_high(rule, before, after):
    matches = finish(rule, [smb(i, i / 2, previous=f'dir{i}/{before}', name=f'dir{i}/{after}') for i in range(130)])
    assert not matches


@pytest.mark.parametrize('suffix', ['.tmp', '.temp', '.part', '.partial', '.filepart',
                                   '.crdownload', '.download', '.!ut', '.swp', '~'])
def test_every_named_temporary_suffix_can_be_removed_without_extension_evidence(rule, suffix):
    [match] = finish(rule, [smb(i, previous=f'dir/file{i}.pdf{suffix}', name=f'dir/file{i}.pdf')
                            for i in range(200)])
    assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('before,after', [('x.tmp', 'x.locked'), ('x.part', 'x.a3b4'),
                                         ('report.pdf', 'report.pdf.akira'),
                                         ('~WRL0001.tmp', 'encrypted.locked'),
                                         ('old/x.tmp', 'new/x.pdf'),
                                         ('tmpk2j3h4l5', 'out.locked'), ('8A3F09C1', 'book.akira'),
                                         ('report', 'report.xml')])
def test_temporary_exception_preserves_eligible_encryption_renames(rule, before, after):
    [match] = finish(rule, [smb(i, previous=f'dir{i}/{before}', name=f'dir{i}/{after}') for i in range(100)])
    assert match.proposed_lane == 'high'


def test_mixed_temp_completion_and_encryption_uses_only_encryption_denominator(rule):
    rows = [smb(i, previous=f'build/mod{i}.obj.tmp', name=f'build/mod{i}.obj') for i in range(60)]
    rows += [smb(i + 60, previous=f'docs/report{i}.pdf', name=f'docs/report{i}.lockbit') for i in range(100)]
    [match] = finish(rule, rows)
    assert match.proposed_lane == 'high' and 'renamed 100 distinct' in match.claim
    assert '100.0%' in match.claim and '.lockbit' in match.claim


def test_different_victims_with_random_four_to_eight_character_extensions_remain_high(rule):
    suffixes = ['q9v2', 'f3r8z', 'e4t1x7', 'p7h2k9w', 'z3m8c6q1']
    rows = [smb(f'{victim}-{i}', previous=f'dir/report{i}.pdf', name=f'dir/report{i}.pdf.{suffix}',
                client=f'10.0.0.{victim + 10}') for victim, suffix in enumerate(suffixes) for i in range(100)]
    matches = finish(rule, rows)
    assert len(matches) == len(suffixes) and all(m.proposed_lane == 'high' for m in matches)
    assert all(any(suffix in m.claim for m in matches) for suffix in suffixes)


def test_random_extensionless_renames_are_volume_lead_with_explicit_note(rule):
    [match] = finish(rule, [smb(i, previous=f'dir/report{i}.pdf', name=f'dir/random{i:08x}') for i in range(200)])
    assert match.proposed_lane == 'lead'
    assert any('no extension' in note and 'volume-only' in note for note in match.notes)


def test_unrelated_ordinary_suffix_changes_are_still_extension_eligible(rule):
    [match] = finish(rule, [smb(i, previous=f'dir/file{i}.docx', name=f'dir/file{i}.pdf') for i in range(100)])
    assert match.proposed_lane == 'high'
