"""Routine WMI/WinRM children fold without weakening recorded code runners."""
import pytest

from romulus.detect.windows_remote import RemoteExecutionParent
from tests.windows_process_support import run, sysmon1


@pytest.mark.parametrize('parent', ['wmiprvse.exe', 'wsmprovhost.exe'])
def test_nonrunner_children_fold_by_host_parent_and_image_without_temporary_arguments(parent):
    records = [sysmon1(image=r'C:\Program Files\Management\inventory.exe',
        command=f'inventory.exe --temp C:\\Temp\\unique-{n}.tmp',
        parent_image='C:\\Windows\\System32\\' + parent, guid=n+10, offset=n) for n in range(50)]
    owner = RemoteExecutionParent()
    try:
        [match] = run(owner, records)
        assert match.proposed_lane == 'lead' and '50' in match.claim
        assert len(owner.groups) == 1
    finally:
        owner.release_state()


def test_nonrunner_fold_keeps_hosts_and_child_images_separate():
    records = [sysmon1(image=child, command='inventory.exe unique', parent_image=r'C:\Windows\System32\wmiprvse.exe',
        host=host, guid=n+10) for n, (host, child) in enumerate([
            ('one.example.test', r'C:\Tools\inventory.exe'), ('two.example.test', r'C:\Tools\inventory.exe'),
            ('one.example.test', r'C:\Other\inventory.exe')])]
    owner = RemoteExecutionParent()
    try:
        matches = run(owner, records)
        assert len(matches) == 3 and all(m.proposed_lane == 'lead' for m in matches)
    finally:
        owner.release_state()


def test_code_runner_highs_retain_distinct_payload_shapes():
    records = [sysmon1(image=r'C:\Windows\System32\cmd.exe', command='cmd.exe /c ' + command,
        parent_image=r'C:\Windows\System32\wmiprvse.exe', guid=n+10) for n, command in enumerate(['whoami', 'ipconfig'])]
    owner = RemoteExecutionParent()
    try:
        matches = run(owner, records)
        assert len(matches) == 2 and all(m.proposed_lane == 'high' for m in matches)
    finally:
        owner.release_state()
