"""Remote service children retain their evidence-specific lanes."""
import pytest

from romulus.detect.windows_remote import DcomActivatedChild, RemoteExecutionParent
from tests.windows_process_support import run, security4688, sysmon1


@pytest.mark.parametrize('parent', ['wmiprvse.exe', 'wsmprovhost.exe'])
@pytest.mark.parametrize('child', ['C:\\Program Files\\Management\\inventory.exe',
                                   'C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe'])
def test_management_children_are_visible_as_leads(parent, child):
    [match] = run(RemoteExecutionParent(), [sysmon1(image=child, command=child,
                         parent_image='C:\\Windows\\SysWOW64\\' + parent)])
    assert match.proposed_lane == 'lead'


@pytest.mark.parametrize('redirect,expected', [
    (r'whoami > \\127.0.0.1\ADMIN$\out 2>&1', 'high'),
    (r'echo ADMIN$', 'lead'),
    (r'whoami > C:\Temp\out', 'lead'),
    (r'whoami > \\server\public\out', 'lead'),
    (r'type < \\server\ADMIN$\input', 'lead'),
    (r'echo \\server\ADMIN$\mention > C:\Temp\note.bat', 'lead'),
    (r'echo type ^< \\server\ADMIN$\input ^> C:\Temp\out > C:\Temp\note.bat', 'lead'),
    (r'echo whoami ^> \\server\ADMIN$\out 2^>^&1 > C:\Temp\run.bat', 'high'),
    (r'echo "whoami > \\server\ADMIN$\mention" > C:\Temp\note.bat', 'lead'),
])
def test_dcom_share_redirection_supplies_the_high_lane(redirect, expected):
    [match] = run(DcomActivatedChild(), [sysmon1(image=r'C:\Windows\System32\cmd.exe',
                 command='cmd.exe /c ' + redirect, parent_image=r'C:\Windows\System32\mmc.exe')])
    assert match.proposed_lane == expected


def test_non_runner_child_waits_for_a_parent_record_arriving_in_a_later_partition():
    child = security4688(image=r'C:\Tools\inventory.exe', command='inventory.exe', pid=200, ppid=100, offset=1)
    parent = security4688(image=r'C:\Windows\System32\wmiprvse.exe', command='wmiprvse.exe', pid=100, ppid=50)
    [match] = run(RemoteExecutionParent(), [[child], [parent]])
    assert match.proposed_lane == 'lead'
    assert any(e.id == parent.id for e in match.events)


def test_dcom_missing_child_command_line_keeps_its_recorded_parent_lead():
    record = sysmon1(image=r'C:\Windows\System32\cmd.exe', command=None,
                     parent_image=r'C:\Windows\System32\mmc.exe')
    [match] = run(DcomActivatedChild(), [record])
    assert match.proposed_lane == 'lead'
