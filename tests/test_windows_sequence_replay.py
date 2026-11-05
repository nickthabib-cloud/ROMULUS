"""Real sweep replay reconstructs each new keyed state without publishing twice."""
import pytest

from romulus.detect.windows_sequence_extensions import (
    ParentProcessSpoofing,
    RdpRunMruWrite,
    SamAdminRegistryWithoutAudit,
    SmbHostDiscovery,
)
from romulus.evidence.windows_catalog import SECURITY
from romulus.hunt import sweep as sw
from romulus.hunt.publish import SourceCitationFetcher
from romulus.sources.models import Window
from tests.test_sweep import _complete, _repo
from tests.test_windows_process_w4 import START, native

GUID = '{00000000-0000-0000-0000-000000000001}'
OTHER = '{00000000-0000-0000-0000-000000000002}'
CHILD = '{00000000-0000-0000-0000-000000000003}'


def observations(kind):
    if kind == 'parent':
        return ParentProcessSpoofing, [
            native({'SourceProcessGUID': GUID, 'TargetProcessGUID': OTHER, 'SourceProcessId': '123',
                    'SourceImage': r'C:\Tools\creator.exe', 'GrantedAccess': '0x80'}, 1, code=10),
            native({'ProcessGuid': CHILD, 'ParentProcessGuid': OTHER, 'Image': r'C:\Windows\System32\cmd.exe'},
                   2, code=1, offset=1)]
    if kind == 'sam':
        return SamAdminRegistryWithoutAudit, [
            native({'TargetObject': r'HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\C',
                    'EventType': 'SetValue', 'Details': 'Binary Data'}, 1, code=13)]
    if kind == 'rdp':
        return RdpRunMruWrite, [
            native({'LogonType': '10', 'IpAddress': '10.0.0.5', 'TargetUserName': 'alice'},
                   1, code=4624, provider=SECURITY, channel='Security'),
            native({'TargetObject': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\a',
                    'Details': 'cmd.exe', 'EventType': 'SetValue'}, 2, code=13, offset=1)]
    return SmbHostDiscovery, [
        native({'Image': r'C:\Tools\inventory.exe', 'ProcessGuid': GUID, 'SourceIp': '10.0.0.1',
                'DestinationIp': f'10.1.0.{n+1}', 'SourcePort': str(5000+n), 'DestinationPort': '445',
                'Protocol': 'tcp', 'Initiated': 'true'}, n+1, code=3, offset=n/10) for n in range(25)]


@pytest.mark.parametrize('kind', ['parent', 'sam', 'rdp', 'smb'])
def test_fresh_sweep_replay_keeps_one_publication_and_resolvable_citations(tmp_path, monkeypatch, kind):
    from datetime import timedelta
    cls, pairs = observations(kind)
    repo = _repo()
    window = Window(start=START, end=START+timedelta(hours=1))
    monkeypatch.setattr(sw, 'fresh_pack', lambda: [cls()])
    class NativeSource:
        def search(self, index, body):
            wanted = body['query']['bool']['filter'][0]['ids']['values']
            return {'hits': {'hits': [hit for _, hit in pairs if hit['_index'] == index and hit['_id'] in wanted]}}
    source = NativeSource()
    target = pairs[0][1]['_index']
    def execute(sweep, batch):
        monkeypatch.setattr(sw, 'execute', lambda _client, intent, _contract: _complete(intent, [h for _, h in batch]))
        sweep.run_partition(target, None, [], window, est=len(batch))
    original = sw.Sweep(repo, None, 'h1', window, {}, stage_dir=tmp_path)
    execute(original, pairs[:1])
    original.close_stage()
    identities = None
    for _attempt in range(2):
        replay = sw.Sweep(repo, None, 'h1', window, {}, stage_dir=tmp_path)
        replay.pack[0].citation_fetcher = SourceCitationFetcher(source)
        try:
            for pair in reversed(pairs):
                execute(replay, [pair, pair])
            replay.finalize()
            findings = repo.candidates('h1')
            assert len(findings) == 1
            current = {row['id'] for row in findings}
            assert identities is None or current == identities
            identities = current
            assert not findings[0].get('citation_unavailable')
            for pair in pairs:
                for ref in pair[0].raw:
                    from romulus.store.repo import raw_id
                    records = repo.raw_records([raw_id(ref.target, ref.native_id)])
                    # SMB cites a bounded sample; every actually cited raw record must be present.
                    if pair[0].id in findings[0]['event_ids']:
                        assert records and records[0]['source'] == pair[1]['_source']
        finally:
            replay.close_stage()
