"""Deterministic, explicitly synthetic SMB lateral-movement scenario for offline demo/tests."""
from ..models import Evidence

def sample_evidence():
    host=[Evidence.create("synthetic:elasticsearch","Successful network logon event (event ID 4624, logon type 3) for account LAB\\svc-backup on LAB-WS02",asset="LAB-WS02",observed_at="2026-10-10T14:03:12+00:00",query='{"term":{"event.code":"4624"}}',provenance={"fixture":"fixtures/synthetic_host.json"},raw={"timestamp":"2026-10-10T14:03:12Z","ip":"10.20.0.15","event_id":4624,"account":"LAB\\svc-backup","host":"LAB-WS02","logon_type":3}),
          Evidence.create("synthetic:elasticsearch","Service installation event associated with LAB\\svc-backup on LAB-WS02",asset="LAB-WS02",observed_at="2026-10-10T14:04:02+00:00",query='{"term":{"event.code":"7045"}}',provenance={"fixture":"fixtures/synthetic_host.json"},raw={"timestamp":"2026-10-10T14:04:02Z","ip":"10.20.0.15","event_id":7045,"account":"LAB\\svc-backup","host":"LAB-WS02","service":"LabUpdateSvc"})]
    network=[Evidence.create("synthetic:arkime","TCP session from 10.20.0.15 to 10.20.0.22 port 445; session marked established in synthetic fixture",asset="10.20.0.22",observed_at="2026-10-10T14:02:58+00:00",query='protocol == smb && port == 445',provenance={"fixture":"fixtures/synthetic_network.json"},raw={"timestamp":"2026-10-10T14:02:58Z","src_ip":"10.20.0.15","dst_ip":"10.20.0.22","dst_port":445,"protocol":"smb","established":True})]
    return host,network
