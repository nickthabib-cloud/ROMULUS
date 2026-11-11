"""Producer identity fencing for native Windows, Zeek, and eCAR evidence.

Native identities: https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventrecordid-systempropertiestype-element
https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html
https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md
"""
from datetime import UTC, datetime, timedelta

import pytest

from romulus.config import Settings
from romulus.evidence.ecar import ECAR_NORMALIZER
from romulus.evidence.normalize import NORMALIZER_VERSION
from romulus.evidence.windows import WINDOWS_NORMALIZER
from romulus.evidence.zeek import ZEEK_NORMALIZER
from romulus.hunt import manifest as manifests
from romulus.hunt import run as hunt_run
from romulus.sources.models import Window

VERSIONS = {"lab-ecs": NORMALIZER_VERSION, "windows-ecs": WINDOWS_NORMALIZER,
            "zeek-ecs": ZEEK_NORMALIZER, "ecar": ECAR_NORMALIZER,
            "suricata-eve": "suricata-eve@2", "arkime": "arkime@1"}


class VersionsAccepted(Exception):
    pass


def resume(manifest, tmp_path, monkeypatch):
    class Repo:
        def get_hunt(self, hunt_id):
            assert hunt_id == "h1"
            return {"manifest": manifest, "execution_state": "partial"}

        def claim_hunt(self, *args, **kwargs):
            pytest.fail("claimed work before checking producer versions")

    monkeypatch.setattr(hunt_run, "open_repo", lambda _s: Repo())
    monkeypatch.setattr(hunt_run, "ensure_site_unchanged", lambda *_args: None)

    def after_versions(*args):
        raise VersionsAccepted

    monkeypatch.setattr(hunt_run, "install_for_hunt", after_versions)
    return hunt_run.resume_hunt(Settings(home=tmp_path), "h1")


def test_new_manifest_records_every_host_and_network_producer():
    start = datetime(2030, 1, 6, tzinfo=UTC)
    manifest = manifests.build_manifest(Settings(), Window(start=start, end=start + timedelta(hours=1)),
                                        {}, "broad", [], {})
    assert manifest["normalizers"] == VERSIONS
    assert manifest["normalizer"] == NORMALIZER_VERSION
    assert manifest["packet_normalizer"] == hunt_run.PACKET_NORMALIZER


def test_manifest_retains_source_shapes_counts_and_retrieval_limitations():
    start = datetime(2030, 1, 6, tzinfo=UTC)
    detail = {"windows_shapes": {"evtx_json": 3}, "linux_text_mixed": None, "ecar": True,
              "windows_not_assessed": {"records": 3, "reason": "not evaluated", "count_scope": "whole index"},
              "temporal_gaps": [{"records": 2, "reason": "native fallback time not queried",
                                 "count_scope": "whole index", "primary": "@timestamp", "alternate": "timestamp_ms"}],
              "notes": ["mixed text count unavailable"]}
    profile = {"id": "p", "backend_version": "8.19", "doc_count": 5, "datasets": {},
               "role": "host", "os_family": "windows", **detail}
    manifest = manifests.build_manifest(Settings(), Window(start=start, end=start + timedelta(hours=1)),
                                        {}, "broad", ["source"], {"source": profile})
    assert all(manifest["source_profiles"]["source"][key] == value for key, value in detail.items())


@pytest.mark.parametrize("producer", VERSIONS)
def test_resume_refuses_each_changed_producer_before_claiming(producer, tmp_path, monkeypatch):
    recorded = {**VERSIONS, producer: VERSIONS[producer] + "-previous"}
    with pytest.raises(RuntimeError, match="Start a new hunt over the same window") as error:
        resume({"normalizers": recorded}, tmp_path, monkeypatch)
    assert producer in str(error.value) and recorded[producer] in str(error.value)


@pytest.mark.parametrize("manifest", [{}, {"normalizer": NORMALIZER_VERSION, "normalizers": VERSIONS},
    {"normalizers": VERSIONS}, {"normalizers": {"windows-ecs": WINDOWS_NORMALIZER}}])
def test_old_or_equal_recorded_producers_pass_the_version_gate(manifest, tmp_path, monkeypatch):
    with pytest.raises(VersionsAccepted):
        resume(manifest, tmp_path, monkeypatch)


def test_a_recorded_producer_absent_from_this_build_is_refused(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="Start a new hunt over the same window"):
        resume({"normalizers": {"missing-producer": "missing-producer@1"}}, tmp_path, monkeypatch)


@pytest.mark.parametrize("recorded", [None, [], "windows-ecs@1"])
def test_malformed_new_version_map_cannot_silently_bypass_fence(recorded, tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="Start a new hunt over the same window"):
        resume({"normalizers": recorded}, tmp_path, monkeypatch)


@pytest.mark.parametrize("manifest", [
    {"normalizer": NORMALIZER_VERSION},
    {"normalizers": {"lab-ecs": NORMALIZER_VERSION}},
    {"normalizer": NORMALIZER_VERSION, "normalizers": {"windows-ecs": WINDOWS_NORMALIZER}},
    {"normalizers": {key: value for key, value in VERSIONS.items() if key != "arkime"}},
    {"normalizers": {key: value for key, value in VERSIONS.items() if key != "suricata-eve"}},
])
def test_legacy_shared_network_producers_require_a_new_hunt(manifest, tmp_path, monkeypatch):
    # These records formerly used the shared epoch. Mixing old staged network IDs
    # with the split producer IDs on resume would count one record twice.
    with pytest.raises(RuntimeError, match="Start a new hunt over the same window"):
        resume(manifest, tmp_path, monkeypatch)
