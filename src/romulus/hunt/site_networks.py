"""The hunt's internal-network definition: installed from the hunt manifest, refused when the configuration
changed since the hunt was created."""
from __future__ import annotations

from romulus.config import Settings
from romulus.detect import netdef
from romulus.detect.netdef import INTERNAL_SETTING, SiteNetworks


def install_for_hunt(settings: Settings, hunt_id: str, manifest: dict) -> SiteNetworks:
    """Install the definition the hunt recorded (a hunt recorded before the setting existed used the default).
    A configuration whose definition differs is refused: the hunt's sweep, coverage and findings were decided
    under the recorded one, so new work under another would mix two meanings of "internal"."""
    recorded = SiteNetworks.from_record(manifest.get("internal_networks"))
    now = SiteNetworks.from_settings(settings)
    if now != recorded:
        raise RuntimeError(
            f"hunt {hunt_id} was created with internal networks {recorded.summary().removeprefix('Internal networks: ')}"
            f" (digest {recorded.digest[:12]}); this configuration has "
            f"{now.summary().removeprefix('Internal networks: ')} (digest {now.digest[:12]}). Restore "
            f"{INTERNAL_SETTING} and its carve-outs, or start a new hunt over the same window instead of resuming.")
    netdef.install(recorded)
    return recorded
