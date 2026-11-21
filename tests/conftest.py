"""Shared test hygiene."""
import os
from pathlib import Path

import pytest

# Hunts in tests read no shipped mention patterns unless a test names its own directory (Settings.mention_dir): the
# captured results of whole-stack tests must not move when the curated corpus changes, nor with a shell's
# ROMULUS_MENTION_DIR. Both the environment value (read by load_settings) and the default directory are forced at
# import, before any module-scoped fixture runs a hunt. tests/test_mention_sweep.py covers the sweep with its own
# fixtures and loads the shipped corpus by its path.
NO_MENTION_PATTERNS = Path(__file__).parent / "data" / "mentions-none"
os.environ["ROMULUS_MENTION_DIR"] = str(NO_MENTION_PATTERNS)

from romulus.content import mention_patterns as _mention_patterns

SHIPPED_MENTION_DIR = _mention_patterns.SHIPPED_DIR
_mention_patterns.SHIPPED_DIR = NO_MENTION_PATTERNS


@pytest.fixture(autouse=True)
def _default_site_networks():
    """Every test starts and ends with the default internal-network definition: a test that installs a site's
    definition must not change what another test's rules see."""
    from romulus.detect import netdef
    netdef.install(netdef.SiteNetworks.default())
    yield
    netdef.install(netdef.SiteNetworks.default())
