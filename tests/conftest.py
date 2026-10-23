"""Shared test hygiene."""
import pytest


@pytest.fixture(autouse=True)
def _default_site_networks():
    """Every test starts and ends with the default internal-network definition: a test that installs a site's
    definition must not change what another test's rules see."""
    from romulus.detect import netdef
    netdef.install(netdef.SiteNetworks.default())
    yield
    netdef.install(netdef.SiteNetworks.default())
