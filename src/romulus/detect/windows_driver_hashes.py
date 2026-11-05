"""Small curated vulnerable-driver byte identities, independent of filename or signature."""
from romulus.detect.windows_events import WindowsEventRule, signal
from romulus.evidence.windows_catalog import SYSMON, SYSMON_CHANNEL

# Reviewed exact SHA256s; these identify dual-use bytes, never intent or exploitation.
DRIVERS = {
    'd969845ef6acc8e5d3421a7ce7e244f419989710871313b04148f9b322751e5d': (
        'RwDrv', 'https://www.trellix.com/assets/instructions/byovd-expert-rule.pdf'),
    '1e0eb0811a7cf1bdaf29d3d2cab373ca51eb8d8b58889ab7728e2d3aed244abe': (
        'RwDrv', 'https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/b03798af-d25a-400b-9236-4643a802846f.yaml'),
    'acb65f96f1d5c986b52d980a1c5ea009292ff472087fdd8a98a485404948f585': (
        'RwDrv', 'https://github.com/magicsword-io/LOLDrivers/blob/main/yaml/fbdd993b-47b1-4448-8c41-24c310802398.yaml'),
}


class KnownDualUseDriver(WindowsEventRule):
    id, title = 'win.known_dual_use_driver', 'A curated dual-use vulnerable driver loaded'
    families = ('image_load',)
    windows_event_classes = ((SYSMON_CHANNEL, SYSMON, 6),)
    attack = ('T1068',)
    benign = ('Authorized hardware inspection and diagnostics use these drivers.',)
    next_checks = ('Review the loading service, driver provenance and subsequent privileged access.',)
    research = tuple(sorted({source for _name, source in DRIVERS.values()}))

    def judge(self, event):
        digest = event.get('image.hash.sha256')
        found = DRIVERS.get(digest.casefold()) if isinstance(digest, str) else None
        if event.get('event.code') != 6 or event.get('image.kind') != 'driver' or not found:
            return []
        name, source = found
        return [signal(event, 'known_driver', f'A loaded driver SHA256 matches curated dual-use {name} bytes.',
            self.attack, ('image.path', 'image.hash.sha256', 'image.signed', 'image.signature_status'),
            severity='low', content=digest.casefold(),
            notes=('The hash identifies vulnerable dual-use bytes; exploitation is not established.', source))]


RULES = (KnownDualUseDriver,)
