"""Inject a named physical-capacity refusal at a controlled accepted-state checkpoint."""
from romulus.detect.bounded import KeyedStore, SpillList


def refuse_after_spill(owner, store, accepted_bytes):
    budget = owner.state_budget()
    budget.force_full("injected physical whole-hunt byte ceiling", lambda account:
                      account is store.account() and store.disk_bytes >= accepted_bytes)


def refuse_new_stores_after_spill(monkeypatch, accepted_bytes):
    for cls in (KeyedStore, SpillList):
        original = cls.__init__
        def initialize(self, owner, *args, original=original, **kwargs):
            original(self, owner, *args, **kwargs)
            if owner is not None:
                refuse_after_spill(owner, self, accepted_bytes)
        monkeypatch.setattr(cls, "__init__", initialize)


def refuse_configured_stores(owner, limits=()):
    explicit = dict(limits)
    for ref in owner.__dict__.get("_state_stores", ()):
        store = ref()
        if store is None:
            continue
        limit = explicit.get(store.name, getattr(store, "disk_budget", None))
        if limit is not None and limit < 2**20:
            refuse_after_spill(owner, store, limit)
