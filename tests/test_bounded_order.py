"""A hunt's result never depends on how much state was in memory: the whole sweep, expansion and report stack gives
the same stored rows (entities included) with every hot set forced to one entry as with the defaults."""
import pytest

from romulus.detect.bounded import KeyedStore, SpillList
from tests import throughput_fixture as tf


@pytest.mark.slow
def test_the_stack_gives_the_same_result_with_every_hot_set_at_one(tmp_path, monkeypatch):
    docs = tf.build(1)
    tf.patched_sizes(monkeypatch)
    (tmp_path / "default").mkdir()
    (tmp_path / "hot1").mkdir()
    default = tf.digests(tf.run_stack(tmp_path / "default", docs=docs))
    keyed, listed = KeyedStore.__init__, SpillList.__init__
    monkeypatch.setattr(KeyedStore, "__init__", lambda self, owner, name, hot, **kw: keyed(self, owner, name, 1, **kw))
    monkeypatch.setattr(SpillList, "__init__", lambda self, owner, name, hot, **kw: listed(self, owner, name, 1, **kw))
    assert tf.digests(tf.run_stack(tmp_path / "hot1", docs=docs)) == default
