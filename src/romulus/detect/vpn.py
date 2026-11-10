"""VPN concurrency from closed, identified lifecycles, never from two login timestamps.

OpenVPN documents session-status fields and duplicate common names at
https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/.
strongSwan logs CHILD_SA establishment and deletion:
https://docs.strongswan.org/docs/latest/config/logging.html.
Concurrent distinct sources can be legitimate shared credentials, roaming or
multiple devices: the observation is a LEAD, not a compromise verdict.
"""
from dataclasses import dataclass, field
from typing import ClassVar

from romulus.detect.bounded import SpillList
from romulus.detect.service_auth import RecordRule, observation, source_ip, text_field


@dataclass
class _Concurrent:
    longest: list = field(default_factory=list)
    match: object = None


class VpnConcurrentSessions(RecordRule):
    id = "vpn.concurrent_sessions_same_user_distinct_sources"
    title = "Overlapping VPN sessions for one identity from distinct sources"
    families = ("vpn_session",)
    required_fields = ("vpn.service", "vpn.action", "user.name", "source.ip")
    attack = ("T1078", "T1133")
    benign = ("Shared identities, multiple authorized devices or roaming may explain overlapping VPN sessions.",
              "A certificate common name is the logged identity and may differ from an authenticated account.")
    next_checks = ("Verify the logged identity, session boundaries and device ownership.",)
    card: ClassVar[dict] = {"behavior": title, "telemetry": "Explicit VPN connect/disconnect with session ID or user/peer/port",
            "fidelity": "Two closed intervals must overlap strictly; absent boundaries and duplicate opens are unresolved."}

    def __init__(self):
        super().__init__()
        self._sessions = self.store("vpn_open")
        self._groups = self.store("vpn_groups", candidate=lambda state: state.match is not None)
        self._intervals = SpillList(self, "vpn_intervals", self.HOT)

    def accept(self, event):
        action = text_field(event, "vpn.action")
        if action is not None and action not in {"connect", "disconnect"}:
            return False
        if (not event.host or not source_ip(event)
                or any(not text_field(event, name) for name in self.required_fields)
                or self.lifecycle_key(event) is None):
            self.missing_required += 1
            return False
        return True

    @staticmethod
    def lifecycle_key(event):
        service = text_field(event, "vpn.service")
        session_id = text_field(event, "vpn.session_id")
        if session_id:
            return event.host, service, "session", session_id
        port = event.get("source.port")
        if service == "openvpn" and type(port) is int and 0 < port <= 65535:
            # This is an evaluator join key, never a fabricated native session id.
            # Both explicit endpoints must agree; a second open before a close invalidates the interval.
            return event.host, service, "endpoint", event.get("user.name"), source_ip(event), port
        return None

    def finalize(self):
        if self._done:
            return
        self._done = True
        for index, record in enumerate(self._rows.ordered()):
            event = record.event
            key = self.lifecycle_key(event)
            start = self._sessions.get(key)
            if event.get("vpn.action") == "connect":
                if start is not None and start is not False:
                    self.missing_required += 1
                    self.put(self._sessions, key, "ambiguous")
                else:
                    self.put(self._sessions, key, record)
            elif start == "ambiguous":
                self.missing_required += 1
                self.put(self._sessions, key, False)
            elif start is not None and start is not False:
                first = start.event
                if (first.ts < event.ts and first.get("user.name") == event.get("user.name")
                        and source_ip(first) == source_ip(event)):
                    if not self._intervals.append((start, record), (first.ts.timestamp(), first.id)):
                        self.refuse("vpn_intervals", "A VPN lifecycle interval was refused by the disk budget")
                else:
                    self.missing_required += 1
                self.put(self._sessions, key, False)
            else:
                self.missing_required += 1
            if index % 128 == 0:
                self.trim()
                self._intervals.trim()
        for _key, start in self._sessions.items():  # noqa: PERF102 - disk-backed KeyedStore has no values()
            if start is not False:
                self.missing_required += 1
        for index, interval in enumerate(self._intervals.ordered()):
            start, end = interval
            first = start.event
            key = (first.host, first.get("vpn.service"), first.get("user.name"))
            state = self._groups.get(key)
            if state is None:
                state = _Concurrent()
                if not self.put(self._groups, key, state):
                    continue
            for prior in state.longest:
                if (prior[1].event.ts > first.ts and source_ip(prior[0].event) != source_ip(first)
                        and state.match is None):
                    state.match = observation(self, list(prior) + list(interval), key,
                                              f"VPN service {key[1]} on {key[0]} recorded two closed sessions "
                                              f"for identity '{key[2]}' from {source_ip(prior[0].event)} and "
                                              f"{source_ip(first)} whose logged lifecycles overlap.",
                                              fields=(*self.required_fields, "vpn.session_id", "source.port"))
            # Two distinct-source intervals with the latest ends suffice to decide the next interval.
            best = {source_ip(pair[0].event): pair for pair in state.longest}
            address = source_ip(first)
            if address not in best or best[address][1].event.ts < end.event.ts:
                best[address] = interval
            state.longest = sorted(best.values(), key=lambda pair: pair[1].event.ts, reverse=True)[:2]
            if index % 128 == 0:
                self.trim()
        self.trim()
        for _key, state in self._groups.items(candidates=True):  # noqa: PERF102 - disk-backed KeyedStore has no values()
            yield state.match

    def release_state(self):
        super().release_state()
        self._intervals.clear()


VPN_PLAYBOOKS = [VpnConcurrentSessions]
