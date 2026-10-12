"""Arkime session search adapter; endpoint/auth behavior must be checked against the deployed build."""
import re
from urllib.parse import quote
from typing import Any
from ..config import Settings, safe_url
from ..investigation.sampling import rank_windows

class ArkimeAdapter:
    def __init__(self, settings: Settings, session: Any = None):
        self.settings=settings; self.session=session
        if self.session is None:
            try:
                import requests
                self.session=requests.Session()
            except ImportError: pass
    def _auth(self):
        if not self.settings.arkime_username or not self.settings.arkime_password: raise RuntimeError("Arkime API credentials are not configured")
        try: from requests.auth import HTTPDigestAuth
        except ImportError as e: raise RuntimeError("Install requirements.txt for Arkime support") from e
        return HTTPDigestAuth(self.settings.arkime_username,self.settings.arkime_password)
    def check(self) -> dict[str, Any]:
        try:
            # A minimal authenticated session query verifies the endpoint in use by
            # ROMULUS. /api/appinfo is not compatible with the deployed Arkime 6.3.1.
            r=self.session.get(self.settings.arkime_url+self.settings.arkime_api_path,
                params={"date":-1,"length":1},auth=self._auth(),timeout=self.settings.tool_timeout_seconds)
            body=r.json() if r.ok else {}
            return {"available":r.ok,"status_code":r.status_code,"authenticated":r.ok,
                    "session_count":len(body.get("data",body.get("sessions",[]))),
                    "total":body.get("recordsFiltered",body.get("total"))}
        except Exception as e: return {"available":False,"error":type(e).__name__}
    def search_sessions(self, expression: str, start_ms: int | None=None, stop_ms: int | None=None, length: int=100, all_history: bool=False, start: int=0) -> dict[str, Any]:
        if len(expression)>512 or any(x in expression for x in (";","\n","\r")): raise ValueError("Invalid Arkime expression")
        if not isinstance(start,int) or start<0 or start>10_000_000: raise ValueError("Invalid Arkime result offset")
        params={"expression":expression,"length":max(1,min(int(length),self.settings.arkime_max_results)),"start":start,
                "fields":"source.ip,source.port,destination.ip,destination.port,ipProtocol,firstPacket,lastPacket,node,rootId,communityId,network.packets,network.bytes,source.packets,destination.packets,source.bytes,destination.bytes,dns.host,dns.ip,http.uri,http.method,host.http,http.user-agent,http.statuscode,tls.ja3,tls.ja4,tls.alt",
                "facets":0,"order":"firstPacket:asc","bounding":"either",
                "date":-1 if all_history or self.settings.historical_search else self.settings.arkime_default_hours}
        if start_ms is not None or stop_ms is not None:
            params.pop("date",None)
            if start_ms is not None: params["startTime"]=_epoch_seconds(start_ms)
            if stop_ms is not None: params["stopTime"]=_epoch_seconds(stop_ms)
        r=self.session.get(self.settings.arkime_url+self.settings.arkime_api_path,params=params,auth=self._auth(),timeout=self.settings.tool_timeout_seconds)
        r.raise_for_status(); data=r.json()
        return {"sessions":data.get("data",data.get("sessions",[])),"total":data.get("recordsFiltered",data.get("total")),"provenance":{"url":safe_url(self.settings.arkime_url)+self.settings.arkime_api_path,"expression":expression,"parameters":params}}
    def search_sessions_sampled(self, expression: str, start_ms: int | None=None, stop_ms: int | None=None,
            limit: int=100, all_history: bool=False, sampling: dict[str, Any] | None=None) -> dict[str, Any]:
        """Retrieve a bounded, rank-representative session sample as one adapter operation."""
        cap=max(1,min(int(limit),self.settings.arkime_max_results))
        requested=max(1,min(int((sampling or {}).get("strata",1)),24))
        probe=self.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,length=1,
            all_history=all_history,start=0)
        total_value=probe.get("total")
        provenance=probe.get("provenance",{})
        if not isinstance(total_value,(int,float)):
            result=self.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,length=cap,
                all_history=all_history,start=0)
            rows=list(result.get("sessions",[]))[:cap]
            return {"sessions":rows,"total":None,"requests":2,"pages":1,"capped":len(rows)>=cap,
                "duplicates_suppressed":0,"provenance":result.get("provenance",provenance),
                "sampling":{"version":1,"strategy":"earliest_fallback","requested_strata":requested,
                    "covered_strata":1 if rows else 0,"retained_by_stratum":[len(rows)],
                    "matched_by_stratum":[len(rows)],
                    "fallback_reason":"unknown_total"}}
        total=max(0,int(total_value))
        if total<=cap:
            result=self.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,length=max(1,total),
                all_history=all_history,start=0)
            rows=list(result.get("sessions",[]))[:cap]
            return {"sessions":rows,"total":total,"requests":2,"pages":1,"capped":False,
                "duplicates_suppressed":0,"provenance":result.get("provenance",provenance),
                "sampling":{"version":1,"strategy":"exhaustive","requested_strata":1,
                    "covered_strata":1 if total else 0,"retained_by_stratum":[len(rows)],
                    "matched_by_stratum":[len(rows)]}}
        windows=rank_windows(total,cap,requested)
        sessions=[]; seen=set(); duplicates=0; retained=[]; matched_by=[]; sampled_windows=[]; requests=1; offset_limited=False
        for window in windows:
            offset=int(window["offset"]); length=int(window["length"])
            if offset>10_000_000:
                offset_limited=True; retained.append(0); matched_by.append(None)
                sampled_windows.append({**window,"status":"offset_limit","retained":0})
                continue
            request_length=min(self.settings.arkime_max_results,length+min(len(seen),length))
            result=self.search_sessions(expression,start_ms=start_ms,stop_ms=stop_ms,length=request_length,
                all_history=all_history,start=offset)
            requests+=1; added=0
            result_rows=list(result.get("sessions",[])); matched_by.append(min(len(result_rows),length))
            for row in result_rows:
                key=_session_key(row)
                if key in seen:
                    duplicates+=1; continue
                seen.add(key); sessions.append(row); added+=1
                if added>=length or len(sessions)>=cap: break
            retained.append(added)
            sampled_windows.append({**window,"status":"covered","retained":added})
        covered=sum(1 for item in sampled_windows if item["status"]=="covered")
        summary={"version":1,"strategy":"rank_stratified","requested_strata":len(windows),
            "covered_strata":covered,"retained_by_stratum":retained,"matched_by_stratum":matched_by,
            "windows":sampled_windows}
        if offset_limited: summary["fallback_reason"]="arkime_offset_limit"
        return {"sessions":sessions,"total":total,"requests":requests,"pages":covered,"capped":True,
            "duplicates_suppressed":duplicates,"provenance":provenance,"sampling":summary}
    def get_session(self, session_id: str) -> dict[str, Any]:
        if not _safe_session_id(session_id): raise ValueError("Invalid Arkime session id")
        r=self.session.get(self.settings.arkime_url+"/api/session/"+quote(session_id,safe=""),auth=self._auth(),timeout=self.settings.tool_timeout_seconds); r.raise_for_status(); return r.json()
    def retrieve_pcap(self, session_ids: list[str], max_bytes: int=16*1024*1024) -> bytes:
        """Fetch PCAP for explicit session IDs only; never export an unbounded expression."""
        if not session_ids or len(session_ids)>20 or any(not _safe_session_id(x) for x in session_ids):
            raise ValueError("Provide 1-20 validated Arkime session IDs")
        url=self.settings.arkime_url+"/api/sessions/pcap"
        response=self.session.get(url,params={"ids":",".join(session_ids)},auth=self._auth(),timeout=self.settings.tool_timeout_seconds,stream=True)
        try:
            response.raise_for_status(); chunks=[]; total=0
            for chunk in response.iter_content(chunk_size=64*1024):
                if not chunk: continue
                total+=len(chunk)
                if total>max_bytes: raise ValueError("Arkime PCAP response exceeded configured byte cap")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            if hasattr(response,"close"): response.close()

def _epoch_seconds(ms: int) -> int:
    if not 0 <= int(ms) <= 4102444800000: raise ValueError("Arkime timestamps out of range")
    return int(ms/1000)

def _safe_session_id(value: str) -> bool:
    return isinstance(value,str) and bool(re.fullmatch(r"[A-Za-z0-9@:_-]{1,256}",value))

def _session_key(row: Any) -> str:
    if not isinstance(row,dict): return repr(row)
    if row.get("id") is not None: return "id:"+str(row["id"])
    values=(row.get("firstPacket"),row.get("source.ip",row.get("srcIp")),
        row.get("destination.ip",row.get("dstIp")),row.get("source.port",row.get("srcPort")),
        row.get("destination.port",row.get("dstPort")))
    return "tuple:"+repr(values)
