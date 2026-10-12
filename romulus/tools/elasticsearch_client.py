"""Read-only Elasticsearch adapter using the official Python client."""
from datetime import datetime, timezone
from typing import Any
from ..config import Settings
from ..investigation.sampling import allocate_cap, time_strata

class ElasticsearchAdapter:
    def __init__(self, settings: Settings, client: Any = None):
        self.settings=settings; self.client=client
    def connect(self):
        if self.client is not None: return self.client
        try: from elasticsearch import Elasticsearch
        except ImportError as e: raise RuntimeError("Install requirements.txt for Elasticsearch support") from e
        kwargs={"hosts":[self.settings.es_url],"request_timeout":self.settings.tool_timeout_seconds,"max_retries":self.settings.max_retries,"retry_on_timeout":True,"verify_certs":self.settings.es_verify_tls}
        if self.settings.es_username: kwargs["basic_auth"]=(self.settings.es_username,self.settings.es_password)
        self.client=Elasticsearch(**kwargs); return self.client
    def check(self) -> dict[str, Any]:
        try:
            rows=self.indices()
            return {"available":bool(rows),"authenticated":True,"matched_indices":len(rows)}
        except Exception as e: return {"available":False,"error":type(e).__name__}
    def indices(self) -> list[dict[str, Any]]:
        # GET /{index} is covered by view_index_metadata; CAT indices needs broader
        # monitoring privileges and was the source of the deployment authorization error.
        patterns=",".join(self.settings.es_index_patterns)
        try:
            response=self.connect().indices.get(index=patterns,allow_no_indices=True,expand_wildcards="open")
        except Exception as e:
            if type(e).__name__ in {"NotFoundError","NotFoundException"}: return []
            raise
        return [{"index":name} for name in sorted(response.keys()) if self._validate_index(name,raise_error=False)]
    def mappings(self, index: str) -> dict[str, Any]:
        self._validate_index(index)
        return self.connect().indices.get_mapping(index=index)
    def mappings_many(self, indices: list[str]) -> dict[str, Any]:
        approved=[self._validate_index(index) for index in indices]
        return self.connect().indices.get_mapping(index=",".join(approved))
    def search(self, index: str, query: dict[str, Any], size: int = 100) -> dict[str, Any]:
        return self.search_many([index],query,size)
    def search_many(self, indices: list[str], query: dict[str, Any], size: int = 100, *,
                    timestamp_field: str | None = None, time_range: dict[str, Any] | None = None,
                    sampling: dict[str, Any] | None = None) -> dict[str, Any]:
        approved=[self._validate_index(index) for index in indices]
        if not approved: return {"hits":[],"total":0}
        validate_query(query); size=max(1,min(int(size),self.settings.max_results))
        client=self.connect(); index_csv=",".join(approved); pit_id=None; rows=[]; total=None
        timed_out=False; shard_failures=0; used_pit=False
        timestamp=timestamp_field or _range_field(query)
        sort=([{timestamp:{"order":"asc","unmapped_type":"date","format":"strict_date_optional_time_nanos"}}] if timestamp else [])+["_shard_doc"]
        sampling_summary={"version":int((sampling or {}).get("version",1)),"strategy":"exhaustive",
            "requested_strata":1,"covered_strata":1,"retained_by_stratum":[]}
        try:
            pit=client.open_point_in_time(index=index_csv,keep_alive="1m")
            pit_id=pit.get("id") if hasattr(pit,"get") else None
        except Exception:
            pit_id=None
        try:
            if pit_id:
                used_pit=True
                initial=_pit_search(client,pit_id,query,size,sort,self.settings.tool_timeout_seconds)
                rows=initial["rows"]; total=initial["total"]
                timed_out=initial["timed_out"]; shard_failures=initial["shard_failures"]
                total_value=_total_value(total)
                should_sample=bool(timestamp and sampling and isinstance(total_value,(int,float)) and total_value>len(rows))
                if should_sample:
                    try:
                        bounds=_sampling_bounds(time_range)
                        bounds_source="task_time_range"
                        if bounds is None:
                            first_value=_hit_sort_time(rows[0]) if rows else None
                            descending=[{timestamp:{"order":"desc","unmapped_type":"date","format":"strict_date_optional_time_nanos"}},"_shard_doc"]
                            last_result=_pit_search(client,pit_id,query,1,descending,self.settings.tool_timeout_seconds)
                            last_value=_hit_sort_time(last_result["rows"][0]) if last_result["rows"] else None
                            bounds=_datetime_bounds(first_value,last_value)
                            bounds_source="matching_extrema"
                            timed_out=timed_out or last_result["timed_out"]
                            shard_failures+=last_result["shard_failures"]
                        if bounds is None: raise ValueError("matching time bounds unavailable")
                        allocations=allocate_cap(size,int(sampling.get("strata",self.settings.time_sampling_strata)))
                        strata=time_strata(bounds[0],bounds[1],len(allocations))
                        sampled=[]; seen=set(); retained=[]; matched_by=[]; covered=0
                        for stratum,quota in zip(strata,allocations):
                            bounded_query=_with_time_stratum(query,timestamp,stratum)
                            result=_pit_search(client,pit_id,bounded_query,quota,sort,self.settings.tool_timeout_seconds)
                            timed_out=timed_out or result["timed_out"]
                            shard_failures+=result["shard_failures"]
                            stratum_total=_total_value(result["total"])
                            matched_by.append(int(stratum_total) if isinstance(stratum_total,(int,float)) else None)
                            accepted=0
                            for hit in result["rows"]:
                                identity=(str(hit.get("_index") or ""),str(hit.get("_id") or ""))
                                if identity in seen: continue
                                seen.add(identity); sampled.append(hit); accepted+=1
                            retained.append(accepted)
                            if stratum_total or accepted: covered+=1
                        rows=sampled[:size]
                        sampling_summary={"version":int(sampling.get("version",1)),"strategy":"time_stratified",
                            "bounds_source":bounds_source,"requested_strata":len(strata),"covered_strata":covered,
                            "retained_by_stratum":retained,"matched_by_stratum":matched_by}
                    except Exception as exc:
                        sampling_summary={"version":int((sampling or {}).get("version",1)),"strategy":"earliest_fallback",
                            "requested_strata":int((sampling or {}).get("strata",1)),"covered_strata":1,
                            "retained_by_stratum":[len(rows)],"fallback_reason":type(exc).__name__}
                else:
                    sampling_summary["retained_by_stratum"]=[len(rows)]
            else:
                # Older clusters or narrowly privileged users may not permit a
                # PIT. Keep a bounded fallback and mark it so coverage cannot be
                # mistaken for an exhaustive search.
                window=min(size,10000)
                result=client.search(index=index_csv,query=query,size=window,track_total_hits=True,source=True,
                                     timeout=f"{self.settings.tool_timeout_seconds}s")
                rows=result.get("hits",{}).get("hits",[]); total=result.get("hits",{}).get("total")
                timed_out=bool(result.get("timed_out")); shard_failures=int(result.get("_shards",{}).get("failed",0) or 0)
                sampling_summary={"version":int((sampling or {}).get("version",1)),"strategy":"bounded_single_page",
                    "requested_strata":int((sampling or {}).get("strata",1)),"covered_strata":1,
                    "retained_by_stratum":[len(rows)],"fallback_reason":"point_in_time_unavailable"}
        finally:
            if pit_id:
                try: client.close_point_in_time(id=pit_id)
                except Exception: pass
        total_value=_total_value(total)
        total_relation=total.get("relation") if isinstance(total,dict) else ("eq" if isinstance(total,(int,float)) else "unknown")
        capped=(isinstance(total_value,(int,float)) and total_value>len(rows)) or (not used_pit and len(rows)>=min(size,10000))
        return {"hits":[h.get("_source",{}) | {"_index":h.get("_index"),"_id":h.get("_id")} for h in rows[:size]],
                "total":total_value,"total_relation":total_relation,"capped":capped,"timed_out":timed_out,
                "shard_failures":shard_failures,"pagination":"pit_search_after" if used_pit else "bounded_single_page",
                "sampling":sampling_summary}
    def _validate_index(self,index: str,raise_error: bool=True):
        if not index or not any(index == p or (p.endswith("*") and index.startswith(p[:-1])) for p in self.settings.es_index_patterns):
            if not raise_error: return False
            raise ValueError("Index is outside configured ES_INDEX_PATTERNS allowlist")
        return index

def validate_query(q: dict[str, Any], depth: int=0) -> None:
    if not isinstance(q,dict) or depth>12 or len(q)>12: raise ValueError("Query structure exceeds limits")
    allowed={"bool","term","terms","match","match_phrase","range","exists","prefix","wildcard"}
    for key,value in q.items():
        if key not in allowed: raise ValueError(f"Unsupported Elasticsearch query clause: {key}")
        if key=="bool":
            if not isinstance(value,dict) or set(value)-{"must","filter","should","must_not","minimum_should_match"}: raise ValueError("Invalid bool query")
            for k,v in value.items():
                if k!="minimum_should_match":
                    seq=v if isinstance(v,list) else [v]
                    for child in seq: validate_query(child,depth+1)
        elif key in {"wildcard","prefix"}:
            if isinstance(value,dict) and any("*" in str(v) or "?" in str(v) for v in value.values()): raise ValueError("Broad wildcard queries are not allowed")
        elif not isinstance(value,dict): raise ValueError("Query clause must be an object")

def _range_field(value: Any) -> str | None:
    if not isinstance(value,dict): return None
    for key,item in value.items():
        if key=="range" and isinstance(item,dict):
            return next(iter(item),None)
        if isinstance(item,dict):
            found=_range_field(item)
            if found: return found
        elif isinstance(item,list):
            for child in item:
                found=_range_field(child)
                if found: return found
    return None


def _pit_search(client: Any, pit_id: str, query: dict[str, Any], size: int, sort: list[Any], timeout: int) -> dict[str, Any]:
    rows=[]; total=None; timed_out=False; shard_failures=0; search_after=None
    while len(rows)<size:
        page_size=min(1000,size-len(rows))
        kwargs={"pit":{"id":pit_id,"keep_alive":"1m"},"query":query,"size":page_size,
            "sort":sort,"track_total_hits":True,"source":True,"timeout":f"{timeout}s"}
        if search_after is not None: kwargs["search_after"]=search_after
        result=client.search(**kwargs); page=result.get("hits",{}).get("hits",[])
        total=result.get("hits",{}).get("total",total); timed_out=timed_out or bool(result.get("timed_out"))
        shard_failures+=int(result.get("_shards",{}).get("failed",0) or 0); rows.extend(page)
        if not page or len(page)<page_size: break
        search_after=page[-1].get("sort")
        if not search_after: break
    return {"rows":rows,"total":total,"timed_out":timed_out,"shard_failures":shard_failures}


def _total_value(total: Any) -> int | float | None:
    return total.get("value") if isinstance(total,dict) else total


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value,(int,float)) and not isinstance(value,bool):
        seconds=float(value)/1000 if abs(float(value))>10_000_000_000 else float(value)
        try: return datetime.fromtimestamp(seconds,tz=timezone.utc)
        except (OverflowError,OSError,ValueError): return None
    if not isinstance(value,str) or not value.strip(): return None
    text=value.strip()
    if text.endswith("Z"): text=text[:-1]+"+00:00"
    try: parsed=datetime.fromisoformat(text)
    except ValueError: return None
    if parsed.tzinfo is None: return None
    return parsed.astimezone(timezone.utc)


def _sampling_bounds(time_range: dict[str, Any] | None) -> tuple[datetime,datetime] | None:
    if not isinstance(time_range,dict): return None
    start=_parse_datetime(time_range.get("gte")); end=_parse_datetime(time_range.get("lte"))
    return (start,end) if start and end and start<end else None


def _hit_sort_time(hit: dict[str, Any]) -> Any:
    values=hit.get("sort")
    return values[0] if isinstance(values,list) and values else None


def _datetime_bounds(first: Any,last: Any) -> tuple[datetime,datetime] | None:
    start=_parse_datetime(first); end=_parse_datetime(last)
    if not start or not end: return None
    if start==end:
        from datetime import timedelta
        end=start+timedelta(microseconds=1)
    return (start,end) if start<end else None


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00","Z")


def _with_time_stratum(query: dict[str, Any],timestamp: str,stratum: dict[str, Any]) -> dict[str, Any]:
    upper="lte" if stratum.get("include_end") else "lt"
    bounds={"gte":_iso(stratum["start"]),upper:_iso(stratum["end"])}
    return {"bool":{"filter":[query,{"range":{timestamp:bounds}}]}}
