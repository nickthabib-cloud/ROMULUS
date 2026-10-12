"""Read-only Elasticsearch adapter using the official Python client."""
from typing import Any
from ..config import Settings

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
    def search_many(self, indices: list[str], query: dict[str, Any], size: int = 100) -> dict[str, Any]:
        approved=[self._validate_index(index) for index in indices]
        if not approved: return {"hits":[],"total":0}
        validate_query(query); size=max(1,min(int(size),self.settings.max_results))
        client=self.connect(); index_csv=",".join(approved); pit_id=None; rows=[]; total=None
        timed_out=False; shard_failures=0; used_pit=False
        timestamp=_range_field(query)
        sort=([{timestamp:{"order":"asc","unmapped_type":"date"}}] if timestamp else [])+["_shard_doc"]
        try:
            pit=client.open_point_in_time(index=index_csv,keep_alive="1m")
            pit_id=pit.get("id") if hasattr(pit,"get") else None
        except Exception:
            pit_id=None
        try:
            if pit_id:
                used_pit=True; search_after=None
                while len(rows)<size:
                    page_size=min(1000,size-len(rows))
                    kwargs={"pit":{"id":pit_id,"keep_alive":"1m"},"query":query,"size":page_size,
                            "sort":sort,"track_total_hits":True,"source":True,"timeout":f"{self.settings.tool_timeout_seconds}s"}
                    if search_after is not None: kwargs["search_after"]=search_after
                    result=client.search(**kwargs); page=result.get("hits",{}).get("hits",[])
                    total=result.get("hits",{}).get("total",total); timed_out=timed_out or bool(result.get("timed_out"))
                    shard_failures+=int(result.get("_shards",{}).get("failed",0) or 0)
                    rows.extend(page)
                    if not page or len(page)<page_size: break
                    search_after=page[-1].get("sort")
                    if not search_after: break
            else:
                # Older clusters or narrowly privileged users may not permit a
                # PIT. Keep a bounded fallback and mark it so coverage cannot be
                # mistaken for an exhaustive search.
                window=min(size,10000)
                result=client.search(index=index_csv,query=query,size=window,track_total_hits=True,source=True,
                                     timeout=f"{self.settings.tool_timeout_seconds}s")
                rows=result.get("hits",{}).get("hits",[]); total=result.get("hits",{}).get("total")
                timed_out=bool(result.get("timed_out")); shard_failures=int(result.get("_shards",{}).get("failed",0) or 0)
        finally:
            if pit_id:
                try: client.close_point_in_time(id=pit_id)
                except Exception: pass
        total_value=total.get("value") if isinstance(total,dict) else total
        total_relation=total.get("relation") if isinstance(total,dict) else ("eq" if isinstance(total,(int,float)) else "unknown")
        capped=(isinstance(total_value,(int,float)) and total_value>len(rows)) or (not used_pit and len(rows)>=min(size,10000))
        return {"hits":[h.get("_source",{}) | {"_index":h.get("_index"),"_id":h.get("_id")} for h in rows[:size]],
                "total":total_value,"total_relation":total_relation,"capped":capped,"timed_out":timed_out,
                "shard_failures":shard_failures,"pagination":"pit_search_after" if used_pit else "bounded_single_page"}
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
