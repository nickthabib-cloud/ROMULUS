"""Constrained offline TShark wrapper: no shell, path allowlist, filter grammar allowlist."""
import csv, hashlib, heapq, json, shutil, subprocess, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from ..config import Settings
from ..investigation.sampling import allocate_cap, time_strata

ALLOWED_FIELDS={"frame.time_epoch","frame.number","frame.len","ip.src","ip.dst","ipv6.src","ipv6.dst","ipv6.addr","ip.addr","tcp.srcport","tcp.dstport","tcp.port","tcp.stream","tcp.flags.syn","tcp.flags.ack","udp.srcport","udp.dstport","udp.port","udp.stream","dns.qry.name","dns.a","http.host","http.request.uri","http.user_agent","tls.handshake.extensions_server_name","smb2.cmd","smb2.filename"}
FILTER_CHARS=set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .:=<>!&|()/-\"'")

class TSharkAdapter:
    def __init__(self, settings: Settings): self.settings=settings
    def check(self) -> dict[str, Any]:
        exe=shutil.which(self.settings.tshark_bin)
        if not exe: return {"available":False,"error":"tshark executable not found"}
        try: p=subprocess.run([exe,"--version"],capture_output=True,text=True,timeout=5,check=False); return {"available":p.returncode==0,"version":p.stdout.splitlines()[0] if p.stdout else "unknown"}
        except Exception as e: return {"available":False,"error":type(e).__name__}
    def inspect(self, pcap_path: str | Path, display_filter: str="", fields: list[str] | None=None, limit: int=100,
            time_filter: str="", sample_start: datetime | None=None, sample_end: datetime | None=None,
            sampling: dict[str, Any] | None=None) -> dict[str, Any]:
        path=self._approved(pcap_path)
        if time_filter:
            if display_filter: display_filter=f"({display_filter}) && ({time_filter})"
            else: display_filter=time_filter
        if display_filter and (len(display_filter)>512 or any(c not in FILTER_CHARS for c in display_filter)): raise ValueError("Display filter contains unsupported syntax")
        fields=fields or ["frame.number","frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport"]
        if not fields or len(fields)>16 or set(fields)-ALLOWED_FIELDS: raise ValueError("One or more packet fields are not allowlisted")
        requested_fields=list(fields)
        command_fields=list(fields)
        if "frame.time_epoch" not in command_fields: command_fields.append("frame.time_epoch")
        exe=shutil.which(self.settings.tshark_bin) or self.settings.tshark_bin
        output_cap=max(1,min(limit,self.settings.max_results))
        # Do not use TShark -c here: it limits packets read before a display
        # filter is applied and creates false negatives for matches later in a
        # capture. Drain the complete filtered stream under the tool timeout,
        # retaining only the configured number of matching rows.
        cmd=[exe,"-n","-r",str(path),"-T","fields","-E","separator=\t","-E","quote=d"]
        if display_filter: cmd += ["-Y",display_filter]
        for field in command_fields: cmd += ["-e",field]
        process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        errors=[]; counts={"matches":0,"invalid_timestamps":0}
        global_heap=[]
        requested_strata=max(1,min(int((sampling or {}).get("strata",1)),24))
        use_time_sampling=isinstance(sample_start,datetime) and isinstance(sample_end,datetime)
        strata=[]; allocations=[]; stratum_heaps=[]; stratum_matches=[]
        if use_time_sampling:
            allocations=allocate_cap(output_cap,requested_strata)
            strata=time_strata(sample_start,sample_end,len(allocations))
            stratum_heaps=[[] for _ in allocations]
            stratum_matches=[0 for _ in allocations]
        timestamp_index=command_fields.index("frame.time_epoch")
        def read_stdout():
            for line in process.stdout or ():
                ordinal=counts["matches"]; counts["matches"]+=1; raw=line.rstrip("\r\n")
                _offer(global_heap,output_cap,ordinal,raw)
                if use_time_sampling:
                    try:
                        values=next(csv.reader([raw],delimiter="\t",quotechar='"'))
                        observed=datetime.fromtimestamp(float(values[timestamp_index]),tz=timezone.utc)
                        index=next(index for index,item in enumerate(strata)
                            if observed>=item["start"] and (observed<item["end"] or item["include_end"] and observed<=item["end"]))
                    except (ValueError,IndexError,StopIteration,OverflowError):
                        counts["invalid_timestamps"]+=1
                    else:
                        stratum_matches[index]+=1
                        _offer(stratum_heaps[index],allocations[index],ordinal,raw)
        def read_stderr():
            for line in process.stderr or ():
                if sum(len(x) for x in errors)<2000: errors.append(line)
        out_thread=threading.Thread(target=read_stdout,daemon=True); err_thread=threading.Thread(target=read_stderr,daemon=True)
        out_thread.start(); err_thread.start()
        try: return_code=process.wait(timeout=self.settings.tool_timeout_seconds)
        except subprocess.TimeoutExpired as e:
            process.kill(); process.wait(); out_thread.join(timeout=2); err_thread.join(timeout=2)
            raise RuntimeError("TShark exceeded configured timeout while scanning the capture") from e
        out_thread.join(timeout=2); err_thread.join(timeout=2)
        if return_code: raise RuntimeError("TShark failed: "+"".join(errors)[:300])
        matched=counts["matches"]
        global_rows=_ordered(global_heap)
        if matched<=output_cap:
            selected=global_rows
            sampling_summary={"version":1,"strategy":"exhaustive","requested_strata":1,
                "covered_strata":1 if matched else 0,"retained_by_stratum":[len(selected)],
                "matched_by_stratum":[matched]}
        elif use_time_sampling and counts["invalid_timestamps"]==0:
            selected_by_stratum=[_ordered(heap) for heap in stratum_heaps]
            selected=[item for rows in selected_by_stratum for item in rows]
            selected_ordinals={item[0] for item in selected}
            backfill=[item for item in global_rows if item[0] not in selected_ordinals]
            selected=sorted((selected+backfill)[:output_cap],key=lambda item:item[0])
            retained=[len(rows) for rows in selected_by_stratum]
            sampling_summary={"version":1,"strategy":"time_stratified_reservoir",
                "requested_strata":len(strata),"covered_strata":sum(bool(value) for value in retained),
                "retained_by_stratum":retained,"matched_by_stratum":stratum_matches,
                "backfilled":max(0,len(selected)-sum(retained))}
        else:
            selected=global_rows
            reason="malformed_or_missing_timestamp" if counts["invalid_timestamps"] else "missing_time_bounds"
            sampling_summary={"version":1,"strategy":"deterministic_reservoir","requested_strata":1,
                "covered_strata":1 if selected else 0,"retained_by_stratum":[len(selected)],
                "matched_by_stratum":[matched],
                "fallback_reason":reason}
        records=[]
        for _,line in selected:
            vals=next(csv.reader([line],delimiter="\t",quotechar='"'))
            parsed=dict(zip(command_fields,vals))
            records.append({field:parsed.get(field,"") for field in requested_fields})
        return {"packets":records,"count":len(records),"matched_count":counts["matches"],"output_capped":counts["matches"]>output_cap,
                "sampling":sampling_summary,
                "provenance":{"pcap":str(path),"display_filter":display_filter,"fields":requested_fields,"read_packet_cap":None,
                    "scan_mode":"complete capture or explicit time slice under timeout","time_range":"explicit filter" if time_filter else "entire configured capture"}}
    def _approved(self, path: str | Path) -> Path:
        candidate=Path(path).expanduser().resolve(strict=True)
        if not candidate.is_file() or candidate.suffix.lower() not in {".pcap",".pcapng"}: raise ValueError("Only existing PCAP/PCAPNG files are allowed")
        allowed=[d.resolve() for d in self.settings.pcap_allowed_dirs if d.exists()]
        if not any(candidate.is_relative_to(d) for d in allowed): raise ValueError("PCAP path is outside PCAP_ALLOWED_DIRS")
        return candidate


def _offer(heap: list[tuple[int,int,int,str]], cap: int, ordinal: int, line: str) -> None:
    score=int.from_bytes(hashlib.sha256(f"{ordinal}:".encode()+line.encode("utf-8",errors="replace")).digest()[:8],"big")
    item=(-score,-ordinal,ordinal,line)
    if len(heap)<cap: heapq.heappush(heap,item)
    elif item>heap[0]: heapq.heapreplace(heap,item)


def _ordered(heap: list[tuple[int,int,int,str]]) -> list[tuple[int,str]]:
    return sorted(((item[2],item[3]) for item in heap),key=lambda item:item[0])
