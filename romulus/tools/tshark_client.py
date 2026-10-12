"""Constrained offline TShark wrapper: no shell, path allowlist, filter grammar allowlist."""
import json, shutil, subprocess, threading
from pathlib import Path
from typing import Any
from ..config import Settings

ALLOWED_FIELDS={"frame.time_epoch","frame.number","frame.len","ip.src","ip.dst","ipv6.src","ipv6.dst","ipv6.addr","ip.addr","tcp.srcport","tcp.dstport","tcp.port","tcp.stream","tcp.flags.syn","tcp.flags.ack","udp.srcport","udp.dstport","udp.port","udp.stream","dns.qry.name","dns.a","http.host","http.request.uri","http.user_agent","tls.handshake.extensions_server_name","smb2.cmd","smb2.filename"}
FILTER_CHARS=set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .:=<>!&|()/-\"'")

class TSharkAdapter:
    def __init__(self, settings: Settings): self.settings=settings
    def check(self) -> dict[str, Any]:
        exe=shutil.which(self.settings.tshark_bin)
        if not exe: return {"available":False,"error":"tshark executable not found"}
        try: p=subprocess.run([exe,"--version"],capture_output=True,text=True,timeout=5,check=False); return {"available":p.returncode==0,"version":p.stdout.splitlines()[0] if p.stdout else "unknown"}
        except Exception as e: return {"available":False,"error":type(e).__name__}
    def inspect(self, pcap_path: str | Path, display_filter: str="", fields: list[str] | None=None, limit: int=100, time_filter: str="") -> dict[str, Any]:
        path=self._approved(pcap_path)
        if time_filter:
            if display_filter: display_filter=f"({display_filter}) && ({time_filter})"
            else: display_filter=time_filter
        if display_filter and (len(display_filter)>512 or any(c not in FILTER_CHARS for c in display_filter)): raise ValueError("Display filter contains unsupported syntax")
        fields=fields or ["frame.number","frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport"]
        if not fields or len(fields)>16 or set(fields)-ALLOWED_FIELDS: raise ValueError("One or more packet fields are not allowlisted")
        exe=shutil.which(self.settings.tshark_bin) or self.settings.tshark_bin
        output_cap=max(1,min(limit,self.settings.max_results))
        # Do not use TShark -c here: it limits packets read before a display
        # filter is applied and creates false negatives for matches later in a
        # capture. Drain the complete filtered stream under the tool timeout,
        # retaining only the configured number of matching rows.
        cmd=[exe,"-n","-r",str(path),"-T","fields","-E","separator=\t","-E","quote=d"]
        if display_filter: cmd += ["-Y",display_filter]
        for field in fields: cmd += ["-e",field]
        process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        lines=[]; errors=[]; counts={"matches":0}
        def read_stdout():
            for line in process.stdout or ():
                counts["matches"]+=1
                if len(lines)<output_cap: lines.append(line.rstrip("\r\n"))
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
        records=[]
        for line in lines:
            vals=next(__import__('csv').reader([line],delimiter="\t",quotechar='"'))
            records.append(dict(zip(fields,vals)))
        return {"packets":records,"count":len(records),"matched_count":counts["matches"],"output_capped":counts["matches"]>output_cap,
                "provenance":{"pcap":str(path),"display_filter":display_filter,"fields":fields,"read_packet_cap":None,
                    "scan_mode":"complete capture or explicit time slice under timeout","time_range":"explicit filter" if time_filter else "entire configured capture"}}
    def _approved(self, path: str | Path) -> Path:
        candidate=Path(path).expanduser().resolve(strict=True)
        if not candidate.is_file() or candidate.suffix.lower() not in {".pcap",".pcapng"}: raise ValueError("Only existing PCAP/PCAPNG files are allowed")
        allowed=[d.resolve() for d in self.settings.pcap_allowed_dirs if d.exists()]
        if not any(candidate.is_relative_to(d) for d in allowed): raise ValueError("PCAP path is outside PCAP_ALLOWED_DIRS")
        return candidate
