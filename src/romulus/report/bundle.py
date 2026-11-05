"""Write all report renderings and their referenced host streams from one manifest."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from romulus.report import executive, markdown


def write_reports(repo, manifest, directory):
    directory.mkdir(parents=True, exist_ok=True)
    stem = manifest["revision"]["id"]
    if Path(stem).name != stem or any(char in stem for char in ("/", "\\")) or stem in ("", ".", ".."):
        raise ValueError("Invalid report revision filename")
    paths = {ext: directory/f"{stem}.{ext}" for ext in ("json", "md", "docx")}
    for finding in manifest["findings"]:
        if not (ref := finding.get("fleet_hosts")):
            continue
        # Paths are derived from the content digest, never a telemetry-controlled filename.
        snapshot = ref["sha256"]
        if len(snapshot) != 64 or any(char not in "0123456789abcdef" for char in snapshot):
            raise ValueError("Invalid host appendix digest")
        if ref["filename"] != f"fleet-hosts-{snapshot}.jsonl":
            raise ValueError("Invalid host appendix filename")
        hasher, count, temporary = hashlib.sha256(), 0, None
        try:
            with NamedTemporaryFile(dir=directory, prefix=".fleet-", suffix=".tmp", delete=False) as output:
                temporary = Path(output.name)
                for row in repo.report_hosts(manifest["hunt"]["id"], snapshot):
                    line = repo.report_host_line(row).encode("utf-8")
                    hasher.update(line)
                    output.write(line)
                    count += 1
            if count != ref["count"] or hasher.hexdigest() != snapshot:
                raise ValueError("Host appendix differs from its report manifest")
            os.replace(temporary, directory/ref["filename"])
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    if visibility := manifest["coverage"].get("zeek_visibility"):
        ref = visibility["snapshot"]
        snapshot = ref["sha256"]
        if (len(snapshot) != 64 or any(char not in "0123456789abcdef" for char in snapshot)
                or ref["filename"] != f"zeek-visibility-{snapshot}.jsonl"):
            raise ValueError("Invalid visibility appendix reference")
        hasher, count, temporary = hashlib.sha256(), 0, None
        try:
            with NamedTemporaryFile(dir=directory, prefix=".visibility-", suffix=".tmp", delete=False) as output:
                temporary = Path(output.name)
                for row in repo.zeek_visibility_rows(manifest["hunt"]["id"], snapshot):
                    line = repo.zeek_visibility_line(row).encode("utf-8")
                    output.write(line)
                    hasher.update(line)
                    count += 1
            if count != ref["count"] or hasher.hexdigest() != snapshot:
                raise ValueError("Zeek visibility appendix differs from its report manifest")
            os.replace(temporary, directory/ref["filename"])
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    staged = {}
    try:
        for ext in paths:
            with NamedTemporaryFile(dir=directory, prefix=".report-", suffix=".tmp", delete=False) as output:
                staged[ext] = Path(output.name)
        with staged["md"].open("w", encoding="utf-8") as output:
            output.writelines(markdown.iter_render(manifest, host_rows=lambda ref: repo.report_hosts(
                manifest["hunt"]["id"], ref["sha256"]), visibility_rows=lambda ref: repo.zeek_visibility_rows(
                    manifest["hunt"]["id"], ref["sha256"])))
        executive.write(manifest, staged["docx"], paths["md"].name)
        staged["json"].write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        # All renderers have completed before any existing revision file is replaced.
        for ext, temporary in staged.items():
            os.replace(temporary, paths[ext])
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    return paths
