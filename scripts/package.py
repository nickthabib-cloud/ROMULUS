"""Build ROMULUS.zip without local secrets, runtime state, caches, or VCS metadata."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT=Path(__file__).resolve().parents[1]
ARCHIVE=ROOT/"ROMULUS.zip"
EXCLUDED={".git","__pycache__",".venv",".verify-venv",".verify-deps",".test-venv",".pytest_cache"}
INCLUDED_RUNTIME_MARKERS={".gitkeep"}

def main():
    with ZipFile(ARCHIVE,"w",ZIP_DEFLATED,compresslevel=9) as z:
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or path==ARCHIVE: continue
            rel=path.relative_to(ROOT)
            if any(part in EXCLUDED for part in rel.parts): continue
            if any(part in {"data","logs","reports"} for part in rel.parts) and path.name!=".gitkeep": continue
            if path.name==".env" or path.suffix in {".pyc",".pyo"}: continue
            if path.name in INCLUDED_RUNTIME_MARKERS and rel.parts[0] not in {"data","logs","reports"}: continue
            if any(part.startswith("tmp") for part in rel.parts): continue
            z.write(path,rel.as_posix())
    print(f"Created {ARCHIVE} ({ARCHIVE.stat().st_size:,} bytes)")

if __name__=="__main__": main()
