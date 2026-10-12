"""Preserve fixture daemon logs and capture bounded, checked public copies."""
from __future__ import annotations
import hashlib
import json
import shutil
from pathlib import Path
from .trace import TraceStore, MAX_RECORD_BYTES


def collect_daemon_logs(run):
    run=Path(run);destination=run/'daemon-logs';files=[]
    trace=TraceStore(run)
    try:
        sources=[*(run/'test-data').rglob('*.log'),*(run/'bitcoind-snapshot').rglob('*.log')]
        for source in sorted(sources):
            if source.name not in {'stdout.log','stderr.log','debug.log'}:continue
            if source.is_symlink() or any(parent.is_symlink() for parent in source.parents):continue
            relative=source.relative_to(run/'test-data') if source.is_relative_to(run/'test-data') else source.relative_to(run)
            target=destination/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            if target.exists():raise FileExistsError('fixture log copy already exists')
            shutil.copyfile(source,target)
            with source.open('rb') as stream:raw=stream.read(MAX_RECORD_BYTES+1)
            metadata={'component':str(relative.parent),'stream':source.name,'bytes':source.stat().st_size,
                      'truncated':len(raw)>MAX_RECORD_BYTES}
            reference=trace.capture('test.run',metadata,raw=raw)
            with target.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            files.append({'path':str(Path('daemon-logs')/relative),'bytes':source.stat().st_size,
                          'sha256':digest,'trace':reference})
        manifest={'schema_version':1,'files':files,'public_trace_checked':True,
                  'private_fixture_artifacts_excluded':True}
        (run/'daemon-logs.json').write_text(json.dumps(manifest,indent=2)+'\n')
        return manifest
    finally:trace.close()
