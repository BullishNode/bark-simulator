#!/bin/bash
# Run via SSH stdin; read-only, no configuration rendering or service changes.
set -euo pipefail
cd /home/ubuntu/abandon-signet-fallback/deploy
python3 - <<'PY'
import json, os, pathlib, subprocess, tomllib

def command(args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=30).stdout

configuration=tomllib.loads(pathlib.Path('state/signet-fallback/captaind.toml').read_text())
public={'network':configuration.get('network'), 'vtxo_lifetime':configuration.get('vtxo_lifetime'),
        'lightning_node_count':len(configuration.get('cln_array',[])),
        'expiry_payout':{k:configuration.get('expiry_payout',{}).get(k) for k in ('enabled','interval','grace_blocks','sweep_min_confs','min_payout_sat','conf_target_blocks')}}
identity=command(['sudo','-n','docker','inspect','--format',
 '{"container":{{json .Name}},"image_digest":{{json .Image}},"status":{{json .State.Status}},"networks":{{json .NetworkSettings.Networks}}}',
 'abandon-signet-fallback-fb-captaind-1'])
identity=json.loads(identity)
identity['networks']={name:{'ip':value.get('IPAddress')} for name,value in identity['networks'].items()}
rounds=json.loads(command(['./fallback/ops.sh','capt','rpc','wallet']))
chain=json.loads(command(['./fallback/ops.sh','cli','getblockchaininfo']))
print(json.dumps({'configuration':public,'identity':identity,'rounds':rounds,
 'chain':{k:chain.get(k) for k in ('chain','blocks','bestblockhash','initialblockdownload')},
 'resources':{'logical_cpus':os.cpu_count(),'meminfo':{line.split(':')[0]:line.split(':')[1].strip() for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))},
 'docker_disk':command(['df','-B1','/var/lib/docker']).strip() }},indent=2))
PY
