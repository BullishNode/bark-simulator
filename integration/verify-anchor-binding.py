#!/usr/bin/env python3
"""Check a genuine exported coin against matching and mismatched backing bytes."""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from simulator.bundle_audit import ReplayCore, archived_transactions, decode_transaction
from simulator.model import canonical


class ChangedAnchor(ReplayCore):
    def __init__(self, genesis, transactions, anchor):
        super().__init__(genesis, transactions)
        self.anchor = anchor

    def call(self, method, params):
        result = super().call(method, params)
        if method == 'getrawtransaction' and params[0] == self.anchor and isinstance(result, str):
            raw = bytes.fromhex(result)
            lock_time = (int.from_bytes(raw[-4:], 'little') + 1) % (1 << 32)
            result = (raw[:-4] + lock_time.to_bytes(4, 'little')).hex()
            assert decode_transaction(result)['txid'] != self.anchor
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--proof-binary', type=Path, required=True)
    args = parser.parse_args()
    transactions = archived_transactions(args.bundle / 'raw-rpc')
    checked = []
    for path in sorted((args.bundle / 'proofs').glob('*.json')):
        coin = json.loads(path.read_text())
        proof = coin['proof']
        anchor = proof['chain_anchor'].split(':')[0]
        request = next(r for r in coin['requests'] if r.get('signed_vtxo') == coin['signed_vtxo'] and r.get('key_link_attestation'))
        with tempfile.TemporaryDirectory(prefix='anchor-binding-fixture-') as temp:
            credential = Path(temp) / 'public-rpc-auth'
            credential.write_text('public-replay:unused'); credential.chmod(0o600)
            outcomes = []
            for adapter in (ReplayCore(proof['genesis'], transactions), ChangedAnchor(proof['genesis'], transactions, anchor)):
                with adapter as core:
                    result = subprocess.run([str(args.proof_binary.resolve()), core.url, str(credential), proof['server_pubkey']], input=canonical(request), text=True, capture_output=True, timeout=30)
                outcomes.append(result)
        print(json.dumps({'coin_id':coin['id'],'matching_exit_code':outcomes[0].returncode,'changed_anchor_exit_code':outcomes[1].returncode,'changed_anchor_error':outcomes[1].stderr.strip()}),file=sys.stderr)
        assert outcomes[0].returncode == 0, 'genuine matching backing must verify'
        assert json.loads(outcomes[0].stdout)['id'] == coin['id']
        assert outcomes[1].returncode != 0, 'verifier accepted backing bytes with a different transaction ID'
        checked.append(coin['id'])
    assert checked, 'a genuine signed coin fixture is required'
    print(json.dumps({'overall': 'PASS', 'genuine_coins_checked': checked, 'matching_backing_accepted': True, 'changed_anchor_transaction_rejected': True}))


if __name__ == '__main__':
    main()
