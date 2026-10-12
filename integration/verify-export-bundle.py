#!/usr/bin/env python3
"""Verify a public export and replay its payout verdict without client wallets."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from simulator.export_bundle import audit_bundle


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle',type=Path)
    parser.add_argument('--proof-binary',type=Path,help='trusted public native verifier; uses only bundled anchor records')
    args=parser.parse_args()
    print(json.dumps(audit_bundle(args.bundle,proof_binary=args.proof_binary),indent=2))

if __name__=='__main__':main()
