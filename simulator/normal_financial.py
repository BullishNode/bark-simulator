"""Bind a genuine normal producer to each Engine observation.

The collector is an explicitly installed, source-qualified Python dependency,
not a command selected by an observer response. It owns the independent money
proofs. This module authenticates its new journal result and never manufactures
readiness from a partial source, a supplied flag, or a historical sequence.
"""
import json
import time
import uuid

from .architecture import profile
from .final_campaign import _pins, _source_event
from .model import canonical, integer
from .operating_limits import envelope
from .ownership import EvidenceGap

KEY = 'normal_financial_collection_required'


def _tip(chain, config):
    value = chain.identity()
    if (chain.call('getblockhash', 0) != config.expected_genesis
            or value.get('chain') != config.network
            or value.get('initialblockdownload') is not False):
        raise EvidenceGap('independent normal financial chain identity unavailable')
    return value


def validate_collection(store, snapshot, *, now=None):
    """A source-qualified producer result must belong to this fresh collection."""
    now = time.time() if now is None else now
    event, collected = _source_event(store, snapshot.get('financial_collection_sequence'))
    proof_event, proof = _source_event(store, snapshot.get('operating_readiness_sequence'))
    context = collected.get('observation', {})
    if (event['kind'] != 'normal_financial_source_collected'
            or proof_event['kind'] != 'financial_operating_readiness'
            or collected.get('readiness_sequence') != proof_event['sequence']
            or collected.get('readiness_event_hash') != proof_event['hash']
            or proof_event['sequence'] >= event['sequence']
            or proof.get('source_observation') != context
            or context.get('architecture_profile') != profile(store)
            or context.get('financial_pins') != snapshot.get('financial_pins')
            or (context.get('height'), context.get('tip_hash')) !=
               (snapshot.get('height'), snapshot.get('tip_hash'))
            or not 0 <= now-collected.get('completed_at', -1) <= 90
            or not 0 <= now-proof.get('observed_at', -1) <= 90):
        raise EvidenceGap('normal readiness lacks its fresh original collection')
    return proof


async def collect(store, config, chain, snapshot, collector):
    """Call the admitted producer under the existing Engine Store/Lease.

    Contract: await collector(store, config, chain, snapshot, observation),
    returning the integer sequence of its newly verified readiness event. Its
    proof includes source_observation unchanged. The collector must authenticate
    exhaustive membership, original liabilities/costs, actual signer enforcement,
    R/F, fee history and independent chain evidence before writing that event.
    Its source and private tools require separate qualification; this hook does
    not qualify a collector or allow it to dispatch wallets/funds.
    """
    result = {key: value for key, value in snapshot.items()
              if key not in ('operating_readiness_sequence', 'financial_collection_sequence')}
    if collector is None:
        raise EvidenceGap('source-qualified normal financial collector not installed')
    config.validate_identity(result)
    limits = envelope(store, config)
    pins = _pins(result.get('financial_pins'))
    if pins != limits['pins']:
        raise EvidenceGap('normal financial collector pins differ from declaration')
    before = _tip(chain, config)
    if ((before['blocks'], before['bestblockhash']) !=
            (result.get('height'), result.get('tip_hash'))):
        raise EvidenceGap('normal observer and independent financial tip differ')
    started = time.time()
    context = {'id': uuid.uuid4().hex, 'started_at': started,
               'architecture_profile': profile(store), 'financial_pins': pins,
               'boundary_id': limits['boundary_id'],
               'height': before['blocks'], 'tip_hash': before['bestblockhash']}
    original = canonical(context)
    first = store.db.execute('SELECT COALESCE(MAX(sequence),0) FROM event').fetchone()[0]
    sequence = await collector(store, config, chain, dict(result), json.loads(original))
    integer(sequence, 'new normal readiness sequence', 1)
    event, proof = _source_event(store, sequence)
    completed = time.time()
    if (sequence <= first or event['kind'] != 'financial_operating_readiness'
            or proof.get('source_observation') != json.loads(original)
            or proof.get('financial_pins') != pins
            or proof.get('boundary_id') != limits['boundary_id']
            or proof.get('complete') is not True
            or (proof.get('height'), proof.get('tip_hash')) !=
               (before['blocks'], before['bestblockhash'])
            or type(proof.get('observed_at')) not in (int, float)
            or not started <= proof['observed_at'] <= completed
            or not 0 <= completed-started <= 90):
        raise EvidenceGap('normal producer did not verify a new matching source observation')
    for name in ('capital_exposure_msat', 'available_fee_funding_msat'):
        integer(proof.get(name), 'normal financial '+name)
    integer(proof.get('estimated_fee_rate_sat_kvb'), 'actual normal fee quote', 1)
    if proof.get('effective_fee_ceilings_sat_kvb') != limits['fee_ceilings_sat_kvb']:
        raise EvidenceGap('normal producer signer ceilings differ from declaration')
    # Report the real quote even above a quiet ceiling. The existing preflight
    # decides each operation's affordability and preserves separate urgent paths.
    ending = _tip(chain, config)
    completed = time.time()
    if not 0 <= completed-started <= 90:
        raise EvidenceGap('normal financial aggregate deadline exceeded during final independent tip read')
    if ((ending['blocks'], ending['bestblockhash']) !=
            (before['blocks'], before['bestblockhash'])):
        raise EvidenceGap('independent chain changed during normal source verification')
    store.event('normal_financial_source_collected', {
        'observation': json.loads(original), 'readiness_sequence': sequence,
        'readiness_event_hash': event['hash'], 'completed_at': completed})
    result.update(operating_readiness_sequence=sequence,
                  financial_collection_sequence=store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0])
    validate_collection(store, result, now=completed)
    return result
