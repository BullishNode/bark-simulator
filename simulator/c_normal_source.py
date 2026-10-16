"""C initial12 source adapter for the existing shared normal Engine hook.

Every invocation collects original full sources and invokes existing reducers.
It opens no SDK wallet, signs nothing and grants no missing six-source/rail gate.
The private launcher supplies admitted bank and fresh native-runtime producers;
no observer or payment body chooses tools, source paths or collection phases.
"""
import copy
from dataclasses import dataclass
import inspect
import math
from pathlib import Path
import re
import time

from .architecture import DIRECT_PER_KEY, profile
from .final_campaign import _source_event
from .model import canonical, integer
from .ownership import EvidenceGap

FIELDS = {'id', 'started_at', 'architecture_profile', 'financial_pins',
          'boundary_id', 'height', 'tip_hash'}
PHASES = {'initial_funding', 'cash'}


def _context(store, observation):
    if (not isinstance(observation, dict) or set(observation) != FIELDS
            or profile(store) != DIRECT_PER_KEY
            or observation['architecture_profile'] != DIRECT_PER_KEY
            or not isinstance(observation['id'], str)
            or re.fullmatch('[0-9a-f]{32}', observation['id']) is None
            or type(observation['started_at']) not in (int, float)
            or not math.isfinite(observation['started_at'])
            or not 0 <= time.time()-observation['started_at'] <= 90
            or type(observation['height']) is not int or observation['height'] < 0
            or not isinstance(observation['tip_hash'], str)
            or re.fullmatch('[0-9a-f]{64}', observation['tip_hash']) is None):
        raise EvidenceGap('exact fresh C source observation required')
    from .c_pilot import declaration
    pilot = declaration(store)
    from .c_execution_context import effective_pins
    if (pilot is None or observation['financial_pins'] != effective_pins(store,pilot['pins'])
            or observation['boundary_id'] != pilot['boundary_id']):
        raise EvidenceGap('unchanged original C pins and boundary required')
    return observation


def _unused(store, observation):
    if store.db.execute("SELECT 1 FROM event WHERE kind='financial_operating_readiness' AND json_extract(payload,'$.source_observation.id')=? LIMIT 1", (observation['id'],)).fetchone():
        raise EvidenceGap('source observation already emitted; collect again')


def bind_source_observation(store, receipt, source, observation):
    """Add invocation provenance only after all existing reducer checks pass."""
    if observation is None:
        return
    _context(store, observation)
    _unused(store, observation)
    for frame in (receipt, source):
        if (frame.get('financial_pins') != observation['financial_pins']
                or frame.get('boundary_id') != observation['boundary_id']
                or (frame.get('height'), frame.get('tip_hash')) !=
                   (observation['height'], observation['tip_hash'])
                or type(frame.get('observed_at')) not in (int, float)
                or not observation['started_at'] <= frame['observed_at'] <= time.time()):
            raise EvidenceGap('new verified source differs from this observation')
    if (receipt.get('complete') is not True or receipt.get('pool_ready') is not False
            or receipt.get('channel_route_ready') is not False):
        raise EvidenceGap('only the actual bounded initial12 source is supported')
    receipt['source_observation'] = copy.deepcopy(observation)


@dataclass(frozen=True)
class Initial12SourceBinding:
    phase: str
    current_startup_path: str


def _new_source(store, result, first, kind, observation):
    sequence = result.get('source_sequence') if isinstance(result, dict) else None
    integer(sequence, 'new original source sequence', 1)
    event, source = _source_event(store, sequence)
    if (sequence <= first or event['kind'] != kind or result.get('source') != source
            or source.get('financial_pins') != observation['financial_pins']
            or source.get('boundary_id') != observation['boundary_id']
            or (source.get('height'), source.get('tip_hash')) !=
               (observation['height'], observation['tip_hash'])
            or type(source.get('observed_at')) not in (int, float)
            or not observation['started_at'] <= source['observed_at'] <= time.time()):
        raise EvidenceGap('this invocation did not collect a new original source')
    return source


def collector(binding, bank_rpc, *, runtime_source_collector):
    """Return the shared hook's async(store,config,chain,snapshot,observation).

    runtime_source_collector has the SAME positional arguments and returns a new
    existing owned_runtime_configuration_verified sequence. It must capture and
    verify actual current native processes/configuration, never relabel an old
    receipt. This adapter authenticates its event, file hash, freshness and pins.
    Missing runtime or final client/target transition evidence remains a hold.
    """
    if (not isinstance(binding, Initial12SourceBinding) or binding.phase not in PHASES
            or not isinstance(binding.current_startup_path, str)
            or not Path(binding.current_startup_path).is_absolute()
            or bank_rpc is None or not callable(getattr(bank_rpc, 'call', None))
            or not callable(runtime_source_collector)):
        raise EvidenceGap('qualified C initial12 phase and private source producers required')

    async def collect(store, config, chain, snapshot, observation):
        original = canonical(_context(store, observation))
        _unused(store, observation)
        from . import c_cohort
        from .identity_bootstrap import declaration, _context as driver_context
        from .runtime_startup import _read
        from .target_epochs import verified_runtime_source
        declared = declaration(store)
        selected = c_cohort.prospective_funding_policy(store)
        if (declared is None or selected.get('opening_kind') != 'unfunded_initial12'
                or selected['customers'] != set(c_cohort.INITIAL)
                or getattr(config, 'architecture_profile', None) != DIRECT_PER_KEY
                or getattr(store, 'trace', None) is None or chain is None):
            raise EvidenceGap('complete traced declared C initial12 profile required')
        identities = (c_cohort.initial_identity_sources(store) if binding.phase == 'initial_funding'
                      else c_cohort.historical_initial_identity_sources(store))
        if set(identities['actors']) != selected['customers']:
            raise EvidenceGap('complete original12 native identity provenance required')
        driver_context(config, declared['declaration'], store=store)
        config.validate_identity(snapshot)
        if (snapshot.get('financial_pins') != observation['financial_pins']
                or (snapshot.get('height'), snapshot.get('tip_hash')) !=
                   (observation['height'], observation['tip_hash'])):
            raise EvidenceGap('actual observation snapshot context differs')
        first = store.db.execute('SELECT COALESCE(MAX(sequence),0) FROM event').fetchone()[0]
        runtime_observation = copy.deepcopy(observation)
        pending = runtime_source_collector(store, config, chain, copy.deepcopy(snapshot), runtime_observation)
        runtime_sequence = await pending if inspect.isawaitable(pending) else pending
        integer(runtime_sequence, 'new runtime source sequence', 1)
        if canonical(runtime_observation) != original:
            raise EvidenceGap('runtime producer changed original observation')
        runtime_event, runtime = _source_event(store, runtime_sequence)
        _, current_sha = _read(binding.current_startup_path)
        verified_runtime_source(store, runtime_sequence,
            origin_pins=observation['financial_pins'], current_source_sha256=current_sha)
        if (runtime_sequence <= first or runtime_event['kind'] != 'owned_runtime_configuration_verified'
                or type(runtime.get('observed_at')) not in (int, float)
                or not observation['started_at'] <= runtime['observed_at'] <= time.time()):
            raise EvidenceGap('new actual loaded runtime evidence required this invocation')
        if binding.phase == 'initial_funding':
            from . import finite_funding_readiness as initial
            fresh = await initial.collect_initial_funding_sources(store, config, chain, bank_rpc,
                runtime_source_sequence=runtime_sequence,
                current_startup_path=binding.current_startup_path,
                boundary_id=observation['boundary_id'])
            source = _new_source(store, fresh, runtime_sequence, 'finite_initial_funding_sources_verified', observation)
            if (set(source.get('customer_source_sequences', {})) != selected['customers']
                    or len(source.get('members', [])) != 15):
                raise EvidenceGap('fresh full initial12 source omitted a member')
            result = initial.record_initial_funding_readiness(store, config, chain,
                fresh['source_sequence'], source_observation=observation)
        else:
            from . import fresh_cash_readiness as cash
            fresh = await cash.collect_fresh_cash_sources(store, config, chain, bank_rpc,
                current_startup_path=binding.current_startup_path)
            source = _new_source(store, fresh, runtime_sequence, 'finite_fresh_cash_sources_verified', observation)
            if set(source.get('actors', [])) != selected['customers'] or len(source.get('members', [])) != 15:
                raise EvidenceGap('fresh full cash source omitted a member')
            result = cash.record_fresh_cash_readiness(store, config, chain,
                source_sequence=fresh['source_sequence'], runtime_source_sequence=runtime_sequence,
                current_startup_path=binding.current_startup_path, source_observation=observation)
        if canonical(observation) != original:
            raise EvidenceGap('source observation mutated during collection')
        sequence = result['operating_readiness_sequence']
        integer(sequence, 'new matching readiness sequence', 1)
        event, proof = _source_event(store, sequence)
        if (sequence <= fresh['source_sequence'] or event['kind'] != 'financial_operating_readiness'
                or proof.get('source_observation') != observation):
            raise EvidenceGap('new original matching readiness was not emitted')
        return sequence
    return collect
