"""Fixed C source profile primitives for the existing shared normal collector.

These primitives authenticate C originals; none declares a boundary, upgrades a
populated opening, changes a budget, or emits normal financial readiness. The
whole normal factory must additionally join actual fresh member/runtime, current
liability and joint-fee sources. An incomplete source remains a hold.
"""
import copy
import time
from pathlib import Path

from .architecture import DIRECT_PER_KEY, profile
from . import c_cohort
from .c_normal_source import _context
from .c_normal_target_source import CheckedTargetReader
from .final_campaign import _source_event
from .model import canonical, public_payload
from .ownership import EvidenceGap
from .two_step_normal import digest, module_hash


def initial_history(store, boundary):
    """Authenticate ORIGINAL pre-money12 history, not A exploratory/B money work.

    Completed zero-fee creates retain their original IDs/results and native
    proof events. Historical identity receipts are not relabelled fresh current
    financial sources. All current full-source observations remain separate.
    """
    if profile(store) != DIRECT_PER_KEY:
        raise EvidenceGap('explicit C architecture required for pre-money opening')
    store.verify_event_chain()
    c_cohort._quiescent(store)
    c_cohort._no_money(store)
    identity = c_cohort.historical_initial_identity_sources(store)
    policy = c_cohort.prospective_funding_policy(store)
    from .identity_bootstrap import require_only_verified_creates
    require_only_verified_creates(store, policy['pins'])
    if (policy['opening_kind'] != 'unfunded_initial12'
            or boundary['pins'] != policy['pins'] or boundary['id'] != policy['boundary_id']
            or identity['financial_pins'] != policy['pins']
            or identity['origin_financial_pins'] != policy['origin_financial_pins']
            or set(identity['sources']) != set(c_cohort.INITIAL)
            or identity['actors'] != list(c_cohort.INITIAL)):
        raise EvidenceGap('unchanged original C initial12 source/boundary required')
    actions = [dict(row) for row in store.db.execute('SELECT * FROM action ORDER BY id')]
    expected = {value['create_action_id'] for value in identity['sources'].values()}
    if (len(expected) != 12 or len(actions) != 12 or {row['id'] for row in actions} != expected
            or {row['actor_id'] for row in actions} != set(c_cohort.INITIAL)):
        raise EvidenceGap('exact twelve retained native create actions required')
    from .c_pilot import declaration
    original = declaration(store)
    if original is None or original['pins'] != policy['origin_financial_pins']:
        raise EvidenceGap('original pilot declaration provenance missing')
    # The entire immutable pilot and native ancestry are committed. A larger
    # independently verified physical escrow opening never enlarges its grants,
    # budgets or action authority, and is not a second income/epoch.
    value = {'kind':'c_original_pre_money_initial12_history',
        'financial_pins':copy.deepcopy(policy['pins']),
        'origin_financial_pins':copy.deepcopy(policy['origin_financial_pins']),
        'boundary_id':boundary['id'],'profile_id':policy['profile_id'],
        'action_ids':sorted(expected),'action_rows_sha256':digest(canonical(actions).encode()),
        'original_pilot_sha256':digest(canonical(original).encode()),
        'identity_sources':copy.deepcopy(identity['sources']),
        'identity_closure_sequence':identity['extra10_closure_sequence'],
        'original_fee_budget_sat':int(store.get_meta('fee_budget_sat')),
        'opening_physical_sat':policy['opening_sat'],
        'original_declared_bank_opening_sat':original['bank_opening_sat'],
        'ordinary_budget_sat':policy['ordinary_budget_sat'],
        'urgent_reserve_sat':policy['urgent_budget_sat']}
    public_payload(value)
    return value


class DirectPerKeyProfile:
    """Trusted installed C type, never a config-selected module or callback.

    This first finite slice provides the source/context/opening boundaries.
    It is NOT yet admitted by the shared money Collector: that registration
    requires the full current-source/fee/member reducer implementation.
    """
    architecture = DIRECT_PER_KEY
    public_context_key = 'c_public_context'
    public_context_filename = 'c-public-metadata-context.json'
    backing_source_kind = 'c_native_current_backing'

    def __init__(self, target, *, runtime=None, owning=None, cln=None, members=None):
        if type(target) is not CheckedTargetReader:
            raise EvidenceGap('fixed C checked-target reader required')
        from .c_normal_runtime_source import RuntimeSource
        if runtime is not None and type(runtime) is not RuntimeSource:
            raise EvidenceGap('fixed admitted C runtime producer required')
        self.target = target
        from .c_normal_owning_join import OwningBinding
        if owning is not None:
            if type(owning) is not OwningBinding:raise EvidenceGap('fixed C owning source binding required')
            owning.check()
        self.runtime = runtime
        self.owning = owning
        from .c_normal_cln_join import ClnBinding
        if cln is not None:
            if type(cln) is not ClnBinding:raise EvidenceGap('fixed C two-host CLN binding required')
            cln.check()
        self.cln = cln
        from .c_normal_member_join import MemberBinding
        if members is not None:
            if type(members) is not MemberBinding:raise EvidenceGap('fixed C complete member binding required')
            members.check()
        self.members = members

    def source_configuration(self):
        """Exact C constructor data for existing shared source admission.

        No A/B MemberReader runs on C. These are the actual fixed sources
        invoked by capture, each still requiring its own installed qualifier.
        A partial profile may check a target primitive but cannot admit capture.
        """
        from .c_normal_runtime_source import RuntimeSource
        from .c_normal_owning_join import OwningBinding
        from .c_normal_cln_join import ClnBinding
        from .c_normal_member_join import MemberBinding
        if (type(self) is not DirectPerKeyProfile
                or set(self.__dict__) != {'target','runtime','owning','cln','members'}
                or type(self.target) is not CheckedTargetReader
                or type(self.runtime) is not RuntimeSource
                or set(self.runtime.__dict__) != {'configuration','qualification_sequence'}
                or type(self.owning) is not OwningBinding or type(self.cln) is not ClnBinding
                or type(self.members) is not MemberBinding
                or set(self.owning.__dict__) != {'reader','qualification_sequence'}
                or set(self.cln.__dict__) != {'reader','member_ids','context_sha256','qualification_sequence'}
                or set(self.members.__dict__) != {'wallet_root','actor_member_ids','bank','qualification_sequence'}):
            raise EvidenceGap('all fixed actual C source constructors required before capture')
        return {'kind':'fixed_c_normal_sources',
            'runtime':{'configuration':copy.deepcopy(self.runtime.configuration),
                'qualification_sequence':self.runtime.qualification_sequence},
            'owning':self.owning.check(),'cln':self.cln.check(),'members':self.members.check()}

    def component_hashes(self):
        result = {'c_profile':digest(Path(__file__).read_bytes()),
            'c_target':module_hash(CheckedTargetReader.check_transport),
            'c_history':module_hash(initial_history),
            'c_target_configuration_sha256':digest(canonical({
                'configuration':self.target.configuration,
                'qualification_sequence':self.target.qualification_sequence,
                'reader':{'command':list(self.target.reader.command),
                    'evidence_directory':str(self.target.reader.evidence_directory),
                    'timeout':self.target.reader.timeout,'request_stdin':self.target.reader.request_stdin}}).encode())}

        if self.runtime is not None:
            from .c_normal_runtime_source import RuntimeSource
            result['c_runtime_producer']=module_hash(RuntimeSource.collect)
            result['c_runtime_constructor_sha256']=digest(canonical({
                'configuration':self.runtime.configuration,
                'qualification_sequence':self.runtime.qualification_sequence}).encode())
        if self.owning is not None:
            from .c_normal_owning_join import collect
            result['c_owning_join']=module_hash(collect)
            result['c_owning_constructor_sha256']=digest(canonical(self.owning.check()).encode())
        if self.cln is not None:
            from .c_normal_cln_join import collect
            result['c_cln_join']=module_hash(collect)
            result['c_cln_constructor_sha256']=digest(canonical(self.cln.check()).encode())
        if self.members is not None:
            from .c_normal_member_join import collect
            result['c_member_join']=module_hash(collect)
            result['c_member_constructor_sha256']=digest(canonical(self.members.check()).encode())
        return result

    async def collect_members(self,store,config,chain,observation,boundary,checked,runtime,cln):
        if self.members is None:raise EvidenceGap('actual fixed complete C member source is not installed')
        from .c_normal_member_join import collect
        return await collect(store,config,chain,observation,boundary=boundary,checked=checked,
            runtime=runtime,cln=cln,binding=self.members)

    async def collect_cln(self,store,config,chain,observation,boundary,checked,runtime,owning):
        if self.cln is None:raise EvidenceGap('actual fixed C two-host CLN source is not installed')
        from .c_normal_cln_join import collect
        return await collect(store,config,chain,observation,boundary=boundary,checked=checked,
            runtime=runtime,owning=owning,binding=self.cln)

    async def collect_owning(self,store,config,chain,observation,boundary,checked,runtime):
        if self.owning is None:raise EvidenceGap('actual fixed C owning source is not installed')
        from .c_normal_owning_join import collect
        return await collect(store,config,chain,observation,boundary=boundary,checked=checked,runtime=runtime,binding=self.owning)

    async def collect_runtime(self, store, config, chain, observation, checked):
        if (checked.get('kind')!='c-checked-native-target-source'
                or checked.get('source_observation')!=observation
                or checked.get('qualification_sequence')!=self.target.qualification_sequence):
            raise EvidenceGap('C target must be checked before fresh runtime/member capture')
        if self.runtime is None:
            raise EvidenceGap('actual fixed fresh C runtime producer is not installed')
        return await self.runtime.collect(store,config,chain,observation)

    def begin_target(self, store, chain, observation):
        return self.target.begin(store, chain, observation)

    def checked_target(self, store, chain, observation, transport, started):
        return self.target.check_transport(store, chain, observation, transport, started)

    def history(self, store, boundary):
        return initial_history(store, boundary)

    def bind_member_context(self, store, observation, checked, context):
        """Bind public metadata/scan references AFTER the actual C cut checked.

        A member helper's manifest cannot select this source authority. Exact
        original native/private references are carried separately from the safe
        public context hash. This does not validate descriptor discovery itself.
        """
        _context(store, observation)
        if (not isinstance(checked,dict)
                or checked.get('kind') != 'c-checked-native-target-source'
                or checked.get('source_observation') != observation
                or checked.get('qualification_sequence') != self.target.qualification_sequence
                or checked.get('qualified_constructor_sha256') != digest(canonical(self.target.admission(store, observation)).encode())
                or checked.get('loaded',{}).get('manifest',{}).get('source_observation') != observation
                or checked['loaded']['manifest']['financial_pins'] != observation['financial_pins']):
            raise EvidenceGap('actual independently checked C target context required')
        if not isinstance(context,dict) or set(context) != {'metadata','descriptor_ranges','confirmed_scan_sequence','confirmed_scan_event_hash','observed_at'}:
            raise EvidenceGap('exact captured C public metadata/scan context required')
        event, scan = _source_event(store, context['confirmed_scan_sequence'])
        if (event['kind'] != 'confirmed_descriptor_scan_verified'
                or event['hash'] != context['confirmed_scan_event_hash']
                or scan.get('identity',{}).get('financial_pins') != observation['financial_pins']
                or scan.get('identity',{}).get('boundary_id') != observation.get('boundary_id')
                or (scan.get('height'),scan.get('tip_hash')) != (observation['height'],observation['tip_hash'])
                or scan.get('descriptor_ranges') != context['descriptor_ranges']
                or not observation['started_at'] <= context['observed_at'] <= time.time()):
            raise EvidenceGap('original current C descriptor scan event differs')
        from .confirmed_scan import _raw_trace
        raw_sha,original_at = _raw_trace(store,scan['raw_trace'],context['descriptor_ranges'],scan['result'])
        if raw_sha != scan['raw_response_sha256'] or original_at != scan['observed_at']:
            raise EvidenceGap('actual original C descriptor scan raw provenance differs')
        value = {**copy.deepcopy(context),'source_observation':copy.deepcopy(observation),
            'target_original_private_source_references':copy.deepcopy(checked['original_private_source_references'])}
        public_payload(value)
        return value
