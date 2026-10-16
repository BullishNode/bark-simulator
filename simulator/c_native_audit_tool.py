"""Coupled captured-byte native subgate, never a financial/current-owner gate.

Only a trusted typed constructor supplies the actual qualified tool/closure and
native identity. Original private source bytes are prepared, executed by the
existing private runner, and bound to its safe reply without source relabelling.
"""
import copy
from dataclasses import dataclass
from pathlib import Path
import re
import time

from . import c_native_audit_request as request
from . import c_native_body_proof as closure
from .c_normal_source import _context
from .c_normal_target_source import CheckedTargetReader
from .final_campaign import _source_event
from .model import canonical,public_payload
from .normal_source_deadline import ACTIVE,Deadline
from .ownership import EvidenceGap
from .two_step_normal import digest,module_hash,run_c_captured_audit,strict_json

KIND='c_normal_captured_native_bytes_audited'
QUALIFIED_KIND='c_normal_captured_native_audit_qualified'
SCOPE='Captured native byte/SQL reciprocity only; legacy DirectRecord closure, source authority, current ownership, liquidity and financial readiness excluded'
COUNTS={'ordinary_publications','urgent_attempts','urgent_signed','round_rights','pending_participations','coin_rows'}
FIELDS={'format','request_sha256','charged_sat','carrier_charged_sat',*COUNTS,
    'complete','qualified','financial_readiness','scope'}


@dataclass(frozen=True)
class AuditBinding:
    tool: dict
    tool_identity: dict
    expected: dict
    qualification_sequence: int

    def check(self):
        if (not isinstance(self.tool,dict)or set(self.tool)!={'command','sha256','evidence_directory'}
                or not isinstance(self.tool['command'],list)or len(self.tool['command'])!=1
                or any(not isinstance(v,str)or not Path(v).is_absolute() for v in [*self.tool['command'],self.tool['evidence_directory']])
                or not isinstance(self.tool['sha256'],str)or re.fullmatch('[0-9a-f]{64}',self.tool['sha256'])is None
                or not isinstance(self.tool_identity,dict)
                or self.tool_identity.get('launcher_sha256')!=self.tool['sha256']
                or not isinstance(self.expected,dict)or set(self.expected)!=request.EXPECTED
                or not isinstance(self.expected['server_pubkey'],str)or re.fullmatch('0[23][0-9a-f]{64}',self.expected['server_pubkey'])is None
                or type(self.qualification_sequence)is not int or self.qualification_sequence<1):
            raise EvidenceGap('fixed qualified native captured-audit constructor required')
        for field in ('genesis','policy_sha256','opening_sha256'):
            value=self.expected[field]
            if not isinstance(value,str)or re.fullmatch('[0-9a-f]{64}',value)is None:
                raise EvidenceGap('independently admitted native audit identity required')
        if self.expected['policy_sha256']=='0'*64 or self.expected['opening_sha256']=='0'*64:
            raise EvidenceGap('actual native policy/opening identity missing')
        value={'tool':copy.deepcopy(self.tool),'tool_identity':copy.deepcopy(self.tool_identity),'expected':copy.deepcopy(self.expected)}
        public_payload(value);return value


def requirement(binding,pins):
    if type(binding)is not AuditBinding:raise EvidenceGap('typed native captured-audit binding required')
    return {'architecture_profile':'direct_per_key','financial_pins':copy.deepcopy(pins),
        'constructor':binding.check(),'fixed_binary_role':'native-fee-audit',
        'component_sha256':{'producer':digest(Path(__file__).read_bytes()),'request':module_hash(request.prepare),
            'runtime_closure':module_hash(closure._tool),'private_runner':module_hash(run_c_captured_audit)}}


def _tool(binding,pins):
    identity=binding.tool_identity
    # Source is NOT guessed from old5f/SDK902. Exact independent qualification
    # below binds this actual new source, owning SDK/component and full closure.
    closure._tool(binding.tool,identity,pins,expected_source=identity.get('source_commit'),binary_name='native-fee-audit')


def bind_summary(prepared,encoded,reply,*,loaded):
    """Pure transport binding only; fee/rights validation stays native."""
    if (not isinstance(encoded,bytes)or encoded!=prepared['private_request']
            or digest(encoded)!=prepared['safe']['request_sha256']):
        raise EvidenceGap('native audit request differs from original captured bytes')
    value=strict_json(reply)
    if (not isinstance(value,dict)or set(value)!=FIELDS or value['format']!=request.FORMAT
            or value['request_sha256']!=digest(encoded)or value['scope']!=SCOPE
            or any(value[field]is not False for field in ('complete','qualified','financial_readiness'))
            or any(type(value[field])is not int or value[field]<0 for field in COUNTS|{'charged_sat','carrier_charged_sat'})):
        raise EvidenceGap('exact safe native captured-audit reply required')
    # These are source-cardinality bindings, not Python fee math/ownership.
    pg=loaded['joint_pg'];body=loaded['private_pg']
    counts={'ordinary_publications':len(pg['native_fee_publication']),
        'urgent_attempts':len(pg['native_urgent_attempt']),
        'urgent_signed':sum(row['signed_entry_hex']is not None and row['signed_record_hex']is not None for row in pg['native_urgent_attempt']),
        'round_rights':len(pg['rounds']),
        'pending_participations':sum(row['round_id']is None for row in pg['round_participation']),
        'coin_rows':len(body['coins'])}
    if any(value[field]!=count for field,count in counts.items()):
        raise EvidenceGap('native audit reply differs from whole original SQL row sets')
    public_payload(value);return copy.deepcopy(value)


def collect(store,config,chain,observation,*,checked,binding):
    """Actual existing bounded private runner, followed by an auxiliary event.

    Success leaves ALL financial/current/legacy predicates unresolved. A failed
    or unknown process never emits this successful byte-consistency event.
    No missing actual native artifact is replaced by oldproof or empty-source.
    """
    _context(store,observation)
    deadline=ACTIVE.get()or Deadline(observation['started_at']);deadline.remaining()
    if type(binding)is not AuditBinding:raise EvidenceGap('typed native captured-audit binding required')
    constructor=canonical(binding.check());original=canonical(observation)
    event,admitted=_source_event(store,binding.qualification_sequence)
    if event['kind']!=QUALIFIED_KIND or admitted!=requirement(binding,observation['financial_pins']):
        raise EvidenceGap('actual new native captured-audit source/ELF/SDK/runtime qualification missing')
    if (checked.get('kind')!='c-checked-native-target-source'or checked.get('source_observation')!=observation
            or checked.get('loaded',{}).get('manifest',{}).get('schema_version')!=4
            or checked['loaded']['manifest'].get('source_observation')!=observation
            or checked['loaded']['manifest'].get('financial_pins')!=observation['financial_pins']
            or checked.get('original_private_source_references')!=checked['loaded'].get('original_private_source_references')
            or binding.expected['server_pubkey']!=config.expected_server_pubkey):
        raise EvidenceGap('original V4 checked source/native identity required')
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?",(KIND,observation['id'])).fetchone():
        raise EvidenceGap('captured native audit observation already consumed')
    before=CheckedTargetReader._identity(chain,observation)
    _tool(binding,observation['financial_pins']);deadline.remaining()
    prepared=request.prepare(checked['loaded'],expected=binding.expected,source_observation=observation,
        original_source_references=checked['original_private_source_references'])
    # The existing runner's12s timeout participates in the SAME90s observation;
    # standalone calls also install the already-aged deadline, never reset it.
    token=None
    if ACTIVE.get()is None:token=ACTIVE.set(deadline)
    try:
        encoded,reply=run_c_captured_audit(binding.tool,prepared['private_request'])
    finally:
        if token is not None:ACTIVE.reset(token)
    deadline.remaining();_tool(binding,observation['financial_pins'])
    summary=bind_summary(prepared,encoded,reply,loaded=checked['loaded'])
    if (canonical(binding.check())!=constructor or canonical(observation)!=original
            or CheckedTargetReader._identity(chain,observation)!=before):
        raise EvidenceGap('native audit source/constructor/chain changed during execution')
    _context(store,observation);deadline.remaining()
    result={'source_observation':copy.deepcopy(observation),'financial_pins':copy.deepcopy(observation['financial_pins']),
        'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time(),
        'original_private_source_references':copy.deepcopy(checked['original_private_source_references']),
        'preparation':prepared['safe'],'native_reply':summary,'native_response_sha256':digest(reply),
        'tool_identity':copy.deepcopy(binding.tool_identity),'qualification_sequence':binding.qualification_sequence,
        'complete':False,'qualified':False,'financial_readiness':False,
        'scope':'Native captured-byte subgate only; legacy DirectRecord/allocation, Board-root, current economics and operating-source admission remain required'}
    public_payload(result);store.event(KIND,result)
    result['source_sequence']=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    return {'safe':result,'private_request':encoded,'private_response':reply}
