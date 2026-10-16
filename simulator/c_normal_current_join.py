"""Fixed C native current-source stage after all actual wallet/CLN members.

Reuse the existing native tool lifecycle and conservative current reducer.
Unsupported economic domains still hold; valid Full paths alone grant nothing.
"""
import copy
from dataclasses import dataclass
from pathlib import Path
import re
import time

from . import c_current_liability_source as current
from . import c_normal_member_join as member_join
from . import c_normal_owning_join as originals
from .c_normal_source import _context
from .final_campaign import _source_event
from .model import canonical,public_payload
from .normal_source_deadline import check as deadline_check
from .ownership import EvidenceGap
from .two_step_normal import module_hash

KIND='c_normal_native_current_source_collected'


@dataclass(frozen=True)
class CurrentBinding:
    tool: dict
    tool_identity: dict
    qualification_sequence: int

    def check(self):
        if (not isinstance(self.tool,dict) or set(self.tool)!={'command','sha256','evidence_directory'}
                or not isinstance(self.tool['command'],list) or len(self.tool['command'])!=1
                or any(not isinstance(v,str) or not Path(v).is_absolute() for v in [*self.tool['command'],self.tool['evidence_directory']])
                or not isinstance(self.tool['sha256'],str) or re.fullmatch('[0-9a-f]{64}',self.tool['sha256'])is None
                or not isinstance(self.tool_identity,dict)
                or self.tool_identity.get('launcher_sha256')!=self.tool['sha256']
                or type(self.qualification_sequence)is not int or self.qualification_sequence<1):
            raise EvidenceGap('exact fixed C native current tool binding required')
        public_payload(self.tool);public_payload(self.tool_identity)
        return {'tool':copy.deepcopy(self.tool),'tool_identity':copy.deepcopy(self.tool_identity)}


def requirement(binding,pins):
    return {'architecture_profile':'direct_per_key','financial_pins':pins,'constructor':binding.check(),
        'component_sha256':{'producer':member_join.digest(Path(__file__).read_bytes()),
            'current_reducer':module_hash(current.collect),'native_paths':module_hash(current.native.collect_paths),
            'source_member_join':module_hash(member_join.collect)}}


def collect(store,config,chain,observation,*,boundary,checked,members,binding,audit_binding=None):
    _context(store,observation);deadline_check()
    if type(binding)is not CurrentBinding:raise EvidenceGap('typed C native current binding required')
    constructor=canonical(binding.check());original=canonical(observation)
    event,admitted=_source_event(store,binding.qualification_sequence)
    if event['kind']!='c_normal_current_source_qualified' or admitted!=requirement(binding,observation['financial_pins']):
        raise EvidenceGap('independent actual native current source qualification missing')
    safe=members.get('safe',{})
    member_event,_=originals._original(store,safe.get('source_sequence'),member_join.KIND,safe,observation)
    if (boundary['pins']!=observation['financial_pins'] or boundary['id']!=observation['boundary_id']
            or checked.get('kind')!='c-checked-native-target-source' or checked.get('source_observation')!=observation
            or members.get('private_checked_target')!=checked
            or checked.get('loaded',{}).get('manifest',{}).get('source_observation')!=observation
            or checked['loaded']['manifest'].get('financial_pins')!=observation['financial_pins']
            or len(safe.get('inventory_sequences',{})) not in (17,29)
            or safe.get('cln_join_sequence')!=members['private_cln_join']['safe']['source_sequence']):
        raise EvidenceGap('actual complete same-observation C member/target source required')
    if checked['loaded']['manifest'].get('schema_version')==4:
        from . import c_native_audit_tool
        if type(audit_binding)is not c_native_audit_tool.AuditBinding:
            raise EvidenceGap('actual fixed new native captured-audit tool is not installed')
        c_native_audit_tool.collect(store,config,chain,observation,checked=checked,binding=audit_binding)
        # Native byte/SQL consistency does not prove current financial closure.
        raise EvidenceGap('captured native bytes audited; legacy DirectRecord/allocation, Board-root and current-economic prerequisites remain missing')
    if checked['loaded']['manifest'].get('schema_version')!=1:
        raise EvidenceGap('versioned joint originals require actual native fee/opening/urgent reconciliation before current audit')
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?",(KIND,observation['id'])).fetchone():
        raise EvidenceGap('native current source observation already collected')
    # _tool authenticates the actual six-file runtime closure and SDK identity
    # even for an empty body set. No available-old-tool or empty-frame waiver.
    current.native._tool(binding.tool,binding.tool_identity,observation['financial_pins'])
    audit=current.collect(store,chain,checked['loaded'],binding.tool,tool_identity=binding.tool_identity,
        observation=observation,server_pubkey=config.expected_server_pubkey)
    if (canonical(binding.check())!=constructor or canonical(observation)!=original
            or audit.get('safe',{}).get('source_observation')!=observation
            or audit['safe'].get('original_private_source_references')!=checked['original_private_source_references']):
        raise EvidenceGap('original C native current audit differs from checked cut')
    _context(store,observation);deadline_check()
    result={'source_observation':copy.deepcopy(observation),'financial_pins':observation['financial_pins'],
        'boundary_id':boundary['id'],'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time(),
        'member_source_sequence':member_event['sequence'],'member_source_event_hash':member_event['hash'],
        'original_private_source_references':checked['original_private_source_references'],
        'tool_identity':copy.deepcopy(binding.tool_identity),'qualification_sequence':binding.qualification_sequence,
        'current_source_audit':audit['safe'],'complete':False,'qualified':False,'financial_readiness':False,
        'scope':'actual current native audit only; unresolved economic/fee sources grant no admission'}
    public_payload(result);store.event(KIND,result)
    result['source_sequence']=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    # Keep the truthful diagnostic event on an unresolved source, then HOLD.
    rights=current.require_resolved(audit['safe'])
    return {'safe':result,'private_current_audit':audit,'supported_retained_customer_rights':rights,
        'private_member_join':members}
