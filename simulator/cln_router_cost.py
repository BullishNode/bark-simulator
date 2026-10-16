"""Source-only selected CLN routing evidence; never dispatches a payment.

Private exact transcripts are replayed with the existing selected-invoice and
parts verifiers. Positive spending/readiness admission additionally needs an authenticated
routing budget contract; the existing miner allowance is never that contract.
"""
import hashlib
import re
import time
from pathlib import Path

from . import c_cln_payment_parts as parts
from .controlled_peer_evidence import SelectedClnReader, action_boundary, _derive_external
from .final_campaign import _source_event
from .model import canonical, integer, public_payload
from .normal_member_source import private_file
from .ownership import EvidenceGap
from .private_source_package import TargetTarReader
from .two_step_normal import digest, strict_json

KIND = 'cln_router_cost_source_verified'
MAX_PACKAGE = 5 * 1024 * 1024
MAX_RECORDS = 20000


def _hex(value, length=64):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{%d}' % length, value) is None:
        raise ValueError('canonical source identity required')
    return value


def _immediate(coroutine):
    """Fixed private replay is in-memory; refuse any I/O/suspension.

    SelectedClnReader._read uses no timer or task creation. Every awaited RPC is
    an immediate bounded lookup in the authenticated original transcript. This
    allows synchronous financial/history consumers to execute the SAME reader,
    without an event-loop thread, arbitrary callback or stored-verdict shortcut.
    """
    try:
        coroutine.send(None)
    except StopIteration as complete:
        return complete.value
    finally:
        coroutine.close()
    raise EvidenceGap('private CLN replay unexpectedly suspended')


def replay_exact(originals, *, alias, payment_hash, node_ids, query_times):
    """Synchronous, exhaustive original replay using shared signed CLN checks."""
    if not isinstance(originals, list) or not 1 <= len(originals) <= parts.MAX_CALLS:
        raise EvidenceGap('bounded whole private transcript required')
    if not isinstance(query_times, list) or len(query_times) != 4:
        raise EvidenceGap('four original selected-query timestamps required')
    times = iter(query_times); index = 0; total = 0
    async def rpc(node, method, params):
        nonlocal index, total
        if index >= len(originals): raise EvidenceGap('private transcript truncated')
        row = originals[index]; index += 1
        if (set(row) != {'alias','method','params','raw'}
                or (row['alias'],row['method'],row['params']) != (node,method,params)):
            raise ValueError('private CLN call order/selection differs')
        raw = row['raw']
        if not isinstance(raw,bytes) or not 0 < len(raw) <= parts.MAX_REPLY:
            raise EvidenceGap('private native reply bound exceeded')
        total += len(raw)
        if total > parts.MAX_TOTAL: raise EvidenceGap('aggregate native bytes exceeded')
        from .process import decode_object
        return decode_object(raw.decode())
    reader = SelectedClnReader(rpc,node_ids=node_ids,network='signet',clock=lambda:next(times))
    selected = _immediate(reader._read(alias,payment_hash))
    response = _immediate(rpc(alias,'listsendpays',{'payment_hash':payment_hash}))
    safe = parts.project_parts(selected,response)
    ending = _immediate(reader._read(alias,payment_hash))
    if ending['query_started_at'] < selected['query_completed_at']:
        raise EvidenceGap('private selected cut clock moved backwards')
    if any(ending[key] != selected[key] for key in ('node_pubkey','network','node_version','payment_hash','pay','invoice')):
        raise EvidenceGap('private selected payment changed across parts cut')
    if index != len(originals): raise EvidenceGap('private transcript has unconsumed replies')
    safe.update(query_started_at=selected['query_started_at'],query_completed_at=ending['query_completed_at'],
                original_transcript_sha256=parts.transcript_hash(originals))
    public_payload(safe)
    return safe


def load_router_package(path, *, producer_exit):
    """Trusted module-level TargetTarReader loader; raw invoice/witness stays private."""
    if producer_exit() != 0: raise EvidenceGap('private producer has no successful reaped exit')
    raw = private_file(path, MAX_PACKAGE); value = strict_json(raw)
    if (set(value) != {'schema_version','request_sha256','source_program_sha256','source_configuration_sha256','query_times','originals'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise ValueError('exact private router package schema required')
    _hex(value['request_sha256']); _hex(value['source_program_sha256']); _hex(value['source_configuration_sha256'])
    rows = value['originals']
    if not isinstance(rows,list) or not 1 <= len(rows) <= parts.MAX_CALLS:
        raise EvidenceGap('bounded whole private replies required')
    originals = []
    for row in rows:
        if set(row) != {'alias','method','params','raw_hex'}: raise ValueError('exact private reply fields required')
        text = row['raw_hex']
        if not isinstance(text,str) or not 0 < len(text) <= 2*parts.MAX_REPLY or re.fullmatch('(?:[0-9a-f]{2})+',text) is None:
            raise EvidenceGap('canonical bounded original reply bytes required')
        originals.append({k:row[k] for k in ('alias','method','params')} | {'raw':bytes.fromhex(text)})
    return {'package':value,'originals':originals,'package_sha256':digest(raw),'directory':str(Path(path).parent)}


def _components():
    from . import controlled_peer_evidence, cln_router_source
    return {'router_cost':digest(Path(__file__).read_bytes()),
            'parts':digest(Path(parts.__file__).read_bytes()),
            'selected_reader':digest(Path(controlled_peer_evidence.__file__).read_bytes()),
            'source_program':digest(Path(cln_router_source.__file__).read_bytes())}


def _admission(store, sequence, pins):
    event, value = _source_event(store,integer(sequence,'router source qualification',1))
    qualification = value.get('router_cost')
    if (event['kind'] != 'normal_financial_collector_qualified' or value.get('financial_pins') != pins
            or not isinstance(qualification,dict)
            or set(qualification) != {'configuration','component_sha256','source_program_sha256','source_configuration_sha256'}
            or qualification['component_sha256'] != _components()):
        raise EvidenceGap('actual installed selected-payment producer/source qualification required')
    cfg = qualification['configuration']
    if (not isinstance(cfg,dict) or set(cfg) != {'command','evidence_directory','timeout'}
            or not isinstance(cfg['command'],list) or not cfg['command']
            or any(not isinstance(v,str) or not v for v in cfg['command'])
            or not Path(cfg['command'][0]).is_absolute()
            or type(cfg['timeout']) not in (int,float) or not 0 < cfg['timeout'] <= 25):
        raise EvidenceGap('fixed admitted private read-only router transport required')
    root = Path(cfg['evidence_directory'])
    if (not root.is_absolute() or any(p.is_symlink() for p in (root,*root.parents))
            or root.stat().st_uid != __import__('os').getuid() or root.stat().st_mode & 0o077):
        raise EvidenceGap('private owned unaliased routing evidence root required')
    _hex(qualification['source_program_sha256']); _hex(qualification['source_configuration_sha256'])
    if qualification['source_program_sha256']!=_components()['source_program']:
        raise EvidenceGap('actual source producer code differs from installed qualification')
    return event, qualification


def _context(store, source_sequence, external_sequence):
    source_event, source = _source_event(store,integer(source_sequence,'original normal source',1))
    external_event, proof = _source_event(store,integer(external_sequence,'original controlled payment proof',1))
    if source_event['kind'] != 'normal_financial_source' or external_event['kind'] != 'controlled_peer_payment_verified':
        raise EvidenceGap('original normal source and controlled terminal proof required')
    observation = source['source_observation']
    _hex(observation['id'],32)
    if (source['financial_pins'] != observation['financial_pins'] or source['boundary_id'] != observation['boundary_id']
            or (source['height'],source['tip_hash']) != (observation['height'],observation['tip_hash'])):
        raise ValueError('original normal source invocation differs')
    action = store.db.execute('SELECT * FROM action WHERE id=?',(proof['action_id'],)).fetchone()
    if action is None or action['state'] != 'completed': raise EvidenceGap('original terminal native action required')
    expected = _derive_external(store,action,proof)
    if any(proof.get(k) != v for k,v in expected.items()): raise ValueError('original controlled summary/ancestry differs')
    if proof['financial_pins'] != source['financial_pins']:
        # Historical records are verified against their ORIGINAL source; do not
        # re-label an old native action with the new observation's pins.
        raise EvidenceGap('router certificate must bind its original financial source pins')
    declared = action_boundary(store,action,proof['financial_pins'])
    if declared['id'] != source['boundary_id']: raise ValueError('original action/source boundary differs')
    nodes = {}; members = {}
    for alias in ('operator','fixture_peer'):
        matching = [m for m in declared['members'] if m['kind']=='lightning_peer' and m['role']==alias]
        if len(matching) != 1: raise EvidenceGap('two original controlled node members required')
        nodes[alias] = matching[0]['identity']; members[alias] = matching[0]['id']
    alias = 'operator' if proof['direction']=='send' else 'fixture_peer'
    request = {**observation,'normal_source_sequence':source_event['sequence'],'normal_source_hash':source_event['hash'],
               'external_sequence':external_event['sequence'],'external_hash':external_event['hash'],
               'payer_alias':alias,'payment_hash':proof['payment_hash']}
    return source_event,source,external_event,proof,nodes,members,request


def _projection(store, source_sequence, external_sequence, package, admission_sequence):
    event,source,external,proof,nodes,members,request = _context(store,source_sequence,external_sequence)
    qualified,admitted = _admission(store,admission_sequence,source['financial_pins'])
    if qualified['sequence'] >= event['sequence'] or qualified['observed_at'] > source['source_observation']['started_at']:
        raise EvidenceGap('source qualification must precede original normal capture')
    wire = package['package']
    if (wire['request_sha256'] != digest((canonical(request)+'\n').encode())
            or wire['source_program_sha256'] != admitted['source_program_sha256']
            or wire['source_configuration_sha256'] != admitted['source_configuration_sha256']):
        raise ValueError('private source program/original source nonce/hash differs')
    safe = replay_exact(package['originals'],alias=request['payer_alias'],payment_hash=proof['payment_hash'],
                        node_ids=nodes,query_times=wire['query_times'])
    if (safe['invoice_sha256'] != proof['invoice_sha256'] or safe['amount_msat'] != proof['amount_msat']
            or safe['amount_sent_msat'] != proof['amount_sent_msat'] or safe['router_fee_msat'] != proof['router_fee_msat']
            or not source['source_observation']['started_at'] <= event['observed_at'] <= safe['query_started_at'] <= safe['query_completed_at']):
        raise ValueError('original native/action/invoice/part ancestry differs')
    groups = {p['groupid'] for p in safe['complete_parts']}
    group = next(iter(groups))
    identifier = 'cln-router:'+safe['payer_node']+':'+safe['payment_hash']+':'+str(group)
    return {'schema_version':1,'monetary_id':identifier,'kind':'router_cost','amount_msat':safe['router_fee_msat'],
        'budget':'ordinary','source':members[request['payer_alias']],'destination':'outside-lightning-routers',
        'financial_pins':source['financial_pins'],'native_action_id':proof['action_id'],
        'normal_source_sequence':event['sequence'],'normal_source_hash':event['hash'],
        'source_observation_id':request['id'],'external_sequence':external['sequence'],'external_hash':external['hash'],
        'admission_sequence':qualified['sequence'],'admission_hash':qualified['hash'],
        'package_sha256':package['package_sha256'],'parts':safe,
        'scope':'selected original payer routing debit only; not exhaustive history or net external forwarding ownership; routing budget admission remains separate'}


class RouterCostProducer:
    """One fixed admitted transport; no observer-selected commands or callbacks."""
    def __init__(self, admission_sequence): self.admission_sequence=admission_sequence

    async def collect(self, store, *, source_sequence, external_sequence):
        store.verify_event_chain()
        context = _context(store,source_sequence,external_sequence)
        _,source,_,_,_,_,request = context
        _,admitted = _admission(store,self.admission_sequence,source['financial_pins'])
        if not 0 <= time.time()-source['source_observation']['started_at'] <= 90:
            raise EvidenceGap('router capture must belong to this fresh normal observation')
        cfg=admitted['configuration']
        reader=TargetTarReader(cfg['command'],cfg['evidence_directory'],timeout=cfg['timeout'],
                               loader=load_router_package,request_stdin=True)
        package=await reader.read(request)
        safe=_projection(store,source_sequence,external_sequence,package,self.admission_sequence)
        capture_id=Path(package['directory']).name;_hex(capture_id,32)
        safe['capture_id']=capture_id
        safe['terminal_sha256']=digest(private_file(Path(package['directory'])/'terminal.json',65536))
        if safe['parts']['query_completed_at'] > time.time(): raise ValueError('router capture completed in future')
        public_payload(safe)
        # A source proof is not a positive cost record or budget/readiness grant.
        with store.transaction():
            store.verify_event_chain()
            store._event(KIND,safe)
            sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        return {'source_sequence':sequence,'source':safe,'zero_fee':safe['amount_msat']==0,
                'financial_admission':False}


def verify_source(store, sequence):
    """Replay exact private originals again, including for retained old history."""
    store.verify_event_chain();event,certificate=_source_event(store,integer(sequence,'router source',1))
    if event['kind'] != KIND: raise ValueError('original router source kind differs')
    _,admitted=_admission(store,certificate['admission_sequence'],certificate['financial_pins'])
    capture_id=_hex(certificate['capture_id'],32)
    root=Path(admitted['configuration']['evidence_directory'])/capture_id
    meta=root.lstat()
    if root.is_symlink() or not root.is_dir() or meta.st_mode&0o077 or meta.st_uid!=__import__('os').getuid():
        raise EvidenceGap('original private capture directory ownership/links changed')
    terminal_raw=private_file(root/'terminal.json',65536)
    if digest(terminal_raw)!=certificate['terminal_sha256']:raise ValueError('actual source terminal receipt changed')
    terminal=strict_json(terminal_raw)
    package=load_router_package(root/'source.tar',producer_exit=lambda:terminal.get('exit'))
    request_raw=private_file(root/'request.json',65536)
    if (terminal.get('exit') != 0 or terminal.get('timed_out') is not False or terminal.get('error_type') is not None
            or terminal.get('stdout_bytes') != (root/'source.tar').stat().st_size
            or terminal.get('source_observation_id') != certificate['source_observation_id']):
        raise EvidenceGap('original actual bounded/reaped source transport differs')
    expected=_projection(store,certificate['normal_source_sequence'],certificate['external_sequence'],package,certificate['admission_sequence'])
    context=_context(store,certificate['normal_source_sequence'],certificate['external_sequence'])
    request=context[-1];command=(*admitted['configuration']['command'],'financial-source '+str(__import__('uuid').UUID(request['id'])))
    if (request_raw != (canonical(request)+'\n').encode() or terminal.get('command_sha256') != digest(canonical(command).encode())
            or expected | {'capture_id':capture_id,'terminal_sha256':digest(terminal_raw)} != certificate
            or certificate['parts']['query_completed_at'] > event['observed_at']):
        raise ValueError('router certificate/private transport/ancestry changed')
    return certificate


def verify_cost(store, cost):
    """Re-derive an observed expense, independently of permission to spend.

    An unauthorized historical expense is still an expense. This verifier never
    turns source qualification, an ordinary total or miner-only 2000 into a
    routing grant. require_routing_readiness supplies the separate launch fence.
    """
    if set(cost) != {'monetary_id','kind','amount_msat','budget','source','destination','financial_pins','router_source_sequence'}:
        raise ValueError('exact router monetary record required; native action coverage is separate')
    certificate=verify_source(store,cost['router_source_sequence'])
    integer(certificate['amount_msat'],'positive actual routing fee',1)
    if any(cost[key] != certificate[key] for key in ('monetary_id','kind','amount_msat','budget','source','destination','financial_pins')):
        raise ValueError('positive router cost differs from authenticated original payment')
    return certificate


def cost_record(certificate, sequence):
    integer(certificate['amount_msat'],'positive actual routing fee',1)
    return {key:certificate[key] for key in ('monetary_id','kind','amount_msat','budget','source','destination','financial_pins')} | {'router_source_sequence':sequence}


def collect_cost_records(store, financial_pins):
    """Known genuine costs are never hidden by an absent routing allocation.

    This is selected-source coverage, not discovery of all payments at a node.
    Re-observation cannot charge the same node/hash/group twice or refresh old
    source pins. Zero-fee original proofs remain separate from positive records.
    """
    started=time.monotonic()
    def bounded():
        if time.monotonic()-started>20:raise EvidenceGap('selected routing history replay exceeded 20-second bound')
    existing={};seen={};zeros=[];reused=[];records=[]
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' ORDER BY sequence"):
        bounded()
        _,old=_source_event(store,row[0])
        if old['monetary_id'] in existing:raise ValueError('historical monetary identity repeated')
        existing[old['monetary_id']]=old
    source_rows=store.db.execute('SELECT sequence FROM event WHERE kind=? ORDER BY sequence',(KIND,)).fetchall()
    if len(source_rows)>MAX_RECORDS:raise EvidenceGap('selected routing source history exceeds bounded replay contract')
    for row in source_rows:
        bounded()
        certificate=verify_source(store,row[0]);identifier=certificate['monetary_id']
        if certificate['amount_msat']==0:
            if identifier in existing or identifier in seen:raise ValueError('zero and positive routing histories conflict')
            if identifier not in {v['monetary_id'] for v in zeros}:
                zeros.append({'monetary_id':identifier,'router_source_sequence':row[0],'amount_msat':0})
            continue
        record=cost_record(certificate,row[0])
        if identifier in {v['monetary_id'] for v in zeros}:raise ValueError('positive and zero routing histories conflict')
        if identifier in seen:
            if any(record[k]!=seen[identifier][k] for k in record if k!='router_source_sequence'):
                raise ValueError('same native routing group has conflicting expense/ancestry')
            continue
        seen[identifier]=record
        if identifier in existing:
            original=existing[identifier];verify_cost(store,original)
            if any(original.get(k)!=record[k] for k in record if k!='router_source_sequence'):
                raise ValueError('retained original routing cost cannot be relabeled')
            reused.append(identifier)
        else:
            if financial_pins is not None and record['financial_pins']!=financial_pins:
                raise EvidenceGap('known old routing expense was not journaled before upgrade; preserve original pins')
            records.append(record)
    bounded()
    return {'cost_records':records,'reused_cost_ids':reused,'zero_fee_router_payments':zeros}


def require_routing_readiness(store):
    """Launch fence only; accounting/history remains available on actual costs.

    Existing controlled proofs can already reveal a positive payer fee without
    any parts certificate. Such an expense must be accounted or HOLD, never
    hidden by the no-routing fast path. No original C routing allocation exists;
    an admitted observer or ordinary total is not a spending-authority substitute.
    """
    relevant=store.db.execute("SELECT 1 FROM event WHERE kind IN (?, 'controlled_peer_payment_verified') OR (kind='financial_cost_verified' AND json_extract(payload,'$.kind')='router_cost') LIMIT 1",(KIND,)).fetchone()
    if not relevant:return
    known=collect_cost_records(store,None)
    if known['cost_records']:
        raise EvidenceGap('known positive routing expense omitted from original cost journal')
    accounted=set();has_cost=False
    for row in store.db.execute("SELECT sequence FROM event WHERE kind='financial_cost_verified' ORDER BY sequence"):
        _,cost=_source_event(store,row[0])
        if cost.get('kind')=='router_cost':
            certificate=verify_cost(store,cost);has_cost=True
            _,external=_source_event(store,certificate['external_sequence'])
            accounted.add(canonical(external))
    proof_rows=store.db.execute("SELECT sequence FROM event WHERE kind='controlled_peer_payment_verified' ORDER BY sequence").fetchall()
    if len(proof_rows)>MAX_RECORDS:raise EvidenceGap('controlled payment history exceeds bounded replay contract')
    for row in proof_rows:
        _,proof=_source_event(store,row[0])
        action=store.db.execute('SELECT * FROM action WHERE id=?',(proof['action_id'],)).fetchone()
        if action is None:raise ValueError('original controlled native action missing')
        expected=_derive_external(store,action,proof)
        if any(proof.get(k)!=v for k,v in expected.items()):raise ValueError('original controlled payment summary/ancestry differs')
        if expected['router_fee_msat']>0 and canonical(proof)not in accounted:
            raise EvidenceGap('known positive controlled payer routing fee requires qualified original parts source and exact cost journal; allocation absence never proves zero')
    if has_cost:
        raise EvidenceGap('actual routing expense recorded; routing scope within immutable ordinary allowance remains unauthenticated; miner-only 2000 is not routing authority')
