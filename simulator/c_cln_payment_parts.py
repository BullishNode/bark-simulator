"""Private exact-hash parts coverage for the existing selected CLN reader.

No cost import, payment action, public raw trace or completeness declaration.
The admitted transport must return original bounded stdout bytes only after an
actual successful fixed read; this module does not manufacture transport proof.
"""
import asyncio
import copy
import hashlib
import time

from .controlled_peer_evidence import SelectedClnReader, _hash, _msat, _witness
from .model import canonical, integer, public_payload
from .ownership import EvidenceGap
from .process import decode_object

MAX_REPLY=256*1024
MAX_TOTAL=2*1024*1024
MAX_PARTS=1024
MAX_CALLS=20


def _u64(value,name,minimum=0):
    value=integer(value,name,minimum)
    if value>=2**64:raise ValueError('native unsigned identity exceeds u64')
    return value


def project_parts(selected,response):
    """All private rows inspected; reuse aggregate's signed/native facts."""
    pay=selected.get('pay');payment_hash=_hash(selected['payment_hash'])
    if(not isinstance(pay,dict)or pay.get('state')!='complete'
            or pay.get('preimage_hash_verified')is not True or pay.get('signature_valid')is not True):
        raise EvidenceGap('original selected completed signed payer source required')
    rows=response.get('payments')
    if not isinstance(rows,list)or not 1<=len(rows)<=MAX_PARTS:raise EvidenceGap('bounded complete native parts missing')
    seen=set();parts=set();groups=set();complete=[];failed=0;last=0
    for row in rows:
        if not isinstance(row,dict)or row.get('payment_hash')!=payment_hash:raise ValueError('foreign native part hash')
        identifier=_u64(row.get('created_index',row.get('id')),'native created part identity',1)
        if 'id'in row and _u64(row['id'],'native old part identity',1)!=identifier:raise ValueError('native part identity aliases differ')
        group=_u64(row['groupid'],'native group identity');part=_u64(row.get('partid',0),'native part identity')
        if identifier in seen or identifier<=last or (group,part)in parts:raise EvidenceGap('native parts duplicated/ambiguous/unordered')
        seen.add(identifier);parts.add((group,part));last=identifier
        _u64(row['created_at'],'native part creation')
        sent=_msat(row['amount_sent_msat'])
        status=row.get('status')
        if status=='pending':raise EvidenceGap('selected hash retains pending native parts')
        if status=='failed':failed+=1;continue
        if status!='complete':raise ValueError('unknown native part status')
        amount=_msat(row['amount_msat'])
        if amount<=0 or sent<amount or row.get('destination')!=pay['payee']:raise EvidenceGap('native part amount/destination incomplete')
        _witness(row,payment_hash)  # Private; never returned in the projection.
        if 'bolt11'in row and hashlib.sha256(row['bolt11'].encode()).hexdigest()!=pay['invoice_sha256']:
            raise ValueError('native part invoice differs from signed aggregate')
        groups.add(group);complete.append({'native_id':identifier,'groupid':group,'partid':part,'amount_msat':amount,'amount_sent_msat':sent})
    if len(groups)!=1 or not complete:raise EvidenceGap('successful native payment group missing/ambiguous')
    amount=sum(p['amount_msat']for p in complete);sent=sum(p['amount_sent_msat']for p in complete)
    if(len(complete)!=integer(pay['number_of_parts'],'original aggregate parts',1)
            or amount!=_msat(pay['amount_msat'])or sent!=_msat(pay['amount_sent_msat'])
            or amount!=_msat(pay['invoice_amount_msat'])):
        raise EvidenceGap('native complete parts do not exhaust signed aggregate')
    result={'payment_hash':payment_hash,'payer_node':selected['node_pubkey'],'network':selected['network'],
      'invoice_sha256':pay['invoice_sha256'],'payee':pay['payee'],'amount_msat':amount,'amount_sent_msat':sent,
      'router_fee_msat':sent-amount,'complete_parts':complete,'failed_parts':failed,
      'row_count':len(rows),'selection':'exact_hash_without_pagination','scope':'one completed payment only; not global cost completeness or budget admission'}
    public_payload(result);return result


class CompletedPartsReader:
    """Reuse SelectedClnReader; retain exact private method replies for replay.

    rpc_bytes(alias,method,params) is trusted admitted readonly transport. It must
    not log replies: decode/listpays/listsendpays can contain secrets. The returned
    private originals must use existing protected evidence/SSH transport, never
    event/TraceStore public payloads. Caller binds actual command/exit/provenance.
    """
    def __init__(self,rpc_bytes,*,node_ids,network,clock=time.time):
        self.rpc_bytes=rpc_bytes;self.node_ids=dict(node_ids);self.network=network;self.clock=clock
        SelectedClnReader(None,node_ids=self.node_ids,network=network,clock=clock)
    async def read(self,alias,payment_hash):
        async with asyncio.timeout(25):
            originals=[];total=0;query_times=[]
            def clock():
                value=self.clock();query_times.append(value);return value
            async def rpc(node,method,params):
                nonlocal total
                raw=await self.rpc_bytes(node,method,params)
                if not isinstance(raw,bytes)or not 0<len(raw)<=MAX_REPLY:raise EvidenceGap('bounded original private CLN reply required')
                total+=len(raw)
                if total>MAX_TOTAL or len(originals)>=MAX_CALLS:raise EvidenceGap('private CLN transcript bound exceeded')
                value=decode_object(raw.decode())
                originals.append({'alias':node,'method':method,'params':copy.deepcopy(params),'raw':raw})
                return value
            selected_reader=SelectedClnReader(rpc,node_ids=self.node_ids,network=self.network,clock=clock)
            selected=await selected_reader.read(alias,payment_hash)
            response=await rpc(alias,'listsendpays',{'payment_hash':_hash(payment_hash)})
            safe=project_parts(selected,response)
            # Independent native aggregates on both sides of the private parts cut.
            ending=await selected_reader.read(alias,payment_hash)
            if ending['query_started_at']<selected['query_completed_at']:raise EvidenceGap('native query clock moved backwards between cuts')
            for key in ('node_pubkey','network','node_version','payment_hash','pay','invoice'):
                if ending[key]!=selected[key]:raise EvidenceGap('selected CLN source changed during parts cut')
            safe['query_started_at']=selected['query_started_at'];safe['query_completed_at']=ending['query_completed_at']
            safe['original_transcript_sha256']=transcript_hash(originals)
            public_payload(safe)
            return {'safe':safe,'private_originals':originals,'query_times':query_times,'transport_admitted':False}


def transcript_hash(originals):
    return hashlib.sha256(canonical([{'alias':r['alias'],'method':r['method'],'params':r['params'],
      'bytes':len(r['raw']),'sha256':hashlib.sha256(r['raw']).hexdigest()}for r in originals]).encode()).hexdigest()


async def replay(originals,*,alias,payment_hash,node_ids,network,query_times):
    """Re-run original shared verifier + parts checks, consume every exact reply."""
    if not isinstance(originals,list)or not 1<=len(originals)<=MAX_CALLS:raise EvidenceGap('whole private transcript required')
    if not isinstance(query_times,list)or len(query_times)!=4:raise EvidenceGap('original local query times required')
    times=iter(query_times);index=0
    async def rpc(node,method,params):
        nonlocal index
        if index>=len(originals):raise EvidenceGap('private original transcript truncated')
        row=originals[index];index+=1
        if set(row)!={'alias','method','params','raw'}or (row['alias'],row['method'],row['params'])!=(node,method,params):
            raise ValueError('private original method/hash/order differs')
        return row['raw']
    result=await CompletedPartsReader(rpc,node_ids=node_ids,network=network,clock=lambda:next(times)).read(alias,payment_hash)
    if index!=len(originals):raise EvidenceGap('unconsumed private originals')
    return result['safe']
