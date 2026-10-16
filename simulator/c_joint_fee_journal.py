"""Strict private decoding of C's existing joint native ordinary journal.

Pure arithmetic/framing only. Complete protected filesystem+sameRR DB sources,
actual input ownership/Core confirmation, native activation and shared monetary
join are REQUIRED separately. Numeric debit/typed charge is never burned fee.
"""
import hashlib
import json
import re
from .bundle_audit import decode_transaction
from .c_native_fee_sources import _json
from .model import SIGNET_GENESIS,integer,public_payload
from .renewal import REGTEST_GENESIS

U64=2**64-1
MAX_MONEY=21000000*100000000
MAX_HISTORY=2*1024*1024
MAX_RECORD=4*1024*1024
MAX_TOTAL=64*1024*1024
ENTRY=('version','path','wtxid','record_sha256','fee_sat','charge_sat')
RECORD=('version','path','policy_sha256','raw','input_parents','max_fee_rate')


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def number(value,name,minimum=0):
    value=integer(value,name,minimum)
    if value>U64:raise ValueError('native u64 overflow')
    return value

def hashed(value):
    if not isinstance(value,str)or re.fullmatch('[0-9a-f]{64}',value)is None:raise ValueError('canonical native digest required')
    return value

def _canonical(raw,fields):
    if not isinstance(raw,bytes):raise ValueError('exact original private bytes required')
    value=_json(raw)
    if not isinstance(value,dict)or tuple(value)!=fields or encode(value)!=raw:raise ValueError('native field/order/canonical bytes differ')
    return value

def policy(raw,*,expected_sha256,network,actual_genesis,declaration_raw=None):
    if not isinstance(raw,bytes)or len(raw)>1024 or sha(raw)!=hashed(expected_sha256):raise ValueError('actual immutable native policy differs')
    value=_json(raw);fields=('urgent_reserve_sat','ordinary_budget_sat')
    if isinstance(value,dict)and'regtest_qualification'in value:fields+=('regtest_qualification',)
    value=_canonical(raw,fields);urgent=number(value['urgent_reserve_sat'],'physical urgent reserve',40000)
    total=number(value['ordinary_budget_sat'],'ordinary lifetime allowance',1)
    if urgent>MAX_MONEY:raise ValueError('urgent money bound exceeded')
    if network not in {'signet','regtest'}or actual_genesis!={'signet':SIGNET_GENESIS,'regtest':REGTEST_GENESIS}[network]:
        raise ValueError('actual independent verified chain differs')
    marker=value.get('regtest_qualification')
    if marker is None:
        if len(value)!=2 or total>60000 or declaration_raw is not None:raise ValueError('live allowance/declaration differs')
        return value,None
    if network!='regtest'or not isinstance(marker,dict)or tuple(marker)!=('max_attempts','per_attempt_ceiling_sat','declaration_sha256'):
        raise ValueError('finite REGTEST marker shape/chain differs')
    n=number(marker['max_attempts'],'finite attempts',1);c=number(marker['per_attempt_ceiling_sat'],'finite C',1)
    if n>=2**32 or n*(len(str(c))+1)>MAX_HISTORY or n*c>U64 or n*c!=total:raise ValueError('finite declared count/ceiling differs')
    if not isinstance(declaration_raw,bytes)or not 0<len(declaration_raw)<=4096 or sha(declaration_raw)!=hashed(marker['declaration_sha256']):
        raise ValueError('original REGTEST declaration missing/different')
    d=_canonical(declaration_raw,('version','purpose','network','genesis','max_attempts','per_attempt_ceiling_sat','ordinary_budget_sat','urgent_reserve_sat','workload_sha256'))
    if(type(d['version'])is not int or d['version']!=1 or d['purpose']!='common-regtest-scale-qualification'
            or d['network']!='regtest'or d['genesis']!=actual_genesis or d['max_attempts']!=n
            or type(d['max_attempts'])is not int or d['per_attempt_ceiling_sat']!=c or type(d['per_attempt_ceiling_sat'])is not int
            or d['ordinary_budget_sat']!=total or type(d['ordinary_budget_sat'])is not int
            or d['urgent_reserve_sat']!=urgent or type(d['urgent_reserve_sat'])is not int
            or hashed(d['workload_sha256'])=='0'*64):raise ValueError('original REGTEST declaration semantics differ')
    return value,c


def _bytes(values):
    if not isinstance(values,list)or not 0<len(values)<=MAX_RECORD or any(type(v)is not int or not 0<=v<=255 for v in values):
        raise ValueError('bounded original transaction u8 array required')
    return bytes(values)

def witness(raw,entry,*,policy_sha256,regtest_ceiling):
    if not isinstance(raw,bytes)or not 0<len(raw)<=MAX_RECORD or sha(raw)!=entry['record_sha256']:
        raise ValueError('original publication witness hash/size differs')
    record=_canonical(raw,RECORD)
    if(record['version']!=entry['version']or type(record['version'])is not int or record['path']!=entry['path']
            or record['policy_sha256']!=policy_sha256):raise ValueError('original witness version/path/policy differs')
    signed=_bytes(record['raw']);tx=decode_transaction(signed.hex());wtxid=hashlib.sha256(hashlib.sha256(signed).digest()).digest()[::-1].hex()
    if tx['weight']>400000 or len(tx['inputs'])>4096 or wtxid!=entry['wtxid']:raise ValueError('actual signed publication weight/wtxid differs')
    points=[v['outpoint']for v in tx['inputs']]
    if len(set(points))!=len(points)or any(v=='0'*64+':4294967295'for v in points):raise ValueError('duplicate/coinbase native spend')
    parents=record['input_parents']
    if not isinstance(parents,list)or len(parents)>4096:raise ValueError('bounded original parents required')
    decoded={};size=len(signed)
    for parent in parents:
        original=_bytes(parent);size+=len(original);p=decode_transaction(original.hex())
        if size>MAX_RECORD or p['txid']in decoded:raise ValueError('original parents duplicate/byte bound exceeded')
        decoded[p['txid']]=p
    required={p.split(':')[0]for p in points}
    if set(decoded)!=required:raise ValueError('all original parents exact coverage required')
    gross=0
    for point in points:
        ident,index=point.split(':');outputs=decoded[ident]['outputs'];index=int(index)
        if index>=len(outputs):raise ValueError('original prevout missing')
        gross+=outputs[index]['amount_sat']
        if gross>MAX_MONEY:raise ValueError('gross money bound exceeded')
    fee=gross-sum(v['amount_sat']for v in tx['outputs']);rate=number(record['max_fee_rate'],'frozen SAT/KWU',1)
    product=rate*tx['weight']
    if product>U64:raise ValueError('native signed-rate multiplication overflow')
    ceiling=(product+999)//1000
    if not 0<fee<=ceiling or fee!=entry['fee_sat']:raise ValueError('actual signed fee/rate ceiling differs')
    charge=regtest_ceiling if regtest_ceiling is not None else(fee if entry['version']==1 else ceiling)
    if entry['charge_sat']!=charge or fee>charge:raise ValueError('full native publication charge differs')
    return {'wtxid':wtxid,'txid':tx['txid'],'version':entry['version'],'path':entry['path'],
      'record_sha256':sha(raw),'fee_sat':fee,'charge_sat':charge,'weight_wu':tx['weight'],'max_fee_rate_sat_kwu':rate,
      'input_parent_sha256':{k:sha(_bytes(v))for k,v in zip([decode_transaction(_bytes(p).hex())['txid']for p in parents],parents)}}


def decode(raw,*,policy_raw,expected_policy_sha256,publication_witnesses,network,actual_genesis,declaration_raw=None,previous_ledger=None):
    """Return reservations, not costs; exact private map must be whole source."""
    value,c=policy(policy_raw,expected_sha256=expected_policy_sha256,network=network,actual_genesis=actual_genesis,declaration_raw=declaration_raw)
    if not isinstance(raw,bytes)or len(raw)>MAX_HISTORY or(raw and not raw.endswith(b'\n')):raise ValueError('bounded complete native journal required')
    if previous_ledger is not None and(not isinstance(previous_ledger,bytes)or not raw.startswith(previous_ledger)or(previous_ledger and not previous_ledger.endswith(b'\n'))):
        raise ValueError('original joint native ledger was reset/replaced')
    if not isinstance(publication_witnesses,dict)or len(publication_witnesses)>4096:raise ValueError('whole private publication set required')
    numeric=[];entries={};total=0
    for line in raw.splitlines():
        if line.startswith(b'p1\t'):
            entry=_canonical(line[3:],ENTRY)
            if(type(entry['version'])is not int or entry['version']not in(1,2)or entry['path']not in('round','pool')
                    or hashed(entry['wtxid'])in entries):raise ValueError('typed native version/path/identity duplicated')
            hashed(entry['record_sha256']);fee=number(entry['fee_sat'],'actual native fee',1);charge=number(entry['charge_sat'],'retained publication charge',1)
            if fee>charge:raise ValueError('actual fee exceeds retained publication charge')
            entries[entry['wtxid']]=entry
        else:
            if re.fullmatch(b'[1-9][0-9]*',line)is None:raise ValueError('unknown/noncanonical native journal line')
            charge=number(int(line),'ordinary carrier ceiling',1)
            if c is not None and charge!=c:raise ValueError('carrier ceiling differs from exact declared C')
            numeric.append(charge)
        total+=charge
        if total>value['ordinary_budget_sat']:raise ValueError('existing cumulative native allowance exhausted')
    if set(entries)!=set(publication_witnesses):raise ValueError('missing/orphan/unindexed private publication witness')
    if any(not isinstance(v,bytes)for v in publication_witnesses.values())or sum(len(v)for v in publication_witnesses.values())>MAX_TOTAL:
        raise ValueError('private witness aggregate bound exceeded')
    records=[witness(publication_witnesses[k],entry,policy_sha256=expected_policy_sha256,regtest_ceiling=c)for k,entry in entries.items()]
    result={'kind':'c-joint-native-fee-journal-decoded','ledger_sha256':sha(raw),'policy_sha256':expected_policy_sha256,
      'numeric_carrier_reservations_sat':numeric,'carrier_booked_sat':sum(numeric),'publication_booked_sat':sum(e['charge_sat']for e in entries.values()),
      'ordinary_booked_sat':total,'ordinary_remaining_sat':value['ordinary_budget_sat']-total,'ordinary_budget_sat':value['ordinary_budget_sat'],
      'urgent_reserve_sat':value['urgent_reserve_sat'],'publications':records,'regtest_qualification':c is not None,
      'complete':False,'qualified':False,'financial_readiness':False,
      'scope':'private journal arithmetic only; reservations are not burned fees or input ownership/confirmed cost/readiness proof'}
    public_payload(result);return result
