"""Join ACTUAL native private proof output to the same owning snapshot.

The caller executes the source-admitted native tool on these exact private
request bytes and authenticates its executable before/after. This is not a
supplied-receipt admission path. Native types/signatures are verified by that
native tool, not a second Python codec. Current Core/descriptor/cost/liability
proof remains separate; no input release, payment or readiness is asserted.
"""
import re
from .b_native_owner_snapshot import need,number,hashed,rows
from .two_step_normal import digest,strict_json
from .model import canonical

MAX_REPLY=16*1024*1024
MAX_REQUEST=64*1024*1024
TOP={'schema','kind','sdk_commit','input_sha256','source_observation','original_sha256',
     'snapshot','funding_rows','urgent_rows','resolutions','nursery_inventory','unrelated_nursery_txids'}
FUNDING={'attempt_key','index','purpose','family','family_sha256','generation','unsigned_body_sha256',
    'prevouts_sha256','reservation_native_sha256','ceiling_sat','max_fee_rate_sat_kwu','unsigned','signed'}
URGENT={'index','ceiling_sat','policy_sha256','metadata_binding_sha256','source_anchors',
    'journal_binding_sha256','urgent_fee_bound','fee_sat','transactions'}
TX={'txid','wtxid','weight_wu','fee_sat','inputs','outputs'}
NURSERY={'txid','wtxid','weight_wu','kind','urgent_fee_bound','urgent_metadata_native_sha256'}


def point(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}:(0|[1-9][0-9]{0,9})',value)
        and int(value.split(':')[1])<2**32,'native public inputpoint differs')
    return value


def script(value):
    need(type(value) is str and len(value)<=20000 and len(value)%2==0
        and re.fullmatch('[0-9a-f]*',value) is not None,'native public script differs')


def transaction(tx):
    need(type(tx) is dict and set(tx)==TX,'exact safe native transaction fields required')
    hashed(tx['txid'],'native txid');hashed(tx['wtxid'],'native wtxid')
    number(tx['weight_wu'],'native signed weight',minimum=1,maximum=400000)
    number(tx['fee_sat'],'native actual fee')
    inputs=rows(tx['inputs'],'native input bound');outputs=rows(tx['outputs'],'native output bound')
    need(inputs,'native source inputs absent');seen=set()
    for row in inputs:
        need(type(row) is dict and set(row)=={'outpoint','value_sat','script_pubkey'},'safe native prevout fields required')
        p=point(row['outpoint']);need(p not in seen,'duplicate native input');seen.add(p)
        number(row['value_sat'],'native prevout value');script(row['script_pubkey'])
    for i,row in enumerate(outputs):
        need(type(row) is dict and set(row)=={'vout','value_sat','script_pubkey'}
            and type(row['vout']) is int and row['vout']==i,'safe native output inventory differs')
        number(row['value_sat'],'native output value');script(row['script_pubkey'])
    need(sum(r['value_sat']for r in inputs)<=21_000_000*100_000_000
        and sum(r['value_sat']for r in outputs)<=21_000_000*100_000_000
        and sum(r['value_sat']for r in inputs)-sum(r['value_sat']for r in outputs)==tx['fee_sat'],
         'native exact public prevout fee differs')
    return seen


def bind_native_fee_reply(request_raw,reply_raw,owner_snapshot_raw,*,expected_tool_commit):
    """Replay exact tool/input/safe projection joins, with no readiness flags.

    Executable/source admission and actual invocation are mandatory before call.
    Request preparation already bound protected files and same-RR byte sources.
    A missing actual native reply MUST remain a hold, never a fabricated fixture.
    """
    need(type(request_raw) is bytes and 0<len(request_raw)<=MAX_REQUEST
        and type(reply_raw) is bytes and 0<len(reply_raw)<=MAX_REPLY+1
        and len(reply_raw[:-1]if reply_raw.endswith(b'\n')else reply_raw)<=MAX_REPLY,
         'bounded actual private proof originals absent')
    request=strict_json(request_raw);reply=strict_json(reply_raw);owner=strict_json(owner_snapshot_raw)
    need(type(reply) is dict and set(reply)==TOP and type(reply['schema']) is int
        and reply['schema']==1 and reply['kind']=='b-native-fee-source-proof',
        'exact native fee proof schema required')
    need(reply['sdk_commit']==request['sdk_commit']==expected_tool_commit
        and reply['input_sha256']==digest(request_raw)
        and canonical(reply['source_observation'])==canonical(request['source_observation']),'actual native tool/input/context differs')
    need(reply['original_sha256']=={k:digest(v.encode())for k,v in request['originals'].items()},
         'actual original native file/SQL hashes differ')
    need(canonical(reply['snapshot'])==canonical({k:v for k,v in owner.items()if k not in {'journal_device','journal_inode'}}),
         'native private SQL/journal projection differs from current owning snapshot')
    funding={r['index']:r for r in owner['funding']};got=set();keys=set();selected=set()
    for row in rows(reply['funding_rows'],'safe native funding row bound'):
        need(type(row) is dict and set(row)==FUNDING,'exact safe funding proof fields required')
        i=number(row['index'],'native funding index',minimum=1,maximum=10000)
        need(i in funding and i not in got,'missing/duplicate/unexpected native funding attempt');got.add(i)
        key=hashed(row['attempt_key'],'native attempt key');need(key not in keys,'duplicate native attempt key');keys.add(key)
        for field in ('family_sha256','unsigned_body_sha256','prevouts_sha256','reservation_native_sha256'):hashed(row[field],field)
        public=funding[i]
        fields=('purpose','family_sha256','generation','unsigned_body_sha256','prevouts_sha256','ceiling_sat')
        need(canonical({k:row[k]for k in fields})==canonical({k:public[k]for k in fields}),
             'native funding original identity differs')
        family=row['family'];tag='Round'if row['purpose']=='round'else'Pool'
        need(type(family) is dict and set(family)=={tag} and type(family[tag]) is dict,'safe native family differs')
        if tag=='Round':
            need(set(family[tag])=={'round_seq','pinned_input'},'safe Round family fields differ')
            number(family[tag]['round_seq'],'actual Round sequence',maximum=2**64-1);point(family[tag]['pinned_input'])
        else:
            need(set(family[tag])=={'funding_txid'} and family[tag]['funding_txid']==public['txid'],'safe Pool family differs')
        unsigned=row['unsigned'];points=transaction(unsigned);selected.update(points)
        if tag=='Round':need(family[tag]['pinned_input']in points,'actual Round pinned input absent')
        need(unsigned['txid']==public['txid'] and unsigned['wtxid']==unsigned['txid']
            and unsigned['fee_sat']==row['ceiling_sat'],'native unsigned original fee/body differs')
        rate=number(row['max_fee_rate_sat_kwu'],'native original rate',minimum=1,maximum=2**64-1)
        signed=row['signed']
        need((signed is None)==(public['signed_wtxid'] is None),'native signed state differs')
        if signed is not None:
            transaction(signed)
            need(signed['txid']==unsigned['txid'] and signed['wtxid']==public['signed_wtxid']
                and all(signed[k]==unsigned[k]for k in ('fee_sat','inputs','outputs'))
                and signed['fee_sat']<=(rate*signed['weight_wu']+999)//1000,
                'native exact signed funding proof differs')
    need(got==set(funding),'native funding row coverage differs')
    urgent={r['index']:r for r in owner['urgent']};got=set();members=set()
    for row in rows(reply['urgent_rows'],'safe native urgent row bound'):
        need(type(row) is dict and set(row)==URGENT,'exact safe urgent proof fields required')
        i=number(row['index'],'native urgent index',minimum=1,maximum=10000)
        number(row['ceiling_sat'],'native urgent ceiling',minimum=1);number(row['fee_sat'],'native urgent fee')
        need(i in urgent and i not in got,'unexpected/duplicate urgent publication');got.add(i);public=urgent[i]
        need(row['ceiling_sat']==public['ceiling_sat'] and row['policy_sha256']==owner['policy_sha256']
            and row['journal_binding_sha256']==public['source_binding_sha256']
            and type(row['urgent_fee_bound']) is bool,'native urgent source/ceiling differs')
        hashed(row['metadata_binding_sha256'],'native urgent metadata binding')
        anchors=rows(row['source_anchors'],'safe urgent anchor bound')
        need(anchors and anchors==sorted(set(point(p)for p in anchors)),'native urgent anchors differ')
        txs=rows(row['transactions'],'safe urgent package bound');need(1<=len(txs)<=2,'complete urgent package required')
        ids=[]
        for tx in txs: selected.update(transaction(tx));members.add(tx['txid']);ids.append({'txid':tx['txid'],'wtxid':tx['wtxid']})
        need(len({t['txid']for t in txs})==len(txs)
            and sum(t['weight_wu']for t in txs)<=400000
            and sum(t['fee_sat']for t in txs)==row['fee_sat']<=row['ceiling_sat'],
            'native whole urgent package fee differs')
        if row['journal_binding_sha256'] is None:need(not row['urgent_fee_bound'],'unbound urgent publication permitted')
        else:need(ids==public['transactions'] and row['metadata_binding_sha256']==row['journal_binding_sha256'],
                  'native exact urgent retained package differs')
    need(all(r['source_binding_sha256'] is None or i in got for i,r in urgent.items()),
         'signed urgent journal lost original SQL publication')
    need(canonical(reply['resolutions'])==canonical(owner['resolutions']),'native resolution SQL coverage differs')
    inventory={}
    for row in rows(reply['nursery_inventory'],'safe complete nursery bound'):
        need(type(row) is dict and set(row)==NURSERY,'safe nursery projection fields differ')
        ident=hashed(row['txid'],'native nursery txid');hashed(row['wtxid'],'native nursery wtxid')
        need(ident not in inventory and type(row['urgent_fee_bound']) is bool
            and type(row['kind']) is str and row['kind'] in {'internal','offboard','round','vtxopool','expiry-payout'},'native nursery inventory differs')
        number(row['weight_wu'],'native nursery weight',minimum=1,maximum=400000)
        if row['urgent_metadata_native_sha256'] is not None:hashed(row['urgent_metadata_native_sha256'],'native nursery metadata')
        inventory[ident]=row
    for publication in reply['urgent_rows']:
        txs=publication['transactions']
        for i,tx in enumerate(txs):
            actual=inventory.get(tx['txid'],{})
            need(actual.get('wtxid')==tx['wtxid'] and actual.get('weight_wu')==tx['weight_wu']
                and actual.get('kind')=='internal','urgent exact nursery member differs')
            if i+1==len(txs):
                need(actual.get('urgent_metadata_native_sha256')==publication['metadata_binding_sha256']
                    and actual.get('urgent_fee_bound')==publication['urgent_fee_bound'],
                    'urgent publication row metadata/bound state differs')
            else:need(actual.get('urgent_metadata_native_sha256') is None,'urgent shared parent metadata differs')
    need(members<=set(inventory) and reply['unrelated_nursery_txids']==sorted(set(inventory)-members),
         'whole nursery member/unrelated inventory differs')
    return {'proof_sha256':digest(reply_raw),'request_sha256':digest(request_raw),
        'original_sha256':reply['original_sha256'],'funding_rows':reply['funding_rows'],
        'urgent_rows':reply['urgent_rows'],'resolutions':reply['resolutions'],
        'nursery_inventory':reply['nursery_inventory'],'unrelated_nursery_txids':reply['unrelated_nursery_txids'],
        'publication_inputpoints':sorted(selected)}
