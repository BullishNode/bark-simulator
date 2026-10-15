"""Private native witness projection; this cannot prove terminal customer payment.

Original transaction witnesses stay inside this function. The public result keeps
only the existing txid-preserving stripped body, original weight and file hashes.
The caller retains private originals and separately checks SQL, chain and owners.
"""
import hashlib
import json
import re

from .bundle_audit import decode_transaction
from .model import InvariantError, integer, public_payload
from .ownership import EvidenceGap

MAX_WITNESS_BYTES = 256*1024
MAX_SETTLEMENTS = 2000


def _json(raw, limit, name):
    if not isinstance(raw, bytes) or len(raw)>limit:
        raise EvidenceGap('bounded private '+name+' bytes required')
    def unique(items):
        result={}
        for key,value in items:
            if key in result:raise InvariantError('duplicate native JSON field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)


def _point(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}:(0|[1-9][0-9]{0,9})',value) is None:
        raise ValueError('invalid native settlement/source point')
    if int(value.split(':')[1])>=2**32:raise ValueError('native outpoint exceeds uint32')
    return value


def _bytes(value, maximum):
    if not isinstance(value,list) or len(value)>maximum or any(type(v)is not int or not 0<=v<=255 for v in value):
        raise ValueError('invalid bounded native byte vector')
    return bytes(value)


def project_private_witness(identity_raw, history_raw, record_name, witness_raw, expected_identity):
    """Project one exact indexed native file; perform no I/O or event mutation.

    This verifies internal identity/body/allocation agreement, not signatures,
    native database survival, entitlement arbitration or confirmed receipt.
    """
    if not isinstance(expected_identity,dict) or set(expected_identity)!={'version','genesis','server_pubkey'}:
        raise ValueError('independently supplied native identity required')
    identity=_json(identity_raw,4096,'identity')
    if (identity!=expected_identity or type(identity.get('version')) is not int or identity['version']!=1
            or not isinstance(identity.get('genesis'),str) or re.fullmatch('[0-9a-f]{64}',identity['genesis']) is None
            or not isinstance(identity.get('server_pubkey'),str) or re.fullmatch('0[23][0-9a-f]{64}',identity['server_pubkey']) is None):
        raise InvariantError('native witness network/server identity differs')
    if not isinstance(history_raw,bytes) or len(history_raw)>4096:
        raise EvidenceGap('bounded original history required')
    history=history_raw.decode('ascii')
    if history and not history.endswith('\n'):raise InvariantError('torn native history append')
    indexed=history.splitlines()
    if len(set(indexed))!=len(indexed) or any(re.fullmatch('[0-9a-f]{64}',item) is None for item in indexed):
        raise InvariantError('duplicate or malformed native history entry')
    if not isinstance(record_name,str) or re.fullmatch('[0-9a-f]{64}\\.json',record_name) is None:
        raise ValueError('exact native txid filename required')
    txid=record_name[:-5]
    if txid not in indexed:raise EvidenceGap('record is not in original durable history')
    witness=_json(witness_raw,MAX_WITNESS_BYTES,'witness')
    if not isinstance(witness,dict) or not {'tx','settlements'}<=witness.keys() or set(witness)-{'tx','settlements','capital_releases'}:
        raise ValueError('actual native witness schema required')
    original=_bytes(witness['tx'],MAX_WITNESS_BYTES)
    decoded=decode_transaction(original.hex(),public_body=True)
    if decoded['txid']!=txid:raise InvariantError('native filename and signed body txid differ')
    if any(decoded['input_script_sig_sizes']):
        raise EvidenceGap('public export refuses nonempty scriptSig')
    settlements=witness['settlements']
    if not isinstance(settlements,list) or not 0<len(settlements)<=MAX_SETTLEMENTS:
        raise EvidenceGap('bounded nonempty native settlement rows required')
    selected=[];ids=set();gaps=[]
    for row in settlements:
        if not isinstance(row,dict) or set(row)!={'id','spk','fee_sat'}:
            raise ValueError('exact native settlement row required')
        point=_point(row['id'])
        if point in ids:raise InvariantError('same settlement appears twice')
        ids.add(point)
        script=None if row['spk'] is None else _bytes(row['spk'],10000).hex()
        if not script:gaps.append('original_settlement_destination_unavailable:'+point)
        selected.append({'id':point,'script':script,'fee_sat':integer(row['fee_sat'],'native recipient fee')})
    releases=witness.get('capital_releases')
    projected_releases=[]
    if releases is None:
        gaps.append('native_capital_release_witness_unavailable')
    else:
        if not isinstance(releases,list) or len(releases)!=len(selected):
            raise InvariantError('native capital witness does not cover exact settlement set')
        release_ids=set(); source_bounds={}
        fields={'id','source','receipt','gross_sat','source_gross_sat','source_revision','receipt_block_hash'}
        for row in releases:
            if not isinstance(row,dict) or set(row)!=fields:raise ValueError('exact native capital release row required')
            point=_point(row['id']);_point(row['source'])
            if point not in ids or point in release_ids:raise InvariantError('native release identity differs or repeats')
            release_ids.add(point)
            for key in ['receipt','receipt_block_hash']:
                if not isinstance(row[key],str) or re.fullmatch('[0-9a-f]{64}',row[key]) is None:
                    raise ValueError('native capital receipt identity invalid')
            gross=integer(row['gross_sat'],'native released gross',1)
            if gross>integer(row['source_gross_sat'],'native source gross',1):
                raise InvariantError('released claim exceeds source physical bound')
            integer(row['source_revision'],'native source revision')
            source=source_bounds.setdefault(row['source'],{'receipt':row['receipt'],
                'block':row['receipt_block_hash'],'gross':row['source_gross_sat'],'selected':0})
            if (source['receipt'],source['block'],source['gross'])!=(row['receipt'],row['receipt_block_hash'],row['source_gross_sat']):
                raise InvariantError('same native backing source has conflicting physical identities')
            source['selected']+=gross
            if source['selected']>source['gross']:
                raise InvariantError('selected claims exceed the same source physical bound')
            projected_releases.append(dict(row))
    result={'kind':'two_step_native_witness_projection','schema_version':1,
        'identity':identity,'payout_txid':txid,'transaction_body':decoded['stripped_hex'],
        'encoding':'bitcoin-stripped-body-v1','original_signed_weight_wu':decoded['weight'],
        'original_signed_body_sha256':hashlib.sha256(original).hexdigest(),
        'original_file_sha256':{'identity':hashlib.sha256(identity_raw).hexdigest(),
            'history':hashlib.sha256(history_raw).hexdigest(),'witness':hashlib.sha256(witness_raw).hexdigest()},
        'settlements':selected,'capital_releases':projected_releases,
        'complete':False,'terminal_payment_verified':False,
        'gaps':gaps+['native_SQL_nursery_settlement_release_cut_not_exported',
            'independent_confirmed_backing_and_payout_not_checked',
            'signed_original_coin_owner_and_arbitration_not_checked',
            'actual_miner_fee_prevouts_and_recipient_conservation_not_checked'],
        'scope':'One original private native witness only; no terminal, economic or live-readiness verdict'}
    public_payload(result)
    return result
