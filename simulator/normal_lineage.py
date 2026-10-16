"""Private source-only lineage joins. No RPC, Wallet, journal or readiness writes.

The caller must execute its admitted native Full/per-key verifier for EVERY coin
and pass the exact request/response buffers to bind_coin. No SQL flag or supplied
boolean substitutes for that execution. Backing and current source freshness are
separate mandatory collector checks. Round retirement additionally requires an
admitted original-forfeit executor; absent support fails closed.
"""
import hashlib
import json
import re
import heapq
from collections import Counter

MAX_COINS = 10000
MAX_SAT = 2_100_000_000_000_000
# Exact selected proof-source SDK pin; this constant does not qualify a tool.
# Executable/source/command qualification and admission remain mandatory.
# Prior e217 helper receipts remain separate from this cccc source successor.
NATIVE_COMPLETION_SDK = 'cccc3f5747ad11b07b4742df1a25fb7b3ebe29c9'


def need(value, message):
    if not value:
        raise ValueError(message)


def amount(value):
    need(type(value) is int and 0 < value <= MAX_SAT, 'positive signed amount required')
    return value


def sha(raw):
    need(isinstance(raw, bytes), 'original bytes required')
    return hashlib.sha256(raw).hexdigest()


def hash_id(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'source hash required')
    return value


def point(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}:(0|[1-9][0-9]{0,9})', value), 'coin outpoint required')
    ident, index = value.split(':')
    need(int(index) < 2**32, 'outpoint index overflow')
    return ident, int(index)


def strict(raw):
    need(isinstance(raw, bytes) and len(raw) <= 2*1024*1024, 'bounded original native proof required')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate proof field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def ids(values):
    need(isinstance(values, list) and 0 < len(values) <= MAX_COINS, 'nonempty bounded coin IDs required')
    for value in values:
        point(value)
    need(len(values) == len(set(values)), 'duplicate input/output identity')
    return tuple(values)


def bind_coin(owned, native, request_raw, response_raw, *, genesis, server_pubkey,
              policy_request_raw=None, policy_response_raw=None, anchor_raw=None,
              policy_sdk_commit=None):
    """Bind completed owned Full AND literal native representation after execution.

    Different native/client bodies require the admitted helper's exact four-key
    native_vtxo mode. This parser does not execute a verifier or admit tools;
    source/nonce/tool/command and private original retention remain mandatory.
    Binding-only, public projection and completion verdicts supplied without the
    exact executed request/response cannot satisfy this contract.
    """
    req, proof = strict(request_raw), strict(response_raw)
    need(isinstance(req, dict) and isinstance(proof, dict)
        and set(req) == {'signed_vtxo', 'binding', 'key_link_attestation'},
        'Full-mode per-key request required')
    need(req['signed_vtxo'] == owned['signed_vtxo'], 'retained completed Full original differs')
    completed_raw = bytes.fromhex(owned['signed_vtxo'])
    native_raw = bytes.fromhex(native['signed_vtxo_hex'])
    need(sha(completed_raw) == owned['signed_hash'], 'original owned signed bytes changed')
    preserved = strict(owned['proof'].encode()) if isinstance(owned['proof'], str) else owned['proof']
    key = owned['pubkey']; ident = owned['id']; point(ident)
    expected = {'id': ident, 'amount_sat': amount(owned['amount_sat']), 'user_pubkey': key,
        'chain_anchor': preserved['chain_anchor'], 'expiry_height': preserved['expiry_height'],
        'genesis': genesis, 'server_pubkey': server_pubkey}
    need(all(proof.get(key) == value for key, value in expected.items()), 'executed Full proof identity differs')
    need(proof.get('signed_path_valid') is True and proof.get('authorization_path_valid') is True
        and type(proof.get('conditional_steps')) is int and proof['conditional_steps'] == 0,
        'ordinary signed Full path required')
    need(native['vtxo_id'] == ident and native['policy_type'] == 'pubkey'
        and native['amount'] == owned['amount_sat'] and native['server_pubkey'] == server_pubkey
        and native['anchor_point'] == proof['chain_anchor'] and native['expiry'] == proof['expiry_height'],
        'native and owned coin differ')
    bound = proof['binding']; original = preserved['binding']; wanted = req['binding']
    need(bound.get('record_signature_valid') is True and bound.get('key_link_signature_valid') is True,
        'executed per-key ownership proof required')
    need(all(bound[key] == original[key] == wanted[key] for key in ('mailbox_pk', 'spk', 'seq')),
        'original rotating owner binding differs')
    path = proof.get('path')
    need(isinstance(path, list) and 0 < len(path) <= 256, 'actual authenticated path required')
    for step in path:
        hash_id(step['txid']); ids(step['inputs']); amount(step['output_amount_sat'])
        need(type(step['output_index']) is int and 0 <= step['output_index'] < 2**32,
            'actual path output index differs')
    need(path[-1]['txid']+':'+str(path[-1]['output_index']) == ident
        and path[-1]['output_amount_sat'] == owned['amount_sat'], 'signed path terminal differs')
    result = {'id': ident, 'actor': owned['actor'], 'pubkey': key, 'amount_sat': owned['amount_sat'],
        'chain_anchor': proof['chain_anchor'], 'path': path,
        'native_request_sha256': sha(request_raw), 'native_response_sha256': sha(response_raw),
        'native_full_sha256': sha(native_raw), 'completed_full_sha256': sha(completed_raw),
        'completed_vtxo_hex': owned['signed_vtxo']}
    if policy_request_raw is None and policy_response_raw is None and anchor_raw is None and policy_sdk_commit is None:
        need(native_raw == completed_raw, 'different native Full requires executed strict completion proof')
        return result
    need(isinstance(anchor_raw, str) and policy_sdk_commit == NATIVE_COMPLETION_SDK,
        'exact admitted native-completion anchor/SDK required')
    preq, policy = strict(policy_request_raw), strict(policy_response_raw)
    need(isinstance(preq, dict) and isinstance(policy, dict)
        and set(preq) == {'signed_vtxo', 'native_vtxo', 'anchor_raw', 'server_pubkey'}
        and preq == {'signed_vtxo': owned['signed_vtxo'], 'native_vtxo': native['signed_vtxo_hex'],
            'anchor_raw': anchor_raw, 'server_pubkey': server_pubkey},
        'literal completed/native Full and source anchor request required')
    expected_policy = {'schema_version': 1, 'sdk_commit': policy_sdk_commit, 'id': ident,
        'amount_sat': owned['amount_sat'], 'candidate_user_pubkey': key,
        'chain_anchor': proof['chain_anchor'], 'server_pubkey': server_pubkey,
        'expiry_height': preserved['expiry_height'], 'policy': 'pubkey', 'tree_padding': False,
        'signed_path_valid': True, 'chain_contract_verified': True, 'client_owner_verified': False,
        'native_owner_verified': False, 'payment_verified': False,
        'native_vtxo_sha256': sha(native_raw), 'completed_vtxo_sha256': sha(completed_raw)}
    need(all(type(policy.get(key)) is type(value) and policy[key] == value
        for key, value in expected_policy.items()), 'executed native-completion proof differs')
    relation = 'exact_full_equality' if native_raw == completed_raw else 'final_hark_leaf_completion'
    need(policy.get('native_completion_relation') == relation,
        'strict known-field-preserving completion relation required')
    unlock = policy.get('unlock_hash')
    need(unlock is None or isinstance(unlock, str) and re.fullmatch('[0-9a-f]{64}', unlock),
        'validated leaf unlock hash malformed')
    return {**result, 'unlock_hash': unlock, 'native_completion_relation': relation,
        'native_policy_request_sha256': sha(policy_request_raw),
        'native_policy_response_sha256': sha(policy_response_raw)}


def direct_origin(coin, input_ids):
    """Match ONE immediate operation, never an original ancestor across splits."""
    path = coin['path']; inputs = set(input_ids)
    for index, step in enumerate(path):
        parents = step['inputs']
        if not parents or len(parents) != len(set(parents)) or not set(parents) <= inputs:
            continue
        if step['output_amount_sat'] != coin['amount_sat']:
            continue
        previous = step['txid']+':'+str(step['output_index'])
        for later in path[index+1:]:
            if later['inputs'] != [previous] or later['output_amount_sat'] != coin['amount_sat']:
                break
            previous = later['txid']+':'+str(later['output_index'])
        else:
            if previous == coin['id']:
                return {'inputs': tuple(parents), 'branch_txid': step['txid']}
    raise ValueError('output lacks exact immediate signed parent lineage')


def authenticate_owned_originals(store, tables, tools, *, genesis, server_pubkey):
    """Execute existing admitted Full-path AND pure Full-policy tools.

    Proposal hook NOT executed here. No SDK wallet is opened. The caller admits
    exact tools/module/commands and enforces source deadline before invoking.
    """
    from simulator.two_step_normal import run_proof
    from simulator.unknown_outcomes import _coins
    native = {row['vtxo_id']: row for row in tables['vtxo']}
    virtual = {row['txid']: row for row in tables['virtual_transaction']}
    need(len(native) == len(tables['vtxo']) and len(virtual) == len(tables['virtual_transaction']), 'duplicate native Full/anchor identity')
    owned = store.db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey ORDER BY c.id').fetchall()
    need(0 < len(owned) <= MAX_COINS, 'bounded complete original ownership required')
    result = {}
    for original in owned:
        identifier = original['id']; row = native.get(identifier)
        need(row is not None, 'original/intermediate owned Full missing; cannot discard obligation')
        _coins(store,[identifier],original['actor'])
        links = [x for x in tables['key_link'] if x['user_pubkey'] == original['pubkey']]
        records = [] if len(links) != 1 else [x for x in tables['fallback_record'] if x['mailbox_pk'] == links[0]['mailbox_pk']]
        need(len(links) == len(records) == 1, 'one exact native rotating owner record required')
        record = records[0]
        # Verify the actual retained completed Full, never ask the binding tool
        # to treat a partial SQL representation as a signed path.
        request = {'signed_vtxo':original['signed_vtxo'],'key_link_attestation':links[0]['sig'],
            'binding':{'mailbox_pk':record['mailbox_pk'],'spk':record['spk'],'seq':record['seq'],'record_attestation':record['sig']}}
        sent, received = run_proof(tools['binding'],request)
        need(strict(sent) == request, 'actual native Full request changed')
        anchor = virtual.get(point(row['anchor_point'])[0])
        need(anchor is not None and anchor['is_funding'] is True, 'original Full anchor missing')
        policy_request = {'signed_vtxo':original['signed_vtxo'], 'native_vtxo':row['signed_vtxo_hex'],
            'anchor_raw':anchor['signed_transaction_hex'], 'server_pubkey':server_pubkey}
        psent, preceived = run_proof(tools['policy'],policy_request)
        need(strict(psent) == policy_request, 'actual native completion request changed')
        result[identifier] = bind_coin(original,row,sent,received,genesis=genesis,server_pubkey=server_pubkey,
            policy_request_raw=psent, policy_response_raw=preceived,
            anchor_raw=anchor['signed_transaction_hex'], policy_sdk_commit=NATIVE_COMPLETION_SDK)
    store.verify_event_chain()
    return result


def arkoor_edge(action_id, input_ids, output_ids, recipient_ids, coins, native, *,
                sender, recipient, transfer_sat, evidence_sha256):
    """Caller has joined one original completed intent/credit/two movements."""
    inputs, outputs = ids(input_ids), ids(output_ids); receipts = ids(recipient_ids)
    need(set(inputs+outputs) <= set(coins) and set(inputs) <= set(native), 'signed coin/native input missing')
    need(set(receipts) <= set(outputs), 'recipient output absent from full allocation')
    need(sender != recipient and amount(transfer_sat) == sum(coins[x]['amount_sat'] for x in receipts),
        'original recipient transfer differs')
    need(all(coins[x]['actor'] == sender for x in inputs), 'foreign input owner')
    need(all(coins[x]['actor'] == (recipient if x in receipts else sender) for x in outputs),
        'foreign output owner')
    covered = set(); branches = {}
    for ident in outputs:
        origin = direct_origin(coins[ident], inputs)
        for parent in origin['inputs']:
            row = native[parent]
            need(row['oor_spent_txid'] == origin['branch_txid'] and row['spent_in_round'] is None
                and row['offboarded_in'] is None and row['onchain_spent_txid'] is None
                and row['spend_state'] == 'spent', 'native immediate Ark disposition differs')
            need(parent not in branches or branches[parent] == origin['branch_txid'], 'conflicting Ark branches')
            branches[parent] = origin['branch_txid']; covered.add(parent)
    need(covered == set(inputs), 'signed Ark allocation omits an input')
    need(sum(coins[x]['amount_sat'] for x in inputs) == sum(coins[x]['amount_sat'] for x in outputs),
        'Ark signed amounts do not conserve')
    return {'action_id': action_id, 'kind': 'arkoor', 'inputs': inputs, 'outputs': outputs,
        'service_fee_sat': 0, 'evidence_sha256': hash_id(evidence_sha256), 'branches': branches}


TREE_PIN_FIELDS = {'tool_sha256','commands_sha256','admission_sha256','sdk_commit',
                   'source_observation_id','source_sha256','qualification_scope'}


def original_hex(value):
    need(isinstance(value,str) and 0 < len(value) <= 2*1024*1024 and len(value)%2 == 0
        and re.fullmatch('[0-9a-f]+',value), 'bounded canonical original hex required')
    return bytes.fromhex(value)


def execute_tree_proof(request, executor, pins):
    """Pinned callback transport, not a substitute for actual source admission.

    executor(request, expected=pins) returns exact (request bytes, response bytes,
    actual execution binding). The caller authenticates the admission event,
    binary/argv/source/nonce before invoking. Software stub scope is propagated
    and never becomes actual native/crypto/financial qualification here.
    """
    need(callable(executor) and isinstance(pins,dict) and set(pins)==TREE_PIN_FIELDS,
        'pinned native tree/forfeit callback unavailable')
    for key in ('tool_sha256','commands_sha256','admission_sha256','source_sha256'):
        hash_id(pins[key])
    need(isinstance(pins['sdk_commit'],str) and re.fullmatch('[0-9a-f]{40}',pins['sdk_commit']), 'exact SDK pin required')
    need(isinstance(pins['source_observation_id'],str) and re.fullmatch('[0-9a-f]{32}',pins['source_observation_id']), 'source observation nonce required')
    need(pins['qualification_scope'] in {'admitted_native','software_stub_no_native_credit'}, 'unknown proof qualification scope')
    packet=executor(request,expected=dict(pins))
    need(isinstance(packet,tuple) and len(packet)==3, 'original execution buffers and binding required')
    sent,received,binding=packet
    need(isinstance(binding,dict) and binding==pins, 'actual tool/command/admission/source binding differs')
    need(strict(sent)==request, 'executed tree/forfeit request differs')
    proof=strict(received)
    need(isinstance(proof,dict) and type(proof.get('schema_version')) is int and proof['schema_version']==1 and proof.get('sdk_commit')==pins['sdk_commit'], 'executed proof SDK/schema differs')
    return proof,{'request_sha256':sha(sent),'response_sha256':sha(received),'execution_binding':dict(pins)}


def tree_context(round_row,part,decode_transaction):
    tree=original_hex(round_row.get('signed_tree_hex'))
    anchor=original_hex(round_row.get('funding_tx_hex'))
    funding=hash_id(part['round_id']);hash_id(part['unlock_hash'])
    need(round_row['funding_txid']==funding and decode_transaction(anchor.hex())['txid']==funding,
        'original signed tree round/funding identity differs')
    return {'signed_tree':tree.hex(),'anchor_raw':anchor.hex(),'server_pubkey':part['expected_server_pubkey'],
            'participation_unlock_hash':part['unlock_hash']}


def tree_response_context(proof,request,mode):
    need(proof.get('mode')==mode and proof.get('server_pubkey')==request['server_pubkey']
        and proof.get('participation_unlock_hash')==request['participation_unlock_hash']
        and proof.get('signed_tree_sha256')==sha(original_hex(request['signed_tree']))
        and proof.get('anchor_raw_sha256')==sha(original_hex(request['anchor_raw'])),
        'authenticated tree mode/original context differs')
    anchor=point(proof.get('chain_anchor'))
    need(type(proof.get('tree_leaf_count')) is int and 2 <= proof['tree_leaf_count'] <= 4096
        and type(proof.get('verified_internal_signature_count')) is int
        and 0 < proof['verified_internal_signature_count'] < proof['tree_leaf_count'], 'native tree signature/count bounds differ')
    for key in ('client_owner_verified','payment_verified'):
        need(proof.get(key) is False, 'tree proof must not grant owner/payment verdict')
    return anchor


def proof_indices(proof,key,allocations):
    values=proof.get(key)
    need(isinstance(values,list) and 0 < len(values) <= 256 and all(type(x) is int and 0 <= x < proof['tree_leaf_count'] for x in values)
        and len(values)==len(set(values))
        and values==sorted(values), 'ALL native tree leaf indices required')
    need(isinstance(allocations,list) and len(allocations)==len(values) and all(isinstance(x,dict)for x in allocations), 'all tree allocations required')
    need([x.get('leaf_index')for x in allocations]==values, 'allocation leaf indices differ')
    return values


def allocation_terms(allocation):
    need(isinstance(allocation,list) and 0 < len(allocation) <= 256, 'all original participation requests required')
    terms=[]
    for row in allocation:
        policy=row['policy_hex']
        need(isinstance(policy,str) and re.fullmatch('00[0-9a-f]{66}',policy), 'nonordinary original request')
        terms.append((policy,amount(row['amount'])))
    return Counter(terms)


def completed_tree_allocation(round_row,part,outputs,coins,native,allocation,decode_transaction,executor,pins):
    need(set(outputs)<=set(native),'completed native output missing')
    servers={native[x]['server_pubkey']for x in outputs};need(len(servers)==1,'foreign completed output server')
    part={**part,'expected_server_pubkey':servers.pop()}
    request=tree_context(round_row,part,decode_transaction)
    request['outputs']=[]
    for ident in sorted(outputs):
        raw=original_hex(coins[ident].get('completed_vtxo_hex'))
        native_raw=original_hex(native[ident]['signed_vtxo_hex'])
        need(sha(raw)==coins[ident]['completed_full_sha256'] and sha(native_raw)==coins[ident]['native_full_sha256'],
            'completed/native output originals differ from admitted owned proof')
        need(native[ident]['server_pubkey']==request['server_pubkey'], 'foreign completed output server')
        request['outputs'].append({'signed_vtxo':raw.hex(),'native_vtxo':native_raw.hex()})
    proof,evidence=execute_tree_proof(request,executor,pins)
    anchor=tree_response_context(proof,request,'round_allocation')
    need(anchor[0]==part['round_id'] and all(coins[x]['chain_anchor']==proof['chain_anchor']for x in outputs), 'complete tree native anchor differs')
    leaves=proof.get('allocations');indexes=proof_indices(proof,'all_matching_leaf_indices',leaves)
    need(proof.get('all_matching_leaves_verified') is True and 'pending_allocations' not in proof,
        'completed tree allocation proof required')
    need({x.get('id')for x in leaves}==set(outputs) and len(leaves)==len(outputs), 'tree allocation extra/missing/duplicate output')
    terms=[];total=0
    for leaf in leaves:
        ident=leaf['id'];coin=coins[ident];raw=original_hex(coin.get('completed_vtxo_hex'))
        native_raw=original_hex(native[ident]['signed_vtxo_hex'])
        need(amount(leaf.get('amount_sat'))==amount(coin['amount_sat']) and leaf.get('policy')=='pubkey'
            and leaf.get('user_pubkey')==coin['pubkey'] and leaf.get('user_policy_hex')=='00'+coin['pubkey']
            and leaf.get('unlock_hash')==part['unlock_hash'] and leaf.get('completed_vtxo_sha256')==sha(raw),
            'signed tree allocation identity/policy/amount differs')
        for name in ('leaf_spec_sha256','tree_native_vtxo_sha256'):hash_id(leaf.get(name))
        need(leaf.get('tree_completion_relation') in {'exact_full_equality','final_hark_leaf_completion'}
            and leaf.get('literal_native_vtxo_sha256')==sha(native_raw)
            and leaf.get('literal_native_completion_relation') in {'exact_full_equality','final_hark_leaf_completion'},
            'native structured completed leaf relation missing')
        terms.append((leaf['user_policy_hex'],leaf['amount_sat']));total+=leaf['amount_sat']
    need(Counter(terms)==allocation_terms(allocation) and type(proof.get('allocation_sat')) is int and proof['allocation_sat']==total,
        'ALL signed tree leaves differ from original allocation/amount sum')
    return {**evidence,'signed_tree_sha256':proof['signed_tree_sha256'],'anchor_raw_sha256':proof['anchor_raw_sha256'],
            'all_matching_leaf_indices':indexes,'completed_output_ids':sorted(outputs),'allocation_sat':total,
            'round_funding_txid':part['round_id'],'chain_anchor':proof['chain_anchor'],
            'participation_unlock_hash':part['unlock_hash'],
            'round_mining_cost_verified_here':False}


def pending_refresh_entitlement(action_id,input_ids,coins,tables,*,actor,committed_fee_sat,evidence_sha256,
                                decode_transaction,tree_proof_executor=None,tree_proof_pins=None):
    """Pending membership is a reference on the original obligation, not an edge.

    Caller authenticates original action/participation/fee/owner source. No
    original input is retired and no new principal or paid fee is credited.
    """
    inputs=ids(input_ids);hash_id(evidence_sha256)
    need(set(inputs)<=set(coins) and all(coins[x]['actor']==actor for x in inputs),'pending original owner missing')
    need(type(committed_fee_sat) is int and 0 <= committed_fee_sat <= MAX_SAT,'original pending fee term required')
    native={x['vtxo_id']:x for x in tables['vtxo']}
    need(len(native)==len(tables['vtxo']) and set(inputs)<=set(native),'pending original native inputs missing/duplicate')
    for ident in inputs:
        need(sha(original_hex(native[ident]['signed_vtxo_hex']))==coins[ident]['native_full_sha256'], 'pending input original differs')
    matches=[]
    for part in tables['round_participation']:
        rows=[x for x in tables['round_part_input']if x['participation_id']==part['id']]
        if {x['vtxo_id']for x in rows}==set(inputs):
            need(len(rows)==len(inputs),'duplicate pending participation input');matches.append(part)
    need(len(matches)==1,'unique original pending participation required')
    part=matches[0];allocation=[x for x in tables['round_part_output']if x['participation_id']==part['id']]
    expected=allocation_terms(allocation);gross=sum(coins[x]['amount_sat']for x in inputs)
    allocated=sum(a*n for (_,a),n in expected.items())
    need(gross==allocated+committed_fee_sat,'pending original allocation/fee does not conserve')
    rounds=[x for x in tables['round']if x['funding_txid']==part['round_id']]
    need(len(rounds)==1,'pending original signed round missing/ambiguous')
    servers={native[x]['server_pubkey']for x in inputs};need(len(servers)==1,'pending foreign input server')
    part={**part,'expected_server_pubkey':servers.pop()}
    request={'mode':'pending_entitlement',**tree_context(rounds[0],part,decode_transaction)}
    proof,evidence=execute_tree_proof(request,tree_proof_executor,tree_proof_pins)
    anchor=tree_response_context(proof,request,'pending_entitlement')
    need(anchor[0]==part['round_id'] and proof.get('pending_allocation_membership_verified') is True
        and 'allocations' not in proof and 'all_matching_leaves_verified' not in proof,'pending-only membership proof required')
    for key in ('signed_leaf_verified','current_spendability_verified','retirement_verified'):
        need(proof.get(key) is False,'pending proof escalated completion/retirement/availability')
    need(proof.get('original_sha256')=={'signed_tree':proof['signed_tree_sha256'],'anchor_raw':proof['anchor_raw_sha256']},'pending complete original hash set differs')
    leaves=proof.get('pending_allocations');indexes=proof_indices(proof,'all_matching_pending_leaf_indices',leaves)
    terms=[];seen=set()
    for leaf in leaves:
        ident=leaf.get('id');point(ident);need(ident not in seen,'duplicate pending allocation id');seen.add(ident)
        policy=leaf.get('user_policy_hex');need(isinstance(policy,str) and re.fullmatch('00[0-9a-f]{66}',policy),'pending ordinary policy missing')
        need(leaf.get('policy')=='pubkey' and leaf.get('user_pubkey')==policy[2:]
            and leaf.get('unlock_hash')==part['unlock_hash'] and leaf.get('chain_anchor')==proof['chain_anchor']
            and leaf.get('unsigned_path_verified') is True,'pending native contract differs')
        for key in ('signed_leaf_verified','current_spendability_verified','client_owner_verified','retirement_verified','payment_verified'):
            need(leaf.get(key) is False,'pending leaf escalated verdict')
        hash_id(leaf.get('tree_native_vtxo_sha256'));hash_id(leaf.get('leaf_spec_sha256'))
        path=leaf.get('derived_native_path');need(isinstance(path,list) and 0 < len(path) <= 256,'pending native path missing')
        for step in path:
            hash_id(step['txid']);hash_id(step['transaction_sha256'])
            need(type(step['output_index']) is int and 0 <= step['output_index'] < 2**32,'pending native path index invalid')
        need(path[-1]['txid']+':'+str(path[-1]['output_index'])==ident,'pending path terminal differs')
        terms.append((policy,amount(leaf['amount_sat'])))
    need(Counter(terms)==expected and type(proof.get('pending_entitlement_sat')) is int and proof['pending_entitlement_sat']==allocated,'ALL pending leaves differ from original allocation')
    return {'action_id':action_id,'kind':'pending_entitlement','preserved_obligation_input_ids':list(inputs),
        'pending_entitlement_ids':sorted(seen),'original_principal_sat':gross,'pending_allocation_sat':allocated,
        'original_committed_service_fee_sat':committed_fee_sat,'additional_principal_sat':0,'retired_claim_ids':[],
        'transfer_sat':0,'paid_sat':0,'owner_verified':False,'current_spendability_verified':False,
        'signed_leaf_verified':False,'evidence_sha256':evidence_sha256,'native_tree_originals':evidence,
        'all_matching_pending_leaf_indices':indexes,'proof_qualification_scope':tree_proof_pins['qualification_scope'],
        'scope':'Pending reference on existing obligation only; no completed edge, extra liability, fee payment, retirement or cash credit'}


def refresh_edge(action_id, input_ids, output_ids, coins, tables, *, actor,
                 committed_fee_sat, evidence_sha256, decode_transaction,
                 round_proof_executor=None, tree_proof_executor=None, tree_proof_pins=None):
    """Exact native participation joins; no retirement on forfeited_at alone.

    round_proof_executor must actually execute an admitted native
    original-forfeit verifier on the supplied private original packet. No such
    executor is claimed qualified by this proposal. Missing support is HOLD.
    Both callbacks use execute_tree_proof pinned-original transport contract;
    actual admission/execution remains the calling collector responsibility.
    """
    inputs, outputs = ids(input_ids), ids(output_ids)
    need(set(inputs+outputs) <= set(coins), 'signed refresh coin missing')
    need(type(committed_fee_sat) is int and 0 <= committed_fee_sat <= MAX_SAT, 'exact SDK fee required')
    need(all(coins[x]['actor'] == actor for x in inputs+outputs), 'refresh ownership changes')
    need(sum(coins[x]['amount_sat'] for x in inputs) == sum(coins[x]['amount_sat'] for x in outputs)+committed_fee_sat,
        'refresh signed amounts/fee do not conserve')
    requested = Counter((coins[x]['pubkey'], coins[x]['amount_sat']) for x in outputs)
    native = {x['vtxo_id']: x for x in tables['vtxo']}
    rounds = {x['funding_txid']: x for x in tables['round']}
    need(len(native) == len(tables['vtxo']) and len(rounds) == len(tables['round']), 'duplicate native round identity')
    matches = []
    for part in tables['round_participation']:
        rows = [x for x in tables['round_part_input'] if x['participation_id'] == part['id']]
        if {x['vtxo_id'] for x in rows} != set(inputs):
            continue
        need(len(rows) == len(inputs), 'duplicate native participation input')
        allocation = [x for x in tables['round_part_output'] if x['participation_id'] == part['id']]
        terms = []
        for row in allocation:
            policy = row['policy_hex']
            need(isinstance(policy,str) and re.fullmatch('00[0-9a-f]{66}',policy), 'nonordinary round output policy')
            terms.append((policy[2:], amount(row['amount'])))
        if Counter(terms) == requested:
            matches.append((part, rows, allocation))
    need(len(matches) == 1, 'unique exact native participation required')
    part, rows, allocation = matches[0]; funding = part['round_id']; round_row = rounds.get(funding)
    need(round_row is not None and part['forfeited_at'] is not None
        and part['unlock_preimage_present'] is True, 'incomplete/unforfeited participation remains held')
    hash_id(part['unlock_hash']); decoded = decode_transaction(round_row['funding_tx_hex'])
    need(decoded['txid'] == funding and all(point(coins[x]['chain_anchor'])[0] == funding for x in outputs),
        'round Full output anchor differs')
    need(all(coins[x].get('unlock_hash') == part['unlock_hash']
        and coins[x].get('native_policy_response_sha256') is not None for x in outputs),
        'authenticated Full leaf unlock hash/participation differs')
    need(set(inputs+outputs)<=set(native) and len({native[x]['server_pubkey']for x in inputs+outputs})==1,
        'refresh crosses native server identity')
    forfeits = []
    for row in rows:
        raw = row['signed_forfeit_tx_hex']
        need(isinstance(raw,str) and raw, 'original signed forfeit missing')
        tx = decode_transaction(raw); ident = row['vtxo_id']; current = native[ident]
        need([x['outpoint'] for x in tx['inputs']].count(ident) == 1
            and current['spent_in_round'] == round_row['id'] and current['oor_spent_txid'] == tx['txid']
            and current['spend_state'] == 'spent' and current['offboarded_in'] is None
            and current['onchain_spent_txid'] is None, 'round input/forfeit disposition differs')
        forfeits.append({'input_id': ident, 'signed_transaction_hex': raw})
    need(round_proof_executor is not None, 'admitted native original-forfeit proof unavailable')
    virtual = {x['txid']: x for x in tables['virtual_transaction']}
    need(len(virtual) == len(tables['virtual_transaction']), 'duplicate original forfeit anchor')
    proof_hashes = []
    for item in forfeits:
        ident = item['input_id']; row = native[ident]; anchor = virtual.get(point(coins[ident]['chain_anchor'])[0])
        need(anchor is not None and anchor['is_funding'] is True, 'forfeit original Full anchor missing')
        request = {'signed_vtxo':coins[ident].get('completed_vtxo_hex'),'native_vtxo':row['signed_vtxo_hex'],
            'anchor_raw':anchor['signed_transaction_hex'],
            'server_pubkey':row['server_pubkey'],'forfeit_raw':item['signed_transaction_hex'],
            'forfeit_unlock_hash':part['unlock_hash']}
        need(sha(original_hex(row['signed_vtxo_hex']))==coins[ident]['native_full_sha256']
            and sha(original_hex(request['signed_vtxo']))==coins[ident]['completed_full_sha256'],
            'original completed/native input differs from admitted owned proof')
        proof,execution = execute_tree_proof(request,round_proof_executor,tree_proof_pins)
        tx = decode_transaction(item['signed_transaction_hex'])
        need(proof.get('signed_path_valid') is True and proof.get('chain_contract_verified') is True
            and proof.get('forfeit_signature_valid') is True and proof.get('id') == ident
            and proof.get('native_vtxo_sha256') == coins[ident]['native_full_sha256']
            and proof.get('completed_vtxo_sha256') == coins[ident]['completed_full_sha256']
            and proof.get('native_completion_relation') == coins[ident]['native_completion_relation']
            and proof.get('native_owner_verified') is False and proof.get('payment_verified') is False
            and proof.get('chain_anchor')==coins[ident]['chain_anchor'] and proof.get('server_pubkey')==row['server_pubkey']
            and proof.get('policy')=='pubkey' and proof.get('amount_sat')==amount(coins[ident]['amount_sat'])
            and proof.get('candidate_user_pubkey')==coins[ident]['pubkey'] and proof.get('tree_padding') is False
            and proof.get('client_owner_verified') is False
            and proof.get('forfeit_input_coin_id') == ident and proof.get('forfeit_txid') == tx['txid']
            and proof.get('forfeit_unlock_hash') == part['unlock_hash']
            and proof.get('forfeit_raw_sha256') == sha(bytes.fromhex(item['signed_transaction_hex'])),
            'native original forfeit proof differs')
        proof_hashes.append({'input_id':ident,**execution})
    tree_evidence=completed_tree_allocation(round_row,part,outputs,coins,native,allocation,
        decode_transaction,tree_proof_executor,tree_proof_pins)
    return {'action_id': action_id, 'kind': 'refresh', 'inputs': inputs, 'outputs': outputs,
        'service_fee_sat': committed_fee_sat, 'evidence_sha256': hash_id(evidence_sha256),
        'native_forfeit_originals':proof_hashes,'participation_unlock_hash':part['unlock_hash'],
        'native_tree_originals':tree_evidence,'proof_qualification_scope':tree_proof_pins['qualification_scope']}


def edges_from_store(store, tables, coins, *, decode_transaction, round_proof_executor=None,
                     tree_proof_executor=None,tree_proof_pins=None):
    """Read actual existing Store/native schemas; no supplied transition flags.

    `coins` must be complete bind_coin results from admitted Full-mode execution.
    The caller separately proves source qualification/nonce and original Board
    funding/intent via the pending-Board/Board fee joins. No event is appended.
    """
    from simulator.final_campaign import _source_event
    from simulator.unknown_outcomes import _intent
    from simulator.fees import _proposal, movement_fee
    from simulator.model import canonical
    store.verify_event_chain()
    native = {row['vtxo_id']: row for row in tables['vtxo']}
    need(len(native) == len(tables['vtxo']), 'duplicate native coin')
    edges = []; originals = []
    def terminal(action):
        _intent(store, action)
        rows = store.db.execute("SELECT sequence FROM event WHERE kind='action_result' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.state')='completed'", (action['id'],)).fetchall()
        need(len(rows) == 1, 'unique original completed terminal required')
        _, event = _source_event(store, rows[0][0])
        need(canonical(event['result']) == action['result'], 'original terminal result changed')
        return event
    for action in store.db.execute("SELECT * FROM action WHERE state='completed' ORDER BY id"):
        operation = action['operation']
        if operation not in {'board','send_arkoor','refresh','refresh_delegated','refresh_scheduled'}:
            continue
        event = terminal(action); result = json.loads(action['result']); data = result.get('data',{})
        if operation == 'board':
            created = ids(data['board']['vtxos'])
            need(len(created) == 1 and created[0] in coins and coins[created[0]]['actor'] == action['actor_id'],
                'original Board ownership missing/ambiguous')
            originals.extend(created)
        elif operation == 'send_arkoor':
            proposal = _proposal(store,action,'arkoor_request'); inputs = ids(proposal['input_vtxo_ids']); args = json.loads(action['args'])
            need(proposal['destination'] == args['destination'] and proposal['amount_sat'] == args['amount_sat']
                and data.get('amount_sat') == args['amount_sat'] and data.get('submitted') == 'send_arkoor'
                and action['actual_fee_sat'] == 0, 'original Ark terms differ')
            credits = store.db.execute("SELECT sequence FROM event WHERE kind='ark_transfer_verified' AND json_extract(payload,'$.action_id')=?", (action['id'],)).fetchall()
            need(len(credits) == 1, 'one original authenticated Ark transfer required')
            _, credit = _source_event(store,credits[0][0]); recipient = credit['recipient_actor']
            need(credit['input_coin_ids'] == list(inputs) and credit['sender_actor'] == action['actor_id']
                and credit['amount_sat'] == args['amount_sat'] and credit['destination'] == args['destination']
                and (args.get('recipient_actor') is None or args['recipient_actor'] == recipient), 'Ark original credit differs')
            senders = [m for m in data.get('evidence',{}).get('movements',[]) if m.get('id') == credit['sender_movement_id']
                and m.get('subsystem') == 'bark.arkoor' and m.get('status') == 'successful'
                and sorted(m.get('input_vtxos',[])) == sorted(inputs) and m.get('offchain_fee_sat') == 0
                and m.get('effective_balance_sat') == -args['amount_sat']]
            need(len(senders) == 1, 'exact original sender movement missing')
            recipient_rows = store.db.execute('SELECT payload FROM movement_evidence WHERE actor=? AND movement_id=?', (recipient,credit['receipt_movement_id'])).fetchall()
            need(len(recipient_rows) == 1, 'original recipient movement missing')
            received = json.loads(recipient_rows[0][0]); receipts = ids([x['coin_id'] for x in credit['receipts']])
            need(received['subsystem'] == 'bark.arkoor' and received['status'] == 'successful'
                and received['input_vtxos'] == [] and set(ids(received['output_vtxos'])) == set(receipts)
                and received['effective_balance_sat'] == args['amount_sat'] and received['offchain_fee_sat'] == 0,
                'original receiver movement differs')
            change = senders[0].get('output_vtxos',[])
            need(isinstance(change,list) and len(change) == len(set(change)), 'duplicate sender change')
            outputs = list(change)+list(receipts)
            evidence = sha(canonical({'terminal':event,'proposal':proposal,'credit':credit,'sender':senders[0],'recipient':received}).encode())
            edges.append(arkoor_edge(action['id'],list(inputs),outputs,list(receipts),coins,native,
                sender=action['actor_id'],recipient=recipient,transfer_sat=args['amount_sat'],evidence_sha256=evidence))
        else:
            if data.get('no_inputs') is True:
                need(action['actual_fee_sat'] == 0, 'empty refresh changed its fee')
                continue
            fee = movement_fee(store,action)
            reconciled = store.db.execute("SELECT sequence FROM event WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?", (action['id'],)).fetchall()
            need(len(reconciled) == 1, 'original reconciled refresh charge required')
            _, original = _source_event(store,reconciled[0][0])
            need(all(original.get(k) == v for k,v in fee.items()) and action['actual_fee_sat'] == fee['actual_fee_sat'],
                'refresh fee original changed')
            evidence = sha(canonical({'terminal':event,'fee':fee,'original_fee_event':original}).encode())
            edges.append(refresh_edge(action['id'],fee['input_coin_ids'],fee['output_coin_ids'],coins,tables,
                actor=action['actor_id'],committed_fee_sat=fee['actual_fee_sat'],evidence_sha256=evidence,
                decode_transaction=decode_transaction,round_proof_executor=round_proof_executor,
                tree_proof_executor=tree_proof_executor,tree_proof_pins=tree_proof_pins))
    ids(originals); store.verify_event_chain()
    return originals, edges


def reduce_lineage(coins, original_ids, edges, *, native_source_sha256):
    """Conserve every original obligation through immediate authenticated edges.

    Inputs come ONLY from bind_coin + original-intent adapters above. This pure
    algebra cannot grant source admission. Multiple origins remain a joint group;
    no invented per-origin allocation or fee rebate is introduced.
    """
    hash_id(native_source_sha256); need(isinstance(coins,dict) and 0 < len(coins) <= MAX_COINS, 'bounded complete coin set required')
    origins = ids(original_ids); need(set(origins) <= set(coins), 'original obligation missing')
    for ident, coin in coins.items():
        need(coin['id'] == ident, 'detached coin identity'); point(ident); amount(coin['amount_sat'])
        for field in ('native_request_sha256','native_response_sha256','native_full_sha256'):
            hash_id(coin[field])
    need(isinstance(edges,list) and len(edges) <= MAX_COINS, 'bounded typed edge set required')
    producers = {}; consumers = {}; actions = set()
    for index, edge in enumerate(edges):
        need(edge['kind'] in {'arkoor','refresh'} and edge['action_id'] not in actions, 'unknown/duplicate action edge')
        actions.add(edge['action_id']); hash_id(edge['evidence_sha256']); inputs, outputs = ids(list(edge['inputs'])), ids(list(edge['outputs']))
        need(not set(inputs)&set(outputs) and set(inputs+outputs) <= set(coins), 'missing/self-referential coin edge')
        fee = edge['service_fee_sat']; need(type(fee) is int and 0 <= fee <= MAX_SAT and (edge['kind'] != 'arkoor' or fee == 0), 'typed exact service fee required')
        need(sum(coins[x]['amount_sat'] for x in inputs) == sum(coins[x]['amount_sat'] for x in outputs)+fee, 'typed edge does not conserve signed amount')
        for ident in inputs:
            need(ident not in consumers, 'input consumed by multiple operations'); consumers[ident] = index
        for ident in outputs:
            need(ident not in producers and ident not in origins, 'output double allocated/original rewritten'); producers[ident] = index
    need(set(origins)|set(producers) == set(coins), 'unattributed coin cannot become or disappear as a liability')
    groups = {ident: {'origins': {ident}, 'current': {ident}, 'fee_sat': 0, 'actions': set()} for ident in origins}
    group_of = {ident: ident for ident in origins}; available = set(origins)
    waiting = {}; remaining = []; ready = []
    for index, edge in enumerate(edges):
        unknown = [x for x in edge['inputs'] if x not in available]; remaining.append(len(unknown))
        for ident in unknown:
            waiting.setdefault(ident, []).append(index)
        if not unknown:
            heapq.heappush(ready,index)
    processed = 0
    while ready:
        index = heapq.heappop(ready); edge = edges[index]; inputs = set(edge['inputs']); outputs = set(edge['outputs'])
        need(inputs <= available, 'input reused in same frontier')
        merged = {group_of[x] for x in inputs}
        # Reuse the largest group; do not rescan every record per candidate.
        key = max(merged,key=lambda x:len(groups[x]['current'])+len(groups[x]['origins']))
        combined = groups[key]
        for other in merged-{key}:
            old = groups.pop(other); combined['origins'] |= old['origins']; combined['current'] |= old['current']
            combined['fee_sat'] += old['fee_sat']; combined['actions'] |= old['actions']
            for ident in old['current']:
                group_of[ident] = key
        combined['current'] -= inputs; combined['current'] |= outputs
        combined['fee_sat'] += edge['service_fee_sat']; combined['actions'].add(edge['action_id'])
        for ident in outputs:
            group_of[ident] = key
        available -= inputs; available |= outputs; processed += 1
        for ident in outputs:
            for next_index in waiting.get(ident,[]):
                remaining[next_index] -= 1
                if remaining[next_index] == 0:
                    heapq.heappush(ready,next_index)
    need(processed == len(edges), 'cyclic or missing original transition frontier')
    result = []
    for group in groups.values():
        gross = sum(coins[x]['amount_sat'] for x in group['origins']); current = sum(coins[x]['amount_sat'] for x in group['current'])
        need(gross == current+group['fee_sat'], 'original obligation conservation failed')
        result.append({'original_claim_ids': sorted(group['origins']), 'current_claim_ids': sorted(group['current']),
            'original_principal_sat': gross, 'current_principal_sat': current,
            'sdk_service_charge_sat': group['fee_sat'], 'action_ids': sorted(group['actions']),
            'per_origin_fee_allocation': None})
    need(set().union(*(set(x['current_claim_ids']) for x in result)) == available, 'current obligation frontier differs')
    return {'current_claim_ids': sorted(available), 'obligation_groups': sorted(result,key=lambda x:x['original_claim_ids']),
        'consumed_claim_ids': sorted(consumers), 'native_source_sha256': native_source_sha256,
        'scope': 'Authenticated immediate-edge liability algebra only; no payment, mining fee, backing, source readiness or epoch credit'}
