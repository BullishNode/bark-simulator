"""Read-only settlement checks against public ownership and independent chain.

Server rows identify candidates, never prove payment. Unknown backing, owner,
pre-commit arbitration or fee share remains pending. No original wallet calls.
"""
import asyncio,json,time
from .model import InvariantError,canonical,fee_allocation,integer
from .ownership import EvidenceGap,expiry_owner

SCHEMA='''
CREATE TABLE IF NOT EXISTS chain_payout(txid TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checked_settlement(coin_id TEXT PRIMARY KEY, txid TEXT NOT NULL, actor TEXT NOT NULL, script TEXT NOT NULL, amount_sat INTEGER NOT NULL, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settlement_check(txid TEXT PRIMARY KEY, state TEXT NOT NULL, reason TEXT, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS operator_script(script TEXT PRIMARY KEY, evidence TEXT NOT NULL);
'''
def initialize(store):store.db.executescript(SCHEMA)

def pre_state(row):
    values={r['spend_state'] for r in row.get('pre_commit_rows',[])}
    if len(values)==1:return values.pop()
    if not values and row.get('board_reserved') is True:return 'pending-board'
    raise EvidenceGap('pre-commit source missing or ambiguous')

def check_payment(store,rows,tx):
    if not rows or len({r['id'] for r in rows})!=len(rows):raise InvariantError('duplicated settlement coin')
    if tx.get('confirmations',0)<1:raise EvidenceGap('payout is not confirmed')
    if {r['txid'] for r in rows}!={tx['txid']}:raise InvariantError('settlement transaction mismatch')
    counts={integer(r.get('tx_settlement_count'),'transaction coin count',1) for r in rows}
    if len(counts)!=1 or counts.pop()!=len(rows):raise EvidenceGap('settlement transaction inventory is incomplete')
    fees={integer(r['fee_sat'],'recipient fee') for r in rows}
    if len(fees)!=1:raise InvariantError('inconsistent repeated settlement fee')
    fee=fees.pop();gross={};owners=[]
    for row in rows:
        state=pre_state(row);owner=expiry_owner(store,row['id'],state);script=row['spk']
        own=store.db.execute('SELECT 1 FROM owner_record WHERE actor=? AND mailbox=? AND script=?',(owner['actor'],owner['mailbox'],script)).fetchone()
        if own is None:
            competing=store.db.execute('SELECT 1 FROM owner_record WHERE script=? AND (actor!=? OR mailbox!=?)',
                (script,owner['actor'],owner['mailbox'])).fetchone()
            if competing is not None:raise InvariantError('payout script belongs to a competing verified owner record')
            raise EvidenceGap('historical payout destination record is not independently verified')
        h=row.get('htlc')
        if h:
            if h['direction']=='outgoing':
                if h.get('collection_recorded') is not True or h.get('subscription_settled') is not True:
                    raise EvidenceGap('receive collection is unproven')
            elif h['direction']=='incoming':
                if h.get('collection_recorded') or h.get('subscription_settled'):raise InvariantError('successful Lightning principal was refunded')
                # Terminal external evidence or expired internal claim must be
                # attached by the specific LN recipe, not inferred from no row.
                raise EvidenceGap('send terminal/deadline evidence not integrated')
            else:raise EvidenceGap('unknown HTLC direction')
        # Chain path proof is retained, but confirmed sweep ownership must also
        # be qualified separately. This checker must never claim it did that.
        old=store.db.execute('SELECT txid FROM checked_settlement WHERE coin_id=?',(row['id'],)).fetchone()
        if old and old['txid']!=tx['txid']:raise InvariantError('same entitlement has two payout transactions')
        gross[script]=gross.get(script,0)+owner['amount_sat'];owners.append((row,owner))
    shares=fee_allocation(gross,fee)
    for script,amount in gross.items():
        outputs=[o for o in tx['outputs'] if o['script']==script]
        if len(outputs)!=1 or outputs[0]['amount_sat']!=amount-shares[script]:raise InvariantError('wrong grouped net payout')
    other=[o for o in tx['outputs'] if o['script'] not in gross]
    if len(other)!=1:raise EvidenceGap('operator change has not been uniquely identified')
    if store.db.execute('SELECT 1 FROM operator_script WHERE script=?',(other[0]['script'],)).fetchone() is None:
        raise EvidenceGap('operator change ownership is unverified')
    if tx['fee_sat']<fee:raise InvariantError('recipient fees exceed actual mining fee')
    return {'owners':owners,'recipient_fee_sat':fee,'operator_fee_sat':tx['fee_sat']-fee,
        'validation_scope':'confirmed chain payment, signed owner bindings, pre-commit source and exact grouped amounts; sweep backing and seed recovery are separate gates'}

async def collect_settlements(store,chain,limit=2):
    initialize(store)
    pages=store.db.execute("SELECT payload FROM server_item WHERE kind='settlements'").fetchall()
    groups={}
    for r in pages:
        value=json.loads(r['payload']);groups.setdefault(value['txid'],[]).append(value)
    pending=[]
    for txid,rows in groups.items():
        old=store.db.execute('SELECT state FROM settlement_check WHERE txid=?',(txid,)).fetchone()
        if old is None or old['state']!='amounts_checked':pending.append((txid,rows))
    after=store.get_meta('settlement_cursor') or ''
    pending=sorted(pending,key=lambda item:item[0]);pending=[x for x in pending if x[0]>after]+[x for x in pending if x[0]<=after]
    for txid,rows in pending[:limit]:
        state='pending';reason=None
        try:
            await asyncio.to_thread(chain.identity)
            tx=await asyncio.to_thread(chain.transaction,txid)
            result=check_payment(store,rows,tx)
            with store.transaction():
                store.db.execute('INSERT OR REPLACE INTO chain_payout VALUES (?,?)',(txid,canonical(tx)))
                for row,owner in result['owners']:
                    store.db.execute('INSERT OR IGNORE INTO checked_settlement VALUES (?,?,?,?,?,?)',(row['id'],txid,owner['actor'],row['spk'],owner['amount_sat'],canonical({'row':row,'owner':owner})))
                store._event('confirmed_payout_amounts_checked',{'txid':txid,'coins':[r['id'] for r in rows],
                    'recipient_fee_sat':result['recipient_fee_sat'],'operator_fee_sat':result['operator_fee_sat'],'scope':result['validation_scope']})
            state='amounts_checked'
        except InvariantError:raise
        except EvidenceGap as e:reason=str(e)
        except Exception as e:reason=type(e).__name__
        store.db.execute('INSERT OR REPLACE INTO settlement_check VALUES (?,?,?,?)',(txid,state,reason,time.time()))
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('settlement_cursor',?)",(txid,))
