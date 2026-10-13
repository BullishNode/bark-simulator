"""Public deterministic traffic choices; no wallet randomness or funding."""
import hashlib,json,math,time
from contextlib import nullcontext
from .model import canonical,integer,public_payload


def _transaction(store):
    return nullcontext() if store.db.in_transaction else store.transaction()


def _value(seed,counter,purpose,inputs):
    message=canonical({'seed':seed,'counter':counter,'purpose':purpose,'inputs':inputs}).encode()
    return (int.from_bytes(hashlib.sha256(message).digest()[:8],'big')>>11)/(1<<53)


class Rng:
    def __init__(self,store,config):
        self.store=store
        self.seed=getattr(config,'campaign_seed','')
        if not isinstance(self.seed,str) or not 1<=len(self.seed)<=128:
            raise ValueError('declare a public campaign seed of 1–128 characters')
        public_payload(self.seed)
        self.settings={'algorithm':'sha256-counter-53bit-v1','seed':self.seed,
            'absence_hazard_per_day':getattr(config,'absence_hazard_per_day',0.005),
            'absent_payment_probability':getattr(config,'absent_payment_probability',0.05)}
        for name in ('absence_hazard_per_day','absent_payment_probability'):
            value=self.settings[name]
            if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=1:
                raise ValueError('realism probabilities must be finite values in [0,1]')
        with _transaction(store):
            previous=store.get_meta('campaign_realism')
            if previous is not None:
                if previous!=canonical(self.settings) or store.get_meta('campaign_seed')!=self.seed:
                    raise ValueError('campaign seed and realism rates are immutable')
                integer(int(store.get_meta('campaign_rng_counter')),'campaign random counter')
            else:
                if store.get_meta('campaign_seed') is not None:raise ValueError('incomplete campaign randomness metadata')
                for key,value in [('campaign_realism',canonical(self.settings)),('campaign_seed',self.seed),
                        ('campaign_rng_counter','0'),('realism_started_at',str(time.time()))]:
                    store.db.execute('INSERT INTO meta VALUES (?,?)',(key,value))
                seen={}
                for row in store.db.execute('SELECT actor,movement_id FROM movement_evidence ORDER BY actor,movement_id'):
                    seen.setdefault(row['actor'],[]).append(row['movement_id'])
                store.db.execute("INSERT INTO meta VALUES ('random_absence_seen_movements',?)",(canonical(seen),))
                store._event('campaign_randomness_declared',self.settings)

    @classmethod
    def configured(cls,store,config):
        if getattr(config,'campaign_seed',''):return cls(store,config)
        if store.get_meta('campaign_seed') is not None:
            raise ValueError('an enabled seeded campaign cannot silently disable randomness')
        return None

    def draw(self,purpose,inputs):
        public_payload(inputs)
        with _transaction(self.store):
            if self.store.get_meta('campaign_realism')!=canonical(self.settings) or self.store.get_meta('campaign_seed')!=self.seed:
                raise ValueError('campaign realism metadata changed')
            counter=int(self.store.get_meta('campaign_rng_counter'))+1
            integer(counter,'campaign random counter',1)
            value=_value(self.seed,counter,purpose,inputs)
            self.store.db.execute("UPDATE meta SET value=? WHERE key='campaign_rng_counter'",(str(counter),))
            self.store._event('random_draw',{'purpose':purpose,'inputs':inputs,'value':value,'counter':counter})
        return value

    @staticmethod
    def replay(seed,draws):
        count=0
        for counter,draw in enumerate(draws,1):
            count=counter
            if (draw['counter']!=counter or draw['value']!=_value(seed,counter,draw['purpose'],draw['inputs'])):
                raise ValueError('random draw journal does not match its declared seed/counter')
        return count

    def due(self,actor,rule,interval,anchor,now):
        """Freeze one jittered deadline per actor/rule/completed anchor."""
        with _transaction(self.store):
            cadences=json.loads(self.store.get_meta('realism_cadences') or '{}')
            key=actor+'/'+rule;previous=cadences.get(key)
            if previous is None or previous['anchor']!=anchor:
                value=self.draw('interval',{'actor':actor,'rule':rule,'interval_seconds':interval,'anchor':anchor})
                previous={'anchor':anchor,'deadline':anchor+interval*(0.5+value)}
                cadences[key]=previous
                self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('realism_cadences',?)",(canonical(cadences),))
        return now>previous['deadline']

    def amount(self,actor,balance,reserve):
        affordable=integer(balance,'spendable balance')-integer(reserve,'payment reserve')
        if affordable<1:return None
        choices=[min(amount,affordable) for amount in [300,900,900,1000,1000,1500,1500,3000,affordable]]
        value=self.draw('payment_amount',{'actor':actor,'balance_sat':balance,'reserve_sat':reserve,'choices_sat':choices})
        return choices[int(value*len(choices))]

    def recipient(self,actor,peers):
        peers=sorted(set(peers)-{actor})
        absent=[p for p in peers if p in {'actor-09','actor-10'}]
        ordinary=[p for p in peers if p not in {'actor-09','actor-10'}]
        if not peers:return None
        use_absent=self.draw('absent_payment',{'actor':actor,'absent_peers':absent,
            'other_peers':ordinary,'probability':self.settings['absent_payment_probability']})<self.settings['absent_payment_probability']
        pool=absent if use_absent else ordinary
        # Never increase absent-payment probability just because ordinary peers
        # are missing. A deliberately selected absent group must be advertised.
        if not pool:return None
        return pool[int(self.draw('payment_recipient',{'actor':actor,'peers':pool})*len(pool))]


def ordinary(actor,detail):
    if detail.get('permanent_absence'):return False
    try:profile=(int(actor.rsplit('-',1)[1])-1)%12+1
    except (ValueError,IndexError):return False
    return profile not in {3,4,6,9,10,11,12}


def hazard(store,config,rng,receive_boundary,lightning_candidates):
    """Accumulate ordinary disappearance intent; stop only at a named boundary."""
    if rng is None:return
    with _transaction(store):
        _hazard(store,config,rng,receive_boundary,lightning_candidates)


def _hazard(store,config,rng,receive_boundary,lightning_candidates):
    now=time.time();interval=integer(getattr(config,'interval_seconds',30),'hazard interval',1)
    state=json.loads(store.get_meta('realism_hazards') or '{}')
    for actor in store.db.execute('SELECT id,details FROM actor WHERE online=1 ORDER BY id').fetchall():
        name=actor['id'];detail=json.loads(actor['details'])
        if store.actor_namespace(name)!='ordinary' or store.actor_held(name):continue
        if not ordinary(name,detail):continue
        previous=state.get(name,{})
        if not previous.get('pending'):
            if now-previous.get('last_tick',0)<interval:continue
            probability=rng.settings['absence_hazard_per_day']*interval/86400
            value=rng.draw('ordinary_absence',{'actor':name,'interval_seconds':interval,'probability':probability})
            previous={'last_tick':now,'pending':value<probability,'draw_counter':int(store.get_meta('campaign_rng_counter'))}
            state[name]=previous
        if not previous.get('pending'):continue
        if store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(name,)).fetchone():continue
        candidates=lightning_candidates(store)
        if name in {a for a,_ in candidates} and len(candidates)<=2:continue
        context={'hazard_draw_counter':previous['draw_counter'],'hazard_per_day':rng.settings['absence_hazard_per_day']}
        if any(receive_boundary(store,name,rail,random_context=context) for rail in ('ark','lightning')):
            previous['pending']=False;continue
        latest=store.db.execute("SELECT * FROM action WHERE actor_id=? AND state='completed' AND operation NOT IN ('snapshot','sync','address','create') ORDER BY updated_at DESC,id DESC LIMIT 1",(name,)).fetchone()
        if (not latest or latest['operation'] not in {'refresh_delegated','invoice'}
                or latest['updated_at']<float(store.get_meta('realism_started_at'))):continue
        ids=[]
        for coin_id in detail.get('coin_ids',[]):
            if store.db.execute('SELECT 1 FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=? AND k.actor=?',(coin_id,name)).fetchone():ids.append(coin_id)
        profile={'rail':latest['operation'],'coin_ids':ids,'boundary_action_id':latest['id'],
            'armed_at':now,'original_wallet_must_stay_closed':True,'trigger':'completed '+latest['operation'],
            'payout_verdict':'pending',**context}
        with _transaction(store):
            detail['permanent_absence']=profile
            store.db.execute('UPDATE actor SET online=0,details=? WHERE id=?',(canonical(detail),name))
            store._event('random_absence_armed',{'actor':name,**profile,'scenario_verdict':'not_qualified',
                'no_client_calls_after_boundary':True})
        previous['pending']=False
    with _transaction(store):
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('realism_hazards',?)",(canonical(state),))
