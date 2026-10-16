from __future__ import annotations

import asyncio
import fcntl
import json
import time
from pathlib import Path

from .config import Config
from .model import public_payload, timestamp
from .observations import observe
from .process import json_command, public_command_capture
from .report import generate
from .store import Store
from .log_capture import configured_sources as configured_log_sources,collect_sources as collect_logs
from .padding import collect as collect_padding, collect_backing as collect_padding_backing, capture_snapshot as capture_padding_snapshot
from .ownership import record_candidates, record_verified, retry_public_candidates, verify_client_evidence, record_server_page
from .model import InvariantError,canonical
from .chain import ChainReader
from .direct_settlements import collect as collect_direct_settlements
from .settlements import collect_settlements as collect_two_step_settlements
from .architecture import profile as campaign_profile, validate as validate_profile, TWO_STEP, DIRECT
from .campaign import CampaignClock,RampPlan,traffic_ready,collect_ark_receipts
from .continuous import schedule as schedule_continuous
from .funding import fund,WalletRpc
from .topology import ready as lightning_ready
from .fees import collect as collect_fees
from .recycling import collect as collect_recycling
from .renewal import collect as collect_renewal
from .workload import record_actor_result, schedule_pilot
from .raw_cases import RAW_CASES
from .negative_checks import collect as collect_negative_checks
from .raw_protocol import collect as collect_protocol_checks
from .phase_trials import Controller as PhaseController
from .payments import collect as collect_payments
from .proof_import import collect as collect_public_proofs
from .recovery import RecoveryController
from .entitlements import record_submitted as record_delegated, collect as collect_delegated
from .operator_scripts import collect as collect_operator_scripts
from .unknown_outcomes import collect as collect_unknown
from .exits import collect as collect_exits
from . import identity_bootstrap

OPERATIONS = {"create", "snapshot", "sync", "address", "board", "send_arkoor", "refresh",
              "refresh_delegated", "refresh_scheduled", "fallback_record_check", "exit", "offboard_all", "invoice", "pay_invoice"} | set(RAW_CASES) | {"phase_execute_d17","phase_register_saved"}


def catalog(profile=None):
    validate_profile(profile)
    cases = json.loads(Path(__file__).with_name("scenarios.json").read_text())
    if profile is not None:
        contracts = json.loads(Path(__file__).with_name("scenario_profiles.json").read_text())
        for case in cases:
            if case['id'] in contracts['cases']:
                contract = contracts['cases'][case['id']]
                selected = contract['profiles'][profile]
                case.update(behavior=selected['behavior'], expected=selected['expected'])
                case['profile_contract'] = {**selected, 'profile':profile,
                    'risk':contract['risk'], 'version':contracts['version'],
                    'scope':contracts['scope']}
    return cases


def initialize(store: Store):
    selected = campaign_profile(store)
    store.register_catalog(catalog(selected if store.get_meta('architecture_profile') else None),
                           set(RAW_CASES.values()))
    roles = ["daily wallet", "spender", "merchant", "saver", "Lightning sender", "Lightning recipient",
             "intermittent phone", "delegated wallet", "absent wallet A", "absent wallet B",
             "adversarial A", "adversarial B"]
    for index, role in enumerate(roles, 1):
        store.actor(f"actor-{index:02}", role)


class Engine:
    def __init__(self, config: Config, store: Store, *, financial_source_collector=None):
        self.config, self.store = config, store
        self.financial_source_collector = financial_source_collector
        selected=campaign_profile(store)
        declared=getattr(config,'architecture_profile',None)
        if (selected!=(declared or DIRECT)
                or bool(store.get_meta('architecture_profile'))!=(declared is not None)):
            raise ValueError('configured architecture differs from original campaign profile')
        if declared is not None:
            if store.get_meta('final_financial_epoch') is not None:
                from .final_campaign import epoch
                if epoch(store)['pins']['sdk_commit']!=config.expected_sdk_commit:
                    raise ValueError('configured SDK differs from immutable final financial epoch')
            # This is a requirement marker, never a readiness proof. Both routes
            # retain the exact same complete financial preflight before dispatch.
            store.db.execute("INSERT OR IGNORE INTO meta VALUES ('financial_qualification_required','true')")
        if self._requires_financial_qualification():
            from .normal_financial import KEY
            store.db.execute('INSERT OR IGNORE INTO meta VALUES (?,?)', (KEY, 'true'))
        self.phases=PhaseController(store,config)
        if config.trace_enabled:
            store.attach_trace(config.trace_retention_days)
            # Verify and open retained trace history before any subprocess timeout.
            store.trace_capture('supervisor.start',{})
        ramp=RampPlan()
        if store.get_meta('fixture_funding_plan') is not None:
            from .funding import plan
            declared=plan(store)
            ramp=RampPlan(initial_clients=declared['initial_clients'],added_clients=declared['ramp_clients'],
                          funding_per_added_client_sat=declared['grant_sat'])
        self.campaign_clock=CampaignClock(store,ramp) if config.workload=="continuous" else None
        self.recovery=RecoveryController(store,config) if config.recovery_command else None

    def _requires_financial_qualification(self):
        return (getattr(self.config,'architecture_profile',None) is not None
                or self.store.get_meta('final_financial_epoch') is not None
                or self.store.get_meta('financial_qualification_required') is not None)

    async def collect_settlement_evidence(self,chain):
        if campaign_profile(self.store)==TWO_STEP:
            await collect_two_step_settlements(self.store,chain)
        else:
            await collect_direct_settlements(self.store,self.config,chain)

    async def refresh_financial_sources(self):
        """Observe before admission; partial facts never replace full preflight."""
        if not self._requires_financial_qualification():return True
        from . import exploratory
        if exploratory.scope(self.store) is not None:
            # Its independent source proof was collected in observe(), before
            # persisting this snapshot. Partial/global sources stay separate.
            return True
        latest = self.store.db.execute('SELECT payload FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()
        if latest and self.financial_source_collector is not None:
            try:
                from .normal_financial import validate_collection
                validate_collection(self.store, json.loads(latest['payload']))
                return True
            except ValueError:
                pass  # Partial capture below is diagnostic; it cannot admit.
        try:
            last=float(self.store.get_meta('financial_partial_observed_at') or '0')
            if 0<=time.time()-last<60:return True
            if len(self.config.proof_command)!=4:
                raise ValueError('independent Core observer unavailable')
            chain=ChainReader(self.config.proof_command[1],self.config.proof_command[2],
                self.config.expected_genesis,capture=self.store.trace_sample,consumer='financial-readiness')
            from .financial_observer import collect_partial
            result=await collect_partial(self.store,self.config,chain)
            if result.get('independent_same_tip') is not True:
                raise ValueError('financial source and independent chain disagree')
            self.store.db.execute("INSERT OR REPLACE INTO meta VALUES('financial_partial_observed_at',?)",(str(time.time()),))
            return True
        except Exception as error:
            self.store.event('financial_source_gap',{'reason':type(error).__name__,'qualified':False})
            return False

    def raw_capture(self, kind, *, actor=None, action_id=None, context=None):
        def capture(record):
            raw=record['raw'];payload={key:value for key,value in record.items() if key!='raw'}
            self.store.trace_capture(kind,{**payload,**(context or {})},actor=actor,action_id=action_id,raw=raw)
        return capture

    async def observe(self):
        def progress(event):
            if event.get('event')!='observer_trace':raise ValueError('unknown observer progress frame')
            self.store.trace_sample(event['data'])
        snapshot = await json_command(list(self.config.observer_command), timeout=30,on_event=progress,
            on_stdout_raw=self.raw_capture('observer.sample.raw',context={'method':'observer-command'}),
            on_stderr_raw=self.raw_capture('observer.stderr'))
        for sample in snapshot.pop('trace_samples',[]):self.store.trace_sample(sample)
        self.config.validate_identity(snapshot)
        self.store.bind_target(snapshot["identity"])
        from . import exploratory
        if exploratory.scope(self.store) is not None:
            if len(self.config.proof_command)!=4:raise ValueError('independent Core required for exploratory source validation')
            chain=ChainReader(self.config.proof_command[1],self.config.proof_command[2],self.config.expected_genesis,
                capture=self.store.trace_sample,consumer='exploratory-operating-readiness')
            snapshot=await exploratory.collect(self.store,self.config,chain,snapshot)
        elif self._requires_financial_qualification():
            # An observer cannot inject or recycle a historical readiness ID.
            snapshot.pop('operating_readiness_sequence', None)
            snapshot.pop('financial_collection_sequence', None)
            from .operating_limits import KEY as envelope_key
            if self.store.get_meta(envelope_key) is not None and not identity_bootstrap.pending(self.store):
                try:
                    if len(self.config.proof_command)!=4:
                        raise ValueError('independent Core required for normal source verification')
                    chain=ChainReader(self.config.proof_command[1],self.config.proof_command[2],
                        self.config.expected_genesis,capture=self.store.trace_sample,consumer='normal-operating-readiness')
                    from .normal_financial import collect
                    snapshot=await collect(self.store,self.config,chain,snapshot,self.financial_source_collector)
                except Exception as error:
                    self.store.event('normal_financial_source_gap', {'reason':type(error).__name__, 'qualified':False})
        self.store.add_snapshot(snapshot)
        for item in snapshot.get("rounds_owned_scripts",[]):
            self.store.db.execute("INSERT OR IGNORE INTO operator_script VALUES (?,?)",(item["script"],canonical(item)))
        return snapshot

    def ready_for_actions(self, snapshot):
        age = time.time() - timestamp(snapshot["observed_at"], "snapshot time")
        healthy = (0 <= age <= 90 and snapshot.get("stable_tip") is True
                   and snapshot.get("initial_block_download") is False
                   and snapshot.get("server_status", {}).get("status") == "running")
        if not healthy:
            return False
        if self._requires_financial_qualification():
            try:
                if identity_bootstrap.pending(self.store):
                    return identity_bootstrap.eligible(self.store,self.config,snapshot)
            except (ValueError,OSError,KeyError):
                return False
            from .operating_limits import envelope,preflight
            try:
                # A scoped canary carries its own independently checked bounds;
                # it cannot supply or consume a normal financial envelope.
                from . import exploratory
                if exploratory.scope(self.store) is not None:
                    return preflight(self.store,self.config,snapshot,operation='progression')['allowed']
                # Sync/claim progression can continue under its own explicit limits
                # while an ordinary fee spike holds new financial actions.
                declaration=envelope(self.store,self.config)
                scope=declaration.get('operation_fee_paths')
                operations=('progression',) if scope is None else tuple(
                    operation for operation in dict.fromkeys(('ordinary','claim','progression',*scope))
                    if operation in scope and operation in OPERATIONS|{'ordinary','claim','progression'})
                for operation in operations:
                    try:
                        if preflight(self.store,self.config,snapshot,operation=operation)['allowed']:
                            return True
                    except ValueError:
                        continue
                return False
            except ValueError:
                return False
        return True

    async def noah_action(self,adapter,actor,identifier,operation,args,maximum_fee_sat):
        """Explicit Noah jobs use the existing queue, native driver and fee holds.

        Raw native frames remain protected. Only invoice creation can complete
        here; payment/claim ACKs retain their original independent-proof hold.
        """
        import base64,hashlib
        from .noah import _actor,_hex
        from .model import integer
        adapter._ready();_actor(actor)
        if not self.config.active or self.store.get_meta('mode')!='live' or self.store.actor_namespace(actor)!='noah':
            raise ValueError('explicit active Noah actor required')
        if adapter.store is not self.store or operation not in {'invoice','claim_lightning','pay_invoice'}:
            raise ValueError('Noah job context differs')
        if operation=='pay_invoice':
            frozen=adapter.payment_request(identifier,_dispatched=True)
            if frozen['actor']!=actor or frozen['args']!=args or frozen['maximum_fee_sat']!=maximum_fee_sat:
                raise ValueError('native payment differs from frozen intended invoice')
        else:adapter._phone(actor,require_online=True)
        integer(maximum_fee_sat,'Noah fee reservation',1)
        if maximum_fee_sat>adapter.manifest['capital']['per_action_fee_sat']:
            raise ValueError('Noah native fee exceeds declared cap')
        if operation=='claim_lightning':_hex(args.get('receive_payment_hash'))
        command=Path(self.config.driver_command[0])
        if command.is_symlink() or hashlib.sha256(command.read_bytes()).hexdigest()!=adapter.manifest['source'].get('driver_binary_sha256'):
            raise ValueError('qualified native driver differs')
        if self.config.expected_server_pubkey!=adapter.manifest['chain']['server_pubkey']:
            raise ValueError('native server differs from Noah declaration')
        wallet=self.config.wallet_root/actor
        if not wallet.is_dir() or any(p.is_symlink() for p in (wallet,*wallet.parents)):
            raise ValueError('declared native wallet is missing or aliased')
        latest=self.store.db.execute('SELECT payload FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()
        snapshot=json.loads(latest[0]) if latest else {}
        if not latest or not self.ready_for_actions(snapshot):raise ValueError('fresh healthy target observation required')
        self.config.validate_identity(snapshot)
        if operation in {'invoice','pay_invoice'}:
            from .pool_readiness import ready as pool_ready
            pool=await json_command(list(self.config.inventory_command),{'kind':'pool_status'},timeout=15,
                **public_command_capture(self.store,'pool.status',{'kind':'pool_status'},action_id=identifier))
            if not pool_ready({**snapshot,'pool_status':pool},args.get('amount_sat',0)):
                raise ValueError('confirmed usable pool is not proven')
        if self._requires_financial_qualification():
            from .operating_limits import preflight
            decision=preflight(self.store,self.config,snapshot,
                operation='claim' if operation=='claim_lightning' else operation,
                amount_sat=args.get('amount_sat',0),maximum_fee_sat=maximum_fee_sat)
            if not decision['allowed']:raise ValueError(decision['reason'])
        old=self.store.db.execute('SELECT state FROM action WHERE id=?',(identifier,)).fetchone()
        if old:raise ValueError('native job already attempted; reconcile original action')
        request={'actor_dir':str(wallet),'operation':operation,'action_id':identifier,'args':args,
            'expected_server_pubkey':self.config.expected_server_pubkey,'maximum_fee_sat':maximum_fee_sat}
        self.store.bind_wallet_root(self.config.wallet_root)
        self.store.db.execute("INSERT OR IGNORE INTO scenario VALUES ('NOAH_NATIVE','Captured Noah native job; independent journey proof required',0)")
        protected=adapter.protect('native.request',request,actor=actor,action_id=identifier)
        self.store.queue(identifier,actor,'NOAH_NATIVE',operation,{'private_request':protected},maximum_fee_sat,namespace='noah')
        action=self.store.claim({operation},namespace='noah',action_id=identifier)
        if action is None:raise ValueError('Noah native action ownership unavailable')
        def raw(stream):
            def capture(row):adapter.protect('native.'+stream,{**{k:v for k,v in row.items() if k!='raw'},
                'body_base64':base64.b64encode(row['raw']).decode()},actor=actor,action_id=identifier)
            return capture
        def progress(frame):
            if frame.get('action_id')!=identifier:raise ValueError('native event identity differs')
            adapter.protect('native.event',frame,actor=actor,action_id=identifier)
        try:
            response=await json_command(list(self.config.driver_command),request,timeout=self.config.action_timeout_seconds,
                on_event=progress,on_stdout_raw=raw('stdout'),on_stderr_raw=raw('stderr'))
            proof=adapter.protect('native.response',response,actor=actor,action_id=identifier)
            if response.get('action_id')!=identifier or response.get('status')!='ok' or not isinstance(response.get('data'),dict):
                raise ValueError('native job unresolved')
            data=response['data']
            if operation=='invoice' and (not isinstance(data.get('invoice'),str) or not data['invoice']):
                raise ValueError('native invoice missing')
            if operation in {'invoice','pay_invoice'}:_hex(data.get('payment_hash'))
            completed=operation=='invoice' and type(response.get('actual_fee_sat')) is int and response['actual_fee_sat']==0
            self.store.finish(identifier,'completed' if completed else 'outcome_unknown',{'native_artifact':proof},0 if completed else None)
            return data
        except BaseException as error:
            adapter.protect('native.error',{'error_type':type(error).__name__},actor=actor,action_id=identifier)
            self.store.finish(identifier,'outcome_unknown',{'reason':'native job needs original independent reconciliation'})
            raise

    async def dispatch_batch(self):
        """Claim distinct actors before launching concurrent client operations."""
        if not self.config.active:return False
        self.store.bind_wallet_root(self.config.wallet_root)
        actions=[]
        count=1 if identity_bootstrap.pending(self.store) else self.config.dispatch_per_tick
        for _ in range(count):
            action=self.store.claim(OPERATIONS)
            if action is None:break
            actions.append(action)
        if not actions:return False
        await asyncio.gather(*(self.dispatch_one(action) for action in actions))
        return True

    async def dispatch_one(self, action=None):
        if not self.config.active:
            return False
        self.store.bind_wallet_root(self.config.wallet_root)
        action = action if action is not None else self.store.claim(OPERATIONS)
        if action is None:
            return False
        if not self.store.ordinary_actor_available(action['actor_id'],native_action=action['id']):
            self.store.finish(action['id'],'blocked',{'reason':'actor belongs to a private namespace or active controller; no native call'},0)
            return True
        if action['args'].get('purpose')=='replenish_lightning_payer':
            target=action['args'].get('recipient_actor')
            if (not isinstance(target,str) or not self.store.online(target)
                    or not self.store.ordinary_actor_available(target)):
                self.store.finish(action['id'],'blocked',{'reason':'liquidity recipient became unavailable before native call'},0)
                return True
        if action['actor_id'] in {'actor-03','actor-09','actor-10'} and (action['operation'].startswith(('raw_protocol_','phase_execute_')) or action['operation'] in {'fallback_record_check','phase_register_saved'}):
            self.store.finish(action['id'],'blocked',{'reason':'original absent wallet must remain closed; no native call'},0)
            return True
        if action['operation'].startswith('phase_') and (not getattr(self.config,'phase_enabled',False) or not getattr(self.config,'phase_manifest_sha256',None) or action['args'].get('qualification_manifest_sha256')!=self.config.phase_manifest_sha256):
            self.store.finish(action['id'],'blocked',{'reason':'compiled phase package has not been explicitly qualified for this invocation; no native call'},0)
            return True
        actor_dir = self.config.wallet_root / action["actor_id"]
        if actor_dir.parent.resolve() != self.config.wallet_root or actor_dir.is_symlink():
            self.store.finish(action["id"], "failed", {"reason": "unsafe actor directory"})
            return True
        request = {
                "actor_dir": str(actor_dir), "operation": action["operation"],
                "action_id": action["id"], "args": action["args"],
                "expected_server_pubkey": self.config.expected_server_pubkey,
                "maximum_fee_sat": action["fee_reservation_sat"],
            }
        latest = self.store.db.execute("SELECT id,payload FROM snapshot ORDER BY id DESC LIMIT 1").fetchone()
        snapshot = json.loads(latest["payload"]) if latest else {}
        financial_declaration=None
        bootstrap_action=False
        if self._requires_financial_qualification():
            from .operating_limits import envelope
            from . import exploratory
            try:
                if identity_bootstrap.pending(self.store):
                    bootstrap_action=identity_bootstrap.eligible(self.store,self.config,snapshot,action)
                elif exploratory.scope(self.store) is None:
                    financial_declaration=envelope(self.store,self.config)
                    scope=financial_declaration.get('operation_fee_paths')
                    if scope is not None and action['operation'] not in scope:
                        raise ValueError('operation not declared in immutable fee path scope')
            except (ValueError,OSError,KeyError) as error:
                self.store.finish(action['id'],'blocked',{'reason':str(error),'scope':'financial preflight; no native call'},0)
                return True
        if action['operation']=='pay_invoice':
            recipient=action['args'].get('recipient_actor')
            if recipient and (not self.store.online(recipient)
                    or not self.store.ordinary_actor_available(recipient)
                    or self.store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND state IN ('queued','dispatched','outcome_unknown')",(recipient,)).fetchone()):
                self.store.finish(action['id'],'blocked',{'reason':'receiver cannot drive frozen hash; no payer call'},0)
                return True
            from .pool_readiness import ready as pool_ready
            try:
                pool=await json_command(list(self.config.inventory_command),{'kind':'pool_status'},timeout=15,
                    **public_command_capture(self.store,'pool.status',{'kind':'pool_status'},action_id=action['id']))
                snapshot={**snapshot,'pool_status':pool}
            except Exception as error:
                self.store.finish(action['id'],'blocked',{'reason':'positive pool observation unavailable','error_type':type(error).__name__},0)
                return True
            if not pool_ready(snapshot,action['args'].get('amount_sat',0)):
                self.store.finish(action['id'],'blocked',{'reason':'confirmed usable pool is not proven','pool_status':pool},0)
                return True
        if self._requires_financial_qualification() and not bootstrap_action:
            from .operating_limits import preflight
            try:
                scoped=financial_declaration is not None and 'operation_fee_paths' in financial_declaration
                operation = 'progression' if action['operation']=='sync' and not scoped else action['operation']
                decision=preflight(self.store,self.config,snapshot,operation=operation,
                    amount_sat=action['args'].get('amount_sat',0),maximum_fee_sat=action['fee_reservation_sat'],
                    reserved_action_id=action['id'])
                if not decision['allowed']:
                    raise ValueError(decision['reason'])
            except ValueError as error:
                self.store.finish(action['id'],'blocked',{'reason':str(error),'scope':'financial preflight; no native call'},0)
                return True
        context = {"snapshot_id":latest["id"] if latest else None, "height":snapshot.get("height"),
                   "tip_hash":snapshot.get("tip_hash"), "mode":self.store.get_meta("mode")}
        if bootstrap_action:
            try:
                identity_bootstrap.begin(self.store,self.config,snapshot,action)
            except (ValueError,OSError,KeyError) as error:
                self.store.finish(action['id'],'blocked',{'reason':str(error),'scope':'zero-principal bootstrap; no native call'},0)
                return True
        self.store.trace_capture('driver.call',{'phase':'request','request':request,'context':context},
            actor=action['actor_id'],action_id=action['id'],raw=canonical(request).encode())
        self.store.event("driver_request", {"action_id": action["id"], "request": request, "context":context})
        queued_for_ms=max(0,round((time.time()-action["created_at"])*1000))
        started = time.monotonic()

        boundary_frames=[]
        receiver_tasks=[]

        def progress(event):
            if event.get("action_id") != action["id"]:
                raise ValueError("driver evidence action mismatch")
            if event.get('event') in {'client_evidence_before','client_evidence_after'} and event.get('data',{}).get('fresh') is True:
                boundary_frames.append(event['data']['evidence'])
            trace_ref=self.store.trace_capture('driver.event',{**event,'context':context},actor=action['actor_id'],action_id=action['id'])
            if trace_ref is not None and event.get('event') in {'client_evidence_before','client_evidence_after'}:
                event={**event,'data':{'fresh':event.get('data',{}).get('fresh'),'trace_ref':trace_ref}}
            self.store.event("driver_evidence", {**event,"context":context})
            kind=event.get('event');data=event.get('data',{});trial=action['args'].get('trial_id')
            if kind=='lightning_proposal' and action['operation']=='pay_invoice':
                from .receive_sync import queue_payment_receiver
                receiver=queue_payment_receiver(self.store,self.config,action,data['payment_hash'])
                if receiver:receiver_tasks.append(asyncio.create_task(self.dispatch_one(receiver)))
            if trial:
                if kind=='phase_preparations_frozen':self.phases.native_prepared(trial,action['id'],data)
                elif kind=='phase_delayed_registration_frozen':self.phases.delivery_prepared(trial,action['id'],data)
                elif kind=='phase_coin_reconciliation':self.phases.reconcile_coin(trial,action['id'],data['observation'])
                elif kind=='phase_reply_observed':self.phases.reply(trial,data['leg_id'],data['reply'])


        def driver_stderr(log):
            try:
                public_payload(log)
            except ValueError:
                log={"redacted":True,"bytes":log["bytes"],"truncated":log["truncated"]}
            from .round_adoption import diagnose_stderr,record_sync_diagnostic
            record_sync_diagnostic(self.store,action['id'],diagnose_stderr(log.get('text',''),
                redacted=bool(log.get('redacted')),truncated=bool(log.get('truncated'))))
            self.store.event("driver_stderr",{'action_id':action['id'],
                'bytes':log['bytes'],'truncated':log['truncated'],'redacted':bool(log.get('redacted'))})

        try:
            response = await json_command(list(self.config.driver_command), request,
                timeout=self.config.action_timeout_seconds, on_event=progress,on_stderr=driver_stderr,
                on_stdout_raw=self.raw_capture('driver.stdout',actor=action['actor_id'],action_id=action['id']),
                on_stderr_raw=self.raw_capture('driver.stderr',actor=action['actor_id'],action_id=action['id']))
            public_payload(response)
            self.store.trace_capture('driver.call',{'phase':'response','response':response,
                'duration_ms':round((time.monotonic()-started)*1000),'queued_for_ms':queued_for_ms,'context':context},
                actor=action['actor_id'],action_id=action['id'])
            self.store.event("driver_response", {"action_id": action["id"], "response": response,
                             "duration_ms": round((time.monotonic() - started) * 1000),
                             "queued_for_ms":queued_for_ms, "context":context})
        except Exception as error:
            self.store.finish(action["id"], "outcome_unknown", {"reason": type(error).__name__,
                "duration_ms": round((time.monotonic() - started) * 1000)})
            if receiver_tasks:await asyncio.gather(*receiver_tasks)
            return True
        if response.get("action_id") != action["id"]:
            self.store.finish(action["id"], "outcome_unknown", {"reason": "driver response identity mismatch"})
        elif response.get("actual_fee_sat") is not None and (type(response["actual_fee_sat"]) is not int or response["actual_fee_sat"] < 0):
            self.store.finish(action["id"], "outcome_unknown", {"reason": "invalid fee evidence"})
        elif response.get("status") == "ok" and action["operation"] == "exit":
            # One original action owns all phases and fees. Submission is not
            # completion; public confirmed whole-exit proofs close it later.
            self.store.finish(action["id"], "outcome_unknown", response)
            for evidence in boundary_frames:
                data={'evidence':evidence}
                record_candidates(self.store,action['actor_id'],action['id'],data)
                try:
                    checked=await verify_client_evidence(self.store,action['actor_id'],'exit',data,self.config.proof_command)
                    record_verified(self.store,action['actor_id'],action['id'],checked)
                except InvariantError as error:
                    self.store.event('ownership_incident',{'action_id':action['id'],'reason':str(error)})
                    self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','ownership contradiction')")
                except Exception as error:
                    self.store.event('ownership_proof_pending',{'action_id':action['id'],'reason':type(error).__name__})
        elif response.get("status") == "ok":
            verified = None
            try:
                verified = await verify_client_evidence(self.store,action["actor_id"],action["operation"],response.get("data",{}),self.config.proof_command)
            except InvariantError as error:
                self.store.event("ownership_incident",{"action_id":action["id"],"reason":str(error)})
                self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','ownership contradiction')")
            except Exception as error:
                self.store.event("ownership_proof_pending",{"action_id":action["id"],"reason":type(error).__name__})
            def completed():
                record_actor_result(self.store,action["actor_id"],action["operation"],response.get("data",{}))
                if action["operation"]=="invoice":
                    row=self.store.db.execute("SELECT details FROM actor WHERE id=?",(action["actor_id"],)).fetchone()
                    detail=json.loads(row[0]);detail["invoice_action_id"]=action["id"]
                    self.store.db.execute("UPDATE actor SET details=? WHERE id=?",(canonical(detail),action["actor_id"]))
                target=action["args"].get("recipient_actor")
                if target:
                    row=self.store.db.execute("SELECT details FROM actor WHERE id=?",(target,)).fetchone()
                    if row:
                        detail=json.loads(row[0]);detail["needs_sync"]=True
                        self.store.db.execute("UPDATE actor SET details=? WHERE id=?",(canonical(detail),target))
                record_candidates(self.store,action["actor_id"],action["id"],response.get("data",{}),verification_failed=verified is None)
                record_verified(self.store,action["actor_id"],action["id"],verified)
                record_delegated(self.store,action["id"])
            try:
                self.store.finish(action["id"], "completed", response, response.get("actual_fee_sat"),
                                  on_completed=completed)
            except (KeyError, TypeError, ValueError):
                self.store.finish(action["id"], "outcome_unknown", {"reason": "invalid completed-action evidence"})
        elif response.get("status") == "expected_refusal" and RAW_CASES.get(action["operation"]) == action["scenario_id"]:
            self.store.finish(action["id"], "expected_refusal", response, response.get("actual_fee_sat"))
        elif response.get("status") == "blocked":
            self.store.finish(action["id"], "blocked", response, response.get("actual_fee_sat"))
        elif response.get("status") == "incident":
            self.store.finish(action['id'],'outcome_unknown',response)
            self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','incident')")
        elif response.get("status") == "error":
            # SDK errors can occur after a successful broadcast/commit. Never label
            # a generic driver error terminal or safely retryable.
            self.store.finish(action["id"], "outcome_unknown", response)
        else:
            self.store.finish(action["id"], "failed", {"reason": "unexpected driver outcome", "response": response})
        if receiver_tasks:await asyncio.gather(*receiver_tasks)
        if bootstrap_action:
            try:
                if len(self.config.proof_command)!=4:raise ValueError('independent bootstrap Core source missing')
                chain=ChainReader(self.config.proof_command[1],self.config.proof_command[2],
                    self.config.expected_genesis,capture=self.store.trace_sample,consumer='identity-bootstrap')
                identity_bootstrap.verify_created(self.store,self.config,chain,action['actor_id'],action['id'])
            except Exception as error:
                self.store.event('identity_bootstrap_held',{'action_id':action['id'],
                    'reason':type(error).__name__,'scope':'await independent zero-asset source; never retry create'})
        return True

    def prepare_campaign_funding(self,snapshot):
        if self.config.workload!="continuous" or not self.config.funding_wallet or not self.config.active or self.store.get_meta("paused"):return
        if self._requires_financial_qualification():
            from .operating_limits import envelope,preflight
            try:
                declared=envelope(self.store,self.config)
                from .funding import plan
                funding_plan=plan(self.store)
                if declared['grant_sat']!=funding_plan['grant_sat']:
                    raise ValueError('funding grants differ from financial envelope')
                if not preflight(self.store,self.config,snapshot,maximum_fee_sat=funding_plan['batch_maximum_fee_sat'])['allowed']:
                    return
            except ValueError as error:
                self.store.event('fixture_funding_held',{'reason':str(error),'scope':'financial preflight; no funding call'})
                return
        for batch,start,end in [("initial",1,12),("ramp",13,24)]:
            if batch=="ramp" and self.store.get_meta("ramp_applied")!="true":continue
            rows=self.store.db.execute("SELECT details FROM actor WHERE id>=? AND id<=?",(f"actor-{start:02}",f"actor-{end:02}")).fetchall()
            if len(rows)!=12 or any(not json.loads(r[0]).get("created") for r in rows):continue
            last=float(self.store.get_meta("funding_check_"+batch) or "0")
            if time.time()-last<120:continue
            try:
                result=fund(self.store,WalletRpc(self.config.funding_credential_file,self.config.funding_wallet,capture=self.store.trace_sample if self.store.trace is not None else None),batch)
                if batch=="initial" and result["state"]=="confirmed" and self.store.get_meta("real_campaign_started") is None:
                    done=sum(bool(json.loads(r[0]).get("board_submitted")) for r in rows)
                    if done==12 and lightning_ready(snapshot):
                        with self.store.transaction():
                            self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started',?)",(str(time.time()),))
                            self.store._event("real_campaign_started",{"initial_clients":12,"funding_txid":result["txid"],"height":snapshot["height"],"setup_time_excluded":True})
            except Exception as error:
                self.store.event("fixture_funding_pending",{"batch":batch,"reason":type(error).__name__})
            self.store.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",("funding_check_"+batch,str(time.time())))

    async def collect_inventory(self):
        if not self.config.inventory_command:return
        kinds=["coins","pending","links","records"]
        if campaign_profile(self.store)==TWO_STEP:kinds += ['settlements','nursery']
        index=int(self.store.get_meta("inventory_kind_index") or "0")%len(kinds)
        kind=kinds[index];key="inventory_cursor_"+kind
        cursor=self.store.get_meta(key) or ""
        page=await json_command(list(self.config.inventory_command),{"kind":kind,"after":cursor},timeout=25,
            on_stdout_raw=self.raw_capture('inventory.page',context={'request':{'kind':kind,'after':cursor}}),
            on_stderr_raw=self.raw_capture('inventory.stderr'))
        if page.get("kind")!=kind:raise ValueError("inventory kind mismatch")
        record_server_page(self.store,page)
        await collect_padding(self.store,self.config.server_policy_command,self.config.expected_server_pubkey,limit=16)
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",(key,page.get("next") or ""))
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('inventory_kind_index',?)",(str((index+1)%len(kinds)),))
        from .priority_inventory import collect as collect_priority_inventory
        result=await collect_priority_inventory(self.store,self.config,
            normal_page={'request':{'kind':kind,'after':cursor},'response':page})
        if result['status']!='idle':self.store.event('round_priority_inventory_cycle',result)


    async def run(self, once: bool = False):
        self.store.verify_event_chain()
        self.store.recover_dispatched()
        last_report = None
        while True:
            ready=False
            snapshot={}
            try:
                snapshot = await self.observe()
            except Exception as error:
                self.store.event("observer_gap", {"reason": type(error).__name__})
                self.store.add_snapshot({"observed_at": time.time(), "complete": False,
                                         "rounds_confirmed_sat": None, "error": type(error).__name__})
                # Never dispatch actions after failed identity or unavailable observation.
            else:
                sources_observed = await self.refresh_financial_sources()
                bootstrap_active=identity_bootstrap.pending(self.store)
                ready = (sources_observed or bootstrap_active) and self.ready_for_actions(snapshot)
                if self.config.active and not ready:
                    self.store.event("dispatch_held", {"reason": "snapshot is stale, unstable, unhealthy or lacks readiness evidence"})
                if self.config.active and ready and self.config.workload == "pilot":
                    if snapshot.get("timings", {}).get("payout_enabled") is not True:
                        self.store.event("pilot_blocked", {"reason": "expiry payouts are not verified enabled"})
                        observe(self.store)
                        generate(self.store, evaluate=False)
                        if once:
                            break
                        await asyncio.sleep(self.config.interval_seconds)
                        continue
                    self.config.wallet_root.mkdir(mode=0o700, parents=True, exist_ok=True)
                    schedule_pilot(self.store, self.config)
                if self.config.active and ready and self.config.workload=="continuous":
                    if snapshot.get("timings",{}).get("payout_enabled") is True:
                        self.prepare_campaign_funding(snapshot)
                        schedule_continuous(self.store,self.config,snapshot)
                if ready:
                    await self.dispatch_batch()
            from . import exploratory
            if exploratory.scope(self.store) is not None:
                # Stage-two traffic is useful evidence, never final clock time.
                if self.store.get_meta('qualified_campaign_active_seconds') not in (None,'0'):
                    raise InvariantError('preserve historical qualified clock; exploratory scope cannot reset it')
            if self.campaign_clock and exploratory.scope(self.store) is None:
                collect_ark_receipts(self.store)
                if self.store.get_meta('final_financial_epoch') is not None:
                    from .final_campaign import collect_traffic
                    collect_traffic(self.store,snapshot.get('financial_pins'))
                self.campaign_clock.tick(healthy=ready and lightning_ready(snapshot) and traffic_ready(self.store,financial_pins=snapshot.get("financial_pins")),real_campaign_started=self.store.get_meta("real_campaign_started") is not None,financial_pins=snapshot.get("financial_pins"))
            try:
                if self.config.active:
                    await collect_public_proofs(self.store,self.config)
                    collect_renewal(self.store,self.config)
                    await collect_payments(self.store,self.config.driver_command,self.config.expected_server_pubkey)
                await self.collect_inventory()
                from .round_adoption import collect_input_params
                await collect_input_params(self.store,self.config)
                await collect_negative_checks(self.store,self.config.inventory_command,self.config.proof_command)
                await collect_protocol_checks(self.store,self.config.inventory_command,self.config.proof_command)
                await retry_public_candidates(self.store,self.config.proof_command)
                chain=None
                if len(self.config.proof_command)==4:
                    chain=ChainReader(self.config.proof_command[1],self.config.proof_command[2],self.config.expected_genesis,capture=self.store.trace_sample)
                    if self.config.server_policy_command:
                        try:
                            chain.consumer='padding-backing'
                            await collect_padding_backing(self.store,chain,self.config.server_policy_command,self.config.expected_server_pubkey,limit=2)
                        except InvariantError:raise
                        except Exception as error:self.store.event('padding_backing_gap',{'reason':type(error).__name__})
                    chain.consumer='operator-ownership'
                    await collect_operator_scripts(self.store,self.config,chain)
                    chain.consumer='settlements'
                    await self.collect_settlement_evidence(chain)
                    chain.consumer='fees'
                    await collect_fees(self.store,chain)
                    chain.consumer='recycling'
                    await collect_recycling(self.store,chain)
                if self.config.active:
                    if ready:await collect_exits(self.store,self.config,chain)
                    await collect_unknown(self.store,self.config,chain)
                collect_delegated(self.store)
                for phase in self.store.db.execute("SELECT id FROM phase_trial WHERE release_action IS NOT NULL").fetchall():self.phases.judge(phase['id'])
            except InvariantError as error:
                self.store.event("ownership_incident",{"reason":str(error)})
                self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','ownership contradiction')")
            except Exception as error:
                self.store.event("inventory_gap",{"reason":type(error).__name__})
            # Existing preparations and broadcasts have their own evidence
            # reader. Poll them even when target inventory is unavailable;
            # RecoveryController retains the pause fence on new work/broadcast.
            if self.recovery:
                try:
                    await self.recovery.tick()
                except InvariantError as error:
                    self.store.event("ownership_incident",{"reason":str(error)})
                    self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','ownership contradiction')")
                except Exception as error:
                    self.store.event("recovery_gap",{"reason":type(error).__name__})
            padding_latest=self.store.db.execute('SELECT id,payload FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()
            if padding_latest:
                padding_snapshot=json.loads(padding_latest['payload'])
                if type(padding_snapshot.get('height')) is int:
                    capture_padding_snapshot(self.store,padding_latest['id'],padding_snapshot)
            if self.config.log_target_enabled or self.config.log_local_sources:
                try:
                    await collect_logs(self.store,configured_log_sources(self.store,self.config),
                        limit=self.config.log_rows_per_page,maximum_bytes=self.config.log_maximum_bytes)
                except Exception as error:
                    self.store.trace_capture('log.capture.gap',{'kind':'configuration_or_collector_unavailable','error_type':type(error).__name__})
            # Independent diagnostic each snapshot, even when inventory work failed.
            from .fee_watch import collect as collect_fee_watch
            fee_latest=self.store.db.execute('SELECT id FROM snapshot ORDER BY id DESC LIMIT 1').fetchone()
            if fee_latest:
                try:
                    if len(self.config.proof_command)!=4:
                        raise ValueError('independent Core observer unavailable')
                    fee_chain=ChainReader(self.config.proof_command[1],self.config.proof_command[2],
                        self.config.expected_genesis,capture=self.store.trace_sample,consumer='payout-fee-watch')
                    await collect_fee_watch(self.store,fee_chain,'snapshot:'+str(fee_latest['id']),
                        target_blocks=6,mode='economical',transaction_limit=2)
                except Exception as error:
                    self.store.trace_capture('fee.watch.gap',{'snapshot_id':fee_latest['id'],'reason':type(error).__name__})
            if self.store.trace is not None:self.store.trace.archive()
            observe(self.store)
            if once or last_report is None or self.store.get_meta("paused") or time.monotonic() - last_report >= 300:
                generate(self.store, evaluate=False)
                last_report = time.monotonic()
            if once:
                break
            await asyncio.sleep(self.config.interval_seconds)


class Lease:
    def __init__(self, root: Path):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.file = (root / "supervisor.lock").open("a")

    def __enter__(self):
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.file.close()
            raise RuntimeError("another simulator owns this state directory") from None
        return self

    def __exit__(self, *args):
        self.file.close()
