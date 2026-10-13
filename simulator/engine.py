from __future__ import annotations

import asyncio
import fcntl
import json
import time
from pathlib import Path

from .config import Config
from .model import public_payload, timestamp
from .observations import observe
from .process import json_command
from .report import generate
from .store import Store
from .log_capture import configured_sources as configured_log_sources,collect_sources as collect_logs
from .padding import collect as collect_padding, collect_backing as collect_padding_backing, capture_snapshot as capture_padding_snapshot
from .ownership import record_candidates, record_verified, retry_public_candidates, verify_client_evidence, record_server_page
from .model import InvariantError,canonical
from .chain import ChainReader
from .settlements import collect_settlements
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
from .payments import collect as collect_payments
from .proof_import import collect as collect_public_proofs
from .recovery import RecoveryController
from .entitlements import record_submitted as record_delegated, collect as collect_delegated
from .operator_scripts import collect as collect_operator_scripts

OPERATIONS = {"create", "snapshot", "sync", "address", "board", "send_arkoor", "refresh",
              "refresh_delegated", "refresh_scheduled", "fallback_rotate", "exit", "offboard_all", "invoice", "pay_invoice"} | set(RAW_CASES)


def catalog():
    return json.loads(Path(__file__).with_name("scenarios.json").read_text())


def initialize(store: Store):
    store.register_catalog(catalog(), set(RAW_CASES.values()))
    roles = ["daily wallet", "spender", "merchant", "saver", "Lightning sender", "Lightning recipient",
             "intermittent phone", "delegated wallet", "absent wallet A", "absent wallet B",
             "adversarial A", "adversarial B"]
    for index, role in enumerate(roles, 1):
        store.actor(f"actor-{index:02}", role)


class Engine:
    def __init__(self, config: Config, store: Store):
        self.config, self.store = config, store
        if config.trace_enabled:store.attach_trace(config.trace_retention_days)
        self.campaign_clock=CampaignClock(store,RampPlan()) if config.workload=="continuous" else None
        self.recovery=RecoveryController(store,config) if config.recovery_command else None

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
        self.store.add_snapshot(snapshot)
        for item in snapshot.get("rounds_owned_scripts",[]):
            self.store.db.execute("INSERT OR IGNORE INTO operator_script VALUES (?,?)",(item["script"],canonical(item)))
        return snapshot

    def ready_for_actions(self, snapshot):
        age = time.time() - timestamp(snapshot["observed_at"], "snapshot time")
        return (0 <= age <= 90 and snapshot.get("stable_tip") is True
                and snapshot.get("initial_block_download") is False
                and snapshot.get("server_status", {}).get("status") == "running")

    async def dispatch_batch(self):
        """Claim distinct actors before launching concurrent client operations."""
        if not self.config.active:return False
        self.store.bind_wallet_root(self.config.wallet_root)
        actions=[]
        for _ in range(self.config.dispatch_per_tick):
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
        context = {"snapshot_id":latest["id"] if latest else None, "height":snapshot.get("height"),
                   "tip_hash":snapshot.get("tip_hash"), "mode":self.store.get_meta("mode")}
        self.store.trace_capture('driver.call',{'phase':'request','request':request,'context':context},
            actor=action['actor_id'],action_id=action['id'],raw=canonical(request).encode())
        self.store.event("driver_request", {"action_id": action["id"], "request": request, "context":context})
        queued_for_ms=max(0,round((time.time()-action["created_at"])*1000))
        started = time.monotonic()

        def progress(event):
            if event.get("action_id") != action["id"]:
                raise ValueError("driver evidence action mismatch")
            trace_ref=self.store.trace_capture('driver.event',{**event,'context':context},actor=action['actor_id'],action_id=action['id'])
            if trace_ref is not None and event.get('event') in {'client_evidence_before','client_evidence_after'}:
                event={**event,'data':{'fresh':event.get('data',{}).get('fresh'),'trace_ref':trace_ref}}
            self.store.event("driver_evidence", {**event,"context":context})

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
            return True
        if response.get("action_id") != action["id"]:
            self.store.finish(action["id"], "outcome_unknown", {"reason": "driver response identity mismatch"})
        elif response.get("actual_fee_sat") is not None and (type(response["actual_fee_sat"]) is not int or response["actual_fee_sat"] < 0):
            self.store.finish(action["id"], "outcome_unknown", {"reason": "invalid fee evidence"})
        elif response.get("status") == "ok" and action["operation"] == "exit":
            # Submission/CSV progress is not confirmed recovered-output proof.
            # Continue only the original frozen action and cap; never replay start.
            self.store.finish(action["id"],"outcome_unknown",response)
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
        elif response.get("status") == "error":
            # SDK errors can occur after a successful broadcast/commit. Never label
            # a generic driver error terminal or safely retryable.
            self.store.finish(action["id"], "outcome_unknown", response)
        else:
            self.store.finish(action["id"], "failed", {"reason": "unexpected driver outcome", "response": response})
        return True

    def prepare_campaign_funding(self,snapshot):
        if self.config.workload!="continuous" or not self.config.funding_wallet or not self.config.active or self.store.get_meta("paused"):return
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
        kinds=["coins","pending","links","settlements","records","nursery"]
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
            try:
                snapshot = await self.observe()
            except Exception as error:
                self.store.event("observer_gap", {"reason": type(error).__name__})
                self.store.add_snapshot({"observed_at": time.time(), "complete": False,
                                         "rounds_confirmed_sat": None, "error": type(error).__name__})
                # Never dispatch actions after failed identity or unavailable observation.
            else:
                ready = self.ready_for_actions(snapshot)
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
            if self.campaign_clock:
                collect_ark_receipts(self.store)
                self.campaign_clock.tick(healthy=ready and lightning_ready(snapshot) and traffic_ready(self.store),real_campaign_started=self.store.get_meta("real_campaign_started") is not None)
            try:
                if self.config.active:
                    await collect_public_proofs(self.store,self.config)
                    collect_renewal(self.store,self.config)
                    await collect_payments(self.store,self.config.driver_command,self.config.expected_server_pubkey)
                await self.collect_inventory()
                from .round_adoption import collect_input_params
                await collect_input_params(self.store,self.config)
                await collect_negative_checks(self.store,self.config.inventory_command,self.config.proof_command)
                await retry_public_candidates(self.store,self.config.proof_command)
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
                    await collect_settlements(self.store,chain)
                    chain.consumer='fees'
                    await collect_fees(self.store,chain)
                    chain.consumer='recycling'
                    await collect_recycling(self.store,chain)
                collect_delegated(self.store)
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
