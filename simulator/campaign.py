"""Persisted client ramp, driven only by verified live-campaign health.

No wall-clock catch-up on restart: setup, pauses, unavailable observations and
process downtime contribute zero. Creation/funding remain journaled operations;
adding actor rows never transfers money or retries an uncertain action.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict

from .model import canonical, integer
from .store import Store

TRAFFIC_WINDOW_SECONDS = 600

def traffic_ready(store: Store, now: float | None = None) -> bool:
    """Require successful customer transfers, rather than a healthy idle server.

    Both rails must have succeeded since declared funding/boarding completed,
    and at least one within the last ten minutes. Reads, invoices, grants and
    merely initiated Lightning sends do not count.
    """
    started = store.get_meta("real_campaign_started")
    if started is None:
        return False
    now = time.time() if now is None else now
    rows = store.db.execute("""SELECT operation, MAX(updated_at) AS latest FROM action
        WHERE state='completed' AND updated_at>=? AND updated_at<=?
        AND ((operation='send_arkoor' AND json_extract(result,'$.data.submitted')='send_arkoor')
          OR (operation='pay_invoice' AND json_extract(result,'$.data.paid')=1
            AND json_extract(result,'$.data.payment_status_verified')=1
            AND json_extract(result,'$.data.payment_state')='succeeded'))
        GROUP BY operation""", (float(started), now)).fetchall()
    latest = {row['operation']:row['latest'] for row in rows}
    return (set(latest) == {'send_arkoor','pay_invoice'}
            and now - max(latest.values()) <= TRAFFIC_WINDOW_SECONDS)


@dataclass(frozen=True)
class RampPlan:
    initial_clients: int = 12
    added_clients: int = 12
    after_active_seconds: int = 10800
    funding_per_added_client_sat: int = 8000

    def validate(self):
        for key, value in asdict(self).items():
            integer(value, key, 1)
        if self.initial_clients + self.added_clients > 99:
            raise ValueError("driver supports actor-01 through actor-99")


class CampaignClock:
    def __init__(self, store: Store, plan: RampPlan, maximum_gap_seconds: int = 180, clock=time.monotonic):
        plan.validate()
        integer(maximum_gap_seconds, "maximum observation gap", 1)
        self.store, self.plan, self.clock = store, plan, clock
        self.maximum_gap = maximum_gap_seconds
        self.previous_time = None
        self.previous_healthy = False
        encoded = canonical(asdict(plan))
        with store.transaction():
            existing = store.get_meta("ramp_plan")
            if existing is not None and existing != encoded:
                raise ValueError("ramp plan/funding are immutable for this campaign")
            if existing is None:
                store.db.execute("INSERT INTO meta VALUES ('ramp_plan',?)", (encoded,))
                store.db.execute("INSERT INTO meta VALUES ('campaign_active_seconds','0')")
                store._event("ramp_declared", {**asdict(plan), "added_funding_budget_sat":plan.added_clients * plan.funding_per_added_client_sat,
                    "recent_transfer_window_seconds":TRAFFIC_WINDOW_SECONDS,
                    "required_initial_successful_rails":["ark","lightning"]})

    def tick(self, *, healthy: bool, real_campaign_started: bool):
        now = self.clock()
        eligible = healthy and real_campaign_started and not self.store.get_meta("paused")
        delta = 0
        if self.previous_time is not None and self.previous_healthy and eligible:
            elapsed = now - self.previous_time
            if 0 <= elapsed <= self.maximum_gap:
                delta = elapsed
        self.previous_time, self.previous_healthy = now, eligible
        with self.store.transaction():
            accumulated = float(self.store.get_meta("campaign_active_seconds")) + delta
            self.store.db.execute("UPDATE meta SET value=? WHERE key='campaign_active_seconds'", (repr(accumulated),))
            if delta:
                self.store._event("campaign_active_interval", {"seconds":delta, "total_seconds":accumulated})
            if eligible and accumulated >= self.plan.after_active_seconds and not self.store.get_meta("ramp_applied"):
                expected = {f"actor-{i:02}" for i in range(1, self.plan.initial_clients + 1)}
                actual = {r[0] for r in self.store.db.execute("SELECT id FROM actor")}
                if actual != expected:
                    raise ValueError("unexpected pre-ramp cohort; no automatic overwrite")
                actors = []
                for index in range(self.plan.initial_clients + 1, self.plan.initial_clients + self.plan.added_clients + 1):
                    actor = f"actor-{index:02}"
                    details = {"cohort":"ramp", "declared_initial_funding_sat":self.plan.funding_per_added_client_sat}
                    self.store.db.execute("INSERT INTO actor VALUES (?,?,1,?)", (actor,"additional realistic client",canonical(details)))
                    actors.append(actor)
                self.store.db.execute("INSERT INTO meta VALUES ('ramp_applied','true')")
                self.store._event("client_ramp_applied", {"actors":actors,"total_clients":len(expected)+len(actors),
                    "active_seconds":accumulated,"funding_budget_sat":self.plan.added_clients*self.plan.funding_per_added_client_sat,
                    "funding_dispatched":False})
        return accumulated
