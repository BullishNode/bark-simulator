"""Noah journey requirements, separate from the core scenario catalogue."""

SCENARIOS=(
 ('Baseline','Five funded awake phones; actual Ark and Lightning receipts, committed maintenance refreshes over several expiry periods.'),
 ('Sleepy phones','Independent misses, correlated offline bursts and periodic wakes; measure actual commitment, wake latency and expiry margin.'),
 ('Phone gone','Deregistration, independent expiry payout and fresh seed-only confirmed spend; original gone wallet stays closed.'),
 ('Gone device without forwarding','Absent Active then Inactive; no invoice or payment and no rescue wallet calls.'),
 ('Forwarding to gone recipient','Actual collection, recipient-owned outputs, once-only fallback and fresh confirmed recovery.'),
 ('Forwarder interrupted','Separate claim/delivery boundary and both restart/permanent disappearance; exactly one economic delivery.'),
 ('Forwarder gone through expiry','Separate pre-collection refund, forwarder custody/customer liability and committed recipient ownership.'),
 ('Ark through LNURL','Same-server Ark destination negotiation; mismatch rejection; no Lightning credit.'),
 ('Phone mid-claim','Separate HtlcsReady and preimage boundaries, never-return and separately declared late-return wallet.'),
 ('Recurring after payout','Real due schedules use live coins or refuse cleanly; duplicate wakes do not repay settled inputs.'),
 ('Backup after payout','Actual local S3 v2 upload/completion/checksum/download/decrypt and network/fingerprint/server/mailbox/schema validation.'),
 ('Funded maintenance scale','5→50→200 funded phones committing refreshes with simultaneous payouts; predeclared capital/resource bounds and independent audit.'),
 ('Delegated mid-swap','Required maintenance-driven mid-swap disappearance, late return, superseded pending requests and both settlement/forfeit race winners; original/replacement principal and fees independently audited.'),
)

LNURL_JOURNEYS=(
 ('Awake device','Authentic two-step request, original Expo invoice submission, actual payment and rightful claimed coin.'),
 ('Sleeping device','Delayed wake within real45s window and late-wake timeout; no silent payment after timeout.'),
 ('Gone device','No invoice/payment without forwarding; no absent wallet calls.'),
 ('Forwarding to gone recipient','Actual collection and recipient-owned outputs, recipient fallback and seed-only confirmed spend.'),
 ('Forwarder before collection','No false completion; payer refund independently proved.'),
 ('Forwarder after collection','Separate committed recipient ownership from forwarder custody and outstanding customer liability.'),
 ('Mid-claim disappearance','Separate HtlcsReady/preimage kills, once-only payout/refund and a separate returning-device variant.'),
 ('Reused Lightning address','Distinct repeated/concurrent invoice hashes, exact recipient grouping, once-only entitlements and fees.'),
 ('Unlinked recipient','Refuse before collection or independently prove payer refund.'),
 ('Push disorder','Delayed/duplicate/out-of-order original pushes/submissions; no wrong payee or duplicate economic payment.'),
 ('Ark negotiation','Same-server selection and mismatched key; Ark-through-LNURL earns no Lightning credit.'),
 ('Pending restart','Preserve invoice/hash, read grant and liabilities; reconcile same prior intent before new dispatch.'),
)


def coverage(store):
    """Unit/native parsing checks cannot promote monetary or full-scenario verdicts."""
    def rows(items,prefix):
        return [{'id':f'{prefix}{i:02d}','name':name,'required':required,'status':'unqualified',
                 'mechanism':'owned signet client profile; fork-controlled maintenance window where required',
                 'actual_transport':None,'evidence':[],'fees':None,'remaining_liabilities':None,
                 'reason':'genuine backend/SDK journey and independent outcome audit not imported'}
                for i,(name,required) in enumerate(items,1)]
    return {'scenarios':rows(SCENARIOS,'N'),'lnurl_journeys':rows(LNURL_JOURNEYS,'NL'),
            'complete':False,'scope':'separate required journey catalogue; transport/unit acceptance is not fixture or payment qualification'}
