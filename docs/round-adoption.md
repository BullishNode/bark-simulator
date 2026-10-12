# Round adoption

A completed refresh request can leave a pending SDK movement while its replacements remain unclaimed on the server. A successful outer sync can also contain an inner round error. Signed client outputs and successful movements establish adoption; a submitted request or confirmation log alone does not.

The `round_confirmed_sync` rule prioritizes an existing frozen refresh when public nursery evidence records the required funding confirmation depth. Matching uses exact frozen output keys and values, decoded signed-coin bytes, a direct funding anchor, and the raw funding transaction's recomputed identity. Ambiguous output matches remain pending. Decoder metadata is scheduling evidence and does not establish client ownership.

Depth and exit margin come from the actual SDK parameters emitted during an existing online wallet operation. Missing parameters remain explicit holds. Configured declarations cannot override those values. Offline clients, unknown action outcomes, stale snapshots, fee caps, and original refresh reservations retain their existing fences. Repeated ticks and restarts do not queue duplicate syncs. One unsafe actor does not prevent another ready actor from being selected.

For live original inputs, the SDK requires replacement expiry at least:

```text
current tip + 2 × wallet exit margin + maximum original input exit delta
```

The SDK skips this particular floor only when all original inputs have expired. A shorter server lifetime can therefore prevent immediate adoption even after confirmation. The simulator reports the exact security-window hold and preserves the SDK checks. More frequent syncs do not resolve an unsafe window.

Near-expiry observations identify unclaimed outputs tied to frozen client intents without claiming a payout, loss, or entitlement. Missing decoder or inventory evidence does not clear an existing warning. Compact structured SDK diagnostics retain waiting, confirmed, and refusal categories in the event journal; complete stderr belongs in the public trace.

The native fixture `simulator_confirmed_round_scheduler_cycle` declares its deposits, boards, customer fee caps, SDK parameters, and a safe replacement lifetime. It supplies real pending movements, signed server inventory and confirmed raw nursery transactions to the normal scheduler. It requires both the interactive and delegated refresh recipients to adopt their exact replacements through the selected syncs within one cycle, with independent signed-output checks. Passing this isolated fixture does not establish live adoption latency under a different server lifetime.
