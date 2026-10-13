# Priority round inventory

An online client with an existing pending SDK round movement enables a bounded public inventory scan. Permanently absent clients do not enable it. The scan requests server inventory through the existing read-only bridge and never opens a customer wallet or queues a payment.

Each collector call keeps the normal six-kind inventory rotation and adds at most one nursery page and three coin pages. Pages retain the bridge's 100-row limit. A shared 12-second deadline bounds the extra RPC and public decoding work; an in-progress bounded database commit finishes before a timeout can stop subsequent requests. Decoder batches prioritize newly observed unclaimed rows.

Priority cursors are separate from normal inventory cursors. They persist across restarts and changes in the online pending cohort. A terminal page wraps its cursor with a recorded scan generation and stops that lane for the current call. A matching normal page is reused without another request. Page history and cursor progress commit together; invalid, private, failed or timed-out responses cannot advance the cursor. Earlier committed pages remain available after a later gap.

With responsive stable pagination, 950 coin rows take four priority calls to scan, compared with one coin page per six normal calls. Rows inserted behind a cursor become visible in the following scan. RPC timeouts, changing inventory and missing decoder evidence remain explicit gaps rather than a discovery guarantee.

These pages are trusted server observations across separate reads. They do not establish an atomic inventory snapshot, ownership, a header-chain confirmation, a successful payout or customer traffic. Confirmation-driven scheduling and signed client adoption retain their separate checks. The normal rotation continues to collect links, records, pending boards and settlements while priority scans progress.
