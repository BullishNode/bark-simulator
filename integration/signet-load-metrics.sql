-- Read-only, target-database counters. No actor, payment, seed or SQL query text.
-- WAL counters are cluster-wide: preserve stats_reset and other-profile activity.
BEGIN READ ONLY;
SELECT json_build_object(
  'at', clock_timestamp(),
  'database', current_database(),
  'database_bytes', pg_database_size(current_database()),
  'database_stats_reset', d.stats_reset,
  'xact_commit', d.xact_commit, 'xact_rollback', d.xact_rollback,
  'blks_read', d.blks_read, 'blks_hit', d.blks_hit,
  'temp_bytes', d.temp_bytes, 'deadlocks', d.deadlocks,
  'connections', (SELECT count(*) FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid()),
  'active', (SELECT count(*) FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='active'),
  'idle_in_transaction', (SELECT count(*) FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='idle in transaction'),
  'unknown_state_connections', (SELECT count(*) FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid() AND state IS NULL),
  'lock_waiters', (SELECT count(*) FROM pg_stat_activity
    WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock'),
  'cluster_wal_bytes', w.wal_bytes::text,
  'cluster_wal_stats_reset', w.stats_reset,
  'scope', 'Target database counters; cluster-wide WAL. No transaction contents or isolated capacity assertion.'
)
FROM pg_stat_database d CROSS JOIN pg_stat_wal w
WHERE d.datname=current_database();
ROLLBACK;
