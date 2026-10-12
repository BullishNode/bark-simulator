"""Bounded negative requests using public, independently verified identities.

Implementation flags describe the request adapter, not completed qualification.
The owner-key table contains signatures and public keys, never private keys.
"""
RAW_CASES = {
    'raw_foreign_record': 'D01', 'raw_record_tamper': 'D02',
    'raw_sequence_tamper': 'D03', 'raw_wrong_chain': 'D04',
    'raw_stale_record': 'D05', 'raw_equal_sequence': 'D06',
    'raw_mixed_link': 'D07', 'raw_invalid_link': 'D08',
    'raw_mailbox_tamper': 'D09', 'raw_key_replay': 'D10',
    'raw_relink': 'D11', 'raw_board_unlinked': 'D12',
    'raw_bounded_queries': 'D39', 'raw_malformed': 'D40',
}

def next_case(store, actor, count):
    cases = list(RAW_CASES)
    for offset in range(len(cases)):
        operation = cases[(count + offset) % len(cases)]
        args = {}
        if operation in {'raw_foreign_record', 'raw_invalid_link'}:
            row = store.db.execute('SELECT pubkey,mailbox FROM owner_key WHERE actor<>? ORDER BY actor,pubkey LIMIT 1', (actor,)).fetchone()
            if row is None:
                continue
            args = {'victim_mailbox_pk': row['mailbox']} if operation == 'raw_foreign_record' else {'victim_pubkey': row['pubkey']}
        if operation == 'raw_malformed':
            args = {'variant': count // len(cases) % 3}
        return RAW_CASES[operation], operation, args
    raise AssertionError('non-targeted raw cases must remain available')
