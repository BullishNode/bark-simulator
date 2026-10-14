"""Immutable ownership/settlement profile for a fresh, isolated campaign.

Unprofiled historical direct campaigns retain their existing API. Explicitly
profiled campaigns must always supply their profile, including on restart.
This does not select a native build or qualify its cryptographic implementation.
"""
import json

from .model import canonical

KEY = 'architecture_profile'
DIRECT = 'direct_xpub'
TWO_STEP = 'two_step_per_key'
PROFILES = frozenset({DIRECT, TWO_STEP})


def validate(requested):
    if requested is not None and (not isinstance(requested, str) or requested not in PROFILES):
        raise ValueError('unsupported explicit campaign architecture profile')


def initialize(store, requested, *, fresh):
    """Bind before ownership DDL; never adopt or migrate a historical database."""
    validate(requested)
    store._architecture_profile = requested
    tables = {row[0] for row in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'meta','event'}.issubset(tables):
        raise ValueError('historical campaign lacks original profile evidence; no adoption')
    saved = store.get_meta(KEY)
    events = store.db.execute("SELECT payload FROM event WHERE kind='architecture_profile_declared'").fetchall()
    if saved is None:
        if events or requested is not None and not fresh:
            raise ValueError('missing architecture declaration; historical campaigns cannot be adopted')
        if requested is not None:
            payload = {'version':1, 'id':requested}
            with store.transaction():
                store.db.execute('INSERT INTO meta VALUES (?,?)', (KEY, canonical(payload)))
                store._event('architecture_profile_declared', payload)
    profile(store)


def profile(store):
    """Recheck original declaration before accepting any ownership evidence."""
    requested = getattr(store, '_architecture_profile', None)
    saved = store.get_meta(KEY)
    events = store.db.execute("SELECT payload FROM event WHERE kind='architecture_profile_declared'").fetchall()
    if saved is None:
        if requested is not None or events:
            raise ValueError('campaign architecture declaration missing')
        return DIRECT
    try:
        value = json.loads(saved)
    except (TypeError, ValueError) as error:
        raise ValueError('invalid campaign architecture declaration') from error
    if (not isinstance(value, dict) or set(value) != {'version','id'}
            or type(value['version']) is not int or value['version'] != 1
            or not isinstance(value['id'], str) or value['id'] not in PROFILES or value['id'] != requested
            or len(events) != 1 or events[0][0] != saved or canonical(value) != saved):
        raise ValueError('campaign architecture differs from original explicit declaration')
    return value['id']
