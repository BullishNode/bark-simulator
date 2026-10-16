"""Synthetic public Core activity captures; never actual Core qualification."""
import hashlib
from simulator.model import canonical


def script(value):
    return hashlib.sha256(value.encode()).hexdigest()


def capture(chain, store, args, result):
    chain.last_capture = store.trace_sample({'kind': 'chain.rpc', 'payload': {
        'method': 'getdescriptoractivity', 'params': list(args), 'result': result, 'error': None},
        'raw': canonical({'jsonrpc': '2.0', 'id': 1, 'result': result}).encode()})
    return result


def receipt(store, source, kind):
    """Control-only RPC receipt for tests that mock the owning collector itself."""
    import time
    from types import SimpleNamespace
    from simulator.owned_mempool import collect,collector_context
    store.attach_trace()
    chain=SimpleNamespace()
    chain.call=lambda method,*args,**kwargs:capture(chain,store,args,{'activity':[]})
    return collect(store,chain,{script('dependent-admission-control')},time.monotonic(),
        context=collector_context(kind,source))
