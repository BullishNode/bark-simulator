"""Bind direct phase calls to the actual negotiated protocol version."""
from .model import InvariantError
from .ownership import EvidenceGap

def negotiated_version(server_min,server_max,client_min,client_max,pinned):
    if any(type(v) is not int or v<0 for v in (server_min,server_max,client_min,client_max)) or server_min>server_max or client_min>client_max:
        raise EvidenceGap('actual bounded handshake range required')
    if server_min>client_max or server_max<client_min:raise EvidenceGap('protocol ranges do not overlap')
    selected=min(server_max,client_max)
    if type(pinned) is not int:raise EvidenceGap('immutable negotiated protocol pin missing')
    if selected!=pinned:raise InvariantError('actual negotiated protocol differs from frozen pin')
    return selected
