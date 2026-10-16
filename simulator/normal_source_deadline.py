"""One measured deadline for the complete normal financial observation."""
import contextvars
import time
from .chain import ChainReader
from .model import timestamp

ACTIVE = contextvars.ContextVar('normal_source_deadline', default=None)


class Deadline:
    def __init__(self, started_at):
        started = timestamp(started_at, 'actual financial observation start')
        age = time.time()-started
        if not 0 <= age < 90: raise ValueError('normal source aggregate deadline expired/future')
        self.wall_end = started+90
        self.monotonic_end = time.monotonic()+90-age
    def remaining(self):
        remaining = min(self.wall_end-time.time(), self.monotonic_end-time.monotonic())
        if remaining <= 0: raise TimeoutError('normal source aggregate deadline exceeded')
        return remaining
    def limit(self, seconds): return min(seconds, self.remaining())


def timeout(seconds):
    deadline = ACTIVE.get()
    return seconds if deadline is None else deadline.limit(seconds)


def check():
    deadline = ACTIVE.get()
    if deadline is not None: deadline.remaining()


class DeadlineChain:
    """Use existing ChainReader derivation/error capture, limiting every RPC."""
    def __init__(self, chain, deadline): self.chain, self.deadline = chain, deadline
    def __getattr__(self, name): return getattr(self.chain, name)
    @property
    def last_capture(self): return self.chain.last_capture
    def call(self, method, *args, timeout=12, **kwargs):
        value = self.chain.call(method, *args, timeout=self.deadline.limit(timeout), **kwargs)
        self.deadline.remaining()
        return value
    def identity(self): return ChainReader.identity(self)
    def tx(self, txid): return ChainReader.tx(self, txid)
    def transaction(self, txid): return ChainReader.transaction(self, txid)
