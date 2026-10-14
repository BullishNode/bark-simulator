"""Capture bounded original financial facts; partial replies never open dispatch."""
import time
from .model import public_payload
from .ownership import EvidenceGap
from .process import json_command,public_command_capture

async def collect_partial(store,config,chain):
    if not config.inventory_command or chain is None:raise EvidenceGap('actual read-only bridge and independent chain required')
    request={'kind':'financial_readiness'}
    before=chain.identity()
    response=await json_command(list(config.inventory_command),request,timeout=25,
        **public_command_capture(store,'financial.readiness.partial',request))
    public_payload(response)
    # Current bridge only reports facts with explicit gaps. A future claiming
    # qualification is a different contract and needs its own independent checks.
    if (response.get('kind')!='financial_readiness' or response.get('network')!=config.network
            or response.get('genesis')!=config.expected_genesis or response.get('complete') is not False
            or response.get('qualified') is not False or not isinstance(response.get('gaps'),list)
            or not response['gaps']):raise EvidenceGap('actual partial financial source contract differs')
    ending=chain.identity()
    same_tip=(before['bestblockhash']==ending['bestblockhash']==response.get('tip_hash')
        and before['blocks']==ending['blocks']==response.get('height') and response.get('stable_tip') is True
        and ending.get('initialblockdownload') is False)
    store.event('financial_source_partial',{'response':response,'independent_same_tip':same_tip,
        'observed_at':time.time(),'qualification':'unqualified; partial facts never become operating readiness or complete assets'})
    return {'qualified':False,'complete':False,'independent_same_tip':same_tip,'gaps':response['gaps']}
