"""Trusted C typed target-reader adapter before generic capture consumption.

Reuse the shared TargetTarReader lifecycle/stateless transport loader. This
adapter authenticates separately admitted expected context and executes ALL C
private source checks before returning the original C source shape. No A30/B
manifest alias, ready receipt, alternate producer or response-selected authority.
"""
import copy
from pathlib import Path
import time
from . import c_private_normal_cut as native
from .c_normal_source import _context
from .final_campaign import _source_event
from .model import canonical,public_payload
from .normal_source_deadline import check as deadline_check
from .two_step_normal import digest,module_hash
from .private_source_package import TargetTarReader

CONFIG_FIELDS={'source_sha256','body_source_sha256','history_identity','policy_sha256','limits','binding'}


class CheckedTargetReader:
    """Actual trusted constructor only; qualification binds all static data.

    Call after existing protected runtime/source-bootstrap verification. `adapter`
    is the existing authenticated fixed v7 source adapter, never a wire plugin.
    Separate installed/source qualification is required; event name is no proof.
    """
    def __init__(self,reader,adapter,configuration,qualification_sequence):
        if(type(reader)is not TargetTarReader or reader.loader is not native.decode_transport or reader.request_stdin is not True
                or not isinstance(configuration,dict)or set(configuration)!=CONFIG_FIELDS):
            raise ValueError('fixed admitted C private source reader/configuration required')
        public_payload(configuration)
        self.reader=reader;self.adapter=adapter;self.configuration=copy.deepcopy(configuration)
        self.qualification_sequence=qualification_sequence
    def admission_requirement(self,observation):
        """Static expected source contract, never qualification authority."""
        value=self.configuration
        from . import c_private_native_body_cut as body
        from . import c_private_fee_cut as fee
        expected={'architecture_profile':'direct_per_key','financial_pins':observation['financial_pins'],
          'configuration':value,'reader':{'command':list(self.reader.command),'evidence_directory':str(self.reader.evidence_directory),
            'timeout':self.reader.timeout,'request_stdin':True},
          'components':{'typed_adapter':digest(Path(__file__).read_bytes()),'shared_reader':module_hash(TargetTarReader.read),
            'stateless_loader':module_hash(native.decode_transport),'typed_loader':module_hash(native.load_target_tar),
            'body':module_hash(body._assemble),'fee':module_hash(fee._assemble),
            'protected_adapter':module_hash(self.adapter),'protected_frontier':module_hash(self.adapter.frontier())}}
        return expected
    def admission(self,store,observation):
        expected=self.admission_requirement(observation);value=self.configuration
        if type(self.reader)is not TargetTarReader or self.reader.loader is not native.decode_transport or self.reader.request_stdin is not True:
            raise ValueError('fixed original private transport/loader changed')
        if set(self.reader.__dict__)!={'command','evidence_directory','timeout','request_stdin','loader'}:
            raise ValueError('fixed reader state contains unadmitted override')
        event,proof=_source_event(store,self.qualification_sequence)
        if event['kind']!='c_normal_target_source_qualified'or proof!=expected:
            raise ValueError('actual fixed C target source/constructor qualification missing')
        if value['binding']['schema_sha256']!=observation['financial_pins']['schema_sha256']:
            raise ValueError('original target binding differs from actual execution schema')
        if value['limits']['deadline_ms']>25000 or not 0<self.reader.timeout<=25:
            raise ValueError('C existing protected target deadline cannot increase')
        return expected
    def begin(self,store,chain,observation):
        """Authenticate expected context BEFORE the one shared transport starts."""
        _context(store,observation);deadline_check()
        admitted=canonical(self.admission(store,observation))
        return {'admission':admitted,'observation':canonical(observation),
            'chain':self._identity(chain,observation),'started_at':time.time(),
            'monotonic_start':time.monotonic()}

    @staticmethod
    def _identity(chain,observation):
        value=chain.identity()
        from .model import SIGNET_GENESIS
        if(chain.call('getblockhash',0)!=SIGNET_GENESIS or value.get('chain')!='signet'or value.get('initialblockdownload')is not False
                or(value['blocks'],value['bestblockhash'])!=(observation['height'],observation['tip_hash'])):
            raise ValueError('actual independent C target chain differs')
        return {'genesis':SIGNET_GENESIS,'height':value['blocks'],'tip_hash':value['bestblockhash'],'ibd':False}

    def check_transport(self,store,chain,observation,transport,started):
        """Check an ALREADY captured original; never execute a second reader.

        `started` comes from begin() in the trusted capture, before transport;
        producer timestamps cannot substitute for that local lifecycle bracket.
        """
        _context(store,observation);deadline_check()
        if(not isinstance(started,dict)or set(started)!={'admission','observation','chain','started_at','monotonic_start'}
                or started['admission']!=canonical(self.admission(store,observation))
                or started['observation']!=canonical(observation)):
            raise ValueError('original C pre-transport context changed')
        before=started['chain'];began=started['started_at'];monotonic_start=started['monotonic_start']
        if(transport.get('kind')!='c-private-normal-transport-only'or transport.get('complete')is not False
                or transport.get('qualified')is not False or not callable(transport.get('producer_exit'))):
            raise ValueError('original actual private transport/terminal missing')
        cfg=self.configuration
        loaded=native.load_target_tar(transport['path'],expected_package_sha256=transport['archive_sha256'],
          expected_source_sha256=cfg['source_sha256'],expected_body_source_sha256=cfg['body_source_sha256'],
          expected_financial_pins=observation['financial_pins'],expected_observation=observation,expected_chain=before,
          expected_history_identity=cfg['history_identity'],expected_policy_sha256=cfg['policy_sha256'],
          adapter=self.adapter,limits=cfg['limits'],binding=cfg['binding'],producer_exit=transport['producer_exit'])
        completed=time.time();deadline_check()
        if(self._identity(chain,observation)!=before or canonical(self.admission(store,observation))!=started['admission'] or canonical(observation)!=started['observation']
                or not observation['started_at']<=began<=completed or completed-observation['started_at']>90
                or time.monotonic()-monotonic_start>self.configuration['limits']['deadline_ms']/1000):
            raise ValueError('C target source context/chain/admission changed')
        # These are actual caller clock cuts around the whole admitted process,
        # not producer-supplied timestamps or proof of hidden source authority.
        return {'kind':'c-checked-native-target-source','source_observation':copy.deepcopy(observation),
          'started_at':began,'completed_at':completed,'qualification_sequence':self.qualification_sequence,
          'qualified_constructor_sha256':digest(started['admission'].encode()),'loaded':loaded,
          'original_private_source_references':loaded['original_private_source_references'],
          'complete':False,'qualified':False,'financial_readiness':False}

    async def read(self,store,chain,observation):
        started=self.begin(store,chain,observation)
        transport=await self.reader.read(copy.deepcopy(observation))
        return self.check_transport(store,chain,observation,transport,started)
