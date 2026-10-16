"""Explicit installed A normal profile; never declares or activates finances."""
import hashlib
import os
from pathlib import Path

from .architecture import TWO_STEP, profile as campaign_profile
from .final_campaign import _pins, _source_event, epoch
from .financial_transition import recorded
from .funding import plan
from .model import SIGNET_GENESIS, canonical, integer, public_payload
from .normal_member_source import private_file
from .operating_limits import envelope
from .treasury import boundary, _members
from .target_epochs import active_identity
from .two_step_normal import digest

FIELDS={'schema_version','architecture_profile','financial_pins','admission_sequence',
        'boundary_sha256','envelope_sha256','opening_sha256','funding_plan_sha256','target_epoch_id',
        'capture_configuration','target_configuration','member_configuration','tools','funding_configuration'}


def collector_from_profile(config,store):
    """Load a hash-pinned static factory and verify original declarations.

    This installs an in-process dependency only. No subprocess, chain call,
    Wallet, Store event, metadata, epoch, budget or dispatch is changed here.
    The Engine still creates a new nonce and independently verifies full fresh
    evidence on every observation under the existing aggregate deadline.
    """
    from .two_step_normal import strict_json
    path=Path(config.normal_source_profile)
    if (path!=Path(os.path.abspath(path))or path==config.wallet_root or config.wallet_root in path.parents
            or any(p.is_symlink()for p in (path,*path.parents))):
        raise ValueError('normal profile must be outside wallets and unaliased')
    raw=private_file(path,128*1024)
    if digest(raw)!=config.normal_source_profile_sha256:
        raise ValueError('installed normal source profile hash differs')
    value=strict_json(raw);public_payload(value)
    if (not isinstance(value,dict)or set(value)!=FIELDS or type(value['schema_version'])is not int
            or value['schema_version']!=1 or value['architecture_profile']!=TWO_STEP
            or config.architecture_profile!=TWO_STEP or campaign_profile(store)!=TWO_STEP):
        raise ValueError('explicit A normal source profile required')
    store.verify_event_chain();pins=_pins(value['financial_pins'])
    if pins['sdk_commit']!=config.expected_sdk_commit:
        raise ValueError('normal source profile SDK differs from actual runtime configuration')
    if len(config.driver_command)!=1:raise ValueError('one actual pinned native driver required')
    driver=Path(config.driver_command[0])
    if (not driver.is_absolute()or driver.is_symlink()or not driver.is_file()
            or not os.access(driver,os.X_OK)or driver.stat().st_size>128*1024*1024):
        raise ValueError('actual normal driver executable unavailable')
    with driver.open('rb')as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=pins['driver_sha256']:
            raise ValueError('actual normal driver differs from immutable source pins')
    original_boundary=boundary(store);limits=envelope(store,config);opening=recorded(store);final=epoch(store)
    if (opening is None or final is None or final['pins']!=pins or original_boundary['pins']!=pins
            or limits['pins']!=pins or limits['boundary_id']!=original_boundary['id']
            or digest(canonical(original_boundary).encode())!=value['boundary_sha256']
            or digest(canonical(limits).encode())!=value['envelope_sha256']
            or digest(canonical(opening).encode())!=value['opening_sha256']
            or opening['declaration']['target_epoch_id']!=value['target_epoch_id']):
        raise ValueError('normal source profile requires exact admitted opening/boundary/envelope/epoch')
    funding=plan(store)
    if (digest(canonical(funding).encode())!=value['funding_plan_sha256']
            or funding['initial_clients']!=12 or funding['ramp_clients']!=12
            or integer(funding['grant_sat'],'actual declared grant',1)!=limits['grant_sat']
            or 24*funding['grant_sat']>integer(funding['maximum_total_principal_sat'],'declared client principal cap',1)
            or 2*integer(funding['batch_maximum_fee_sat'],'declared batch fee cap',1)>integer(funding['maximum_total_fee_sat'],'declared bank fee cap',1)):
        raise ValueError('actual immutable funding plan/grants differ from financial envelope')
    deployments=store.db.execute("SELECT sequence FROM event WHERE kind='target_epoch_declared' ORDER BY sequence DESC LIMIT 1").fetchall()
    if len(deployments)!=1:raise ValueError('actual target deployment epoch required')
    _,deployed=_source_event(store,deployments[0][0]);identity=deployed['identity']
    if (deployed['id']!=value['target_epoch_id']or deployed['sdk_commit']!=pins['sdk_commit']
            or deployed['native_hashes']['bark-sim-driver']!=pins['driver_sha256']
            or active_identity(store)!=identity
            or identity!={'network':config.network,'genesis':config.expected_genesis,'container':config.expected_container,
                'image_digest':config.expected_image,'server_pubkey':config.expected_server_pubkey}):
        raise ValueError('normal profile runtime differs from actual admitted deployment')
    members=_members(original_boundary)
    for member in members.values():
        event,proof=_source_event(store,member['verification_sequence'])
        if (event['kind']!='treasury_member_verified'or proof.get('member')!={k:v for k,v in member.items()if k!='verification_sequence'}
                or proof.get('financial_pins')!=pins or proof.get('genesis')!=SIGNET_GENESIS):
            raise ValueError('original role/descriptor member registration differs')
    member_configuration=value['member_configuration'];mapping=member_configuration['actor_member_ids']
    if (set(mapping)!={f'actor-{n:02}'for n in range(1,25)}or len(set(mapping.values()))!=24
            or any(name not in members or members[name]['kind']!='wallet'or members[name]['role']!='customer'for name in mapping.values())
            or value['capture_configuration']['actor_member_ids']!=mapping):
        raise ValueError('preserved initial and dormant future member identities must remain complete')
    if Path(member_configuration['wallet_root'])!=config.wallet_root:
        raise ValueError('member source must retain the actual original wallet root')
    directories=[Path(value['target_configuration']['evidence_directory']),Path(member_configuration['evidence_root']),
        Path(member_configuration['helper_evidence_root'])]
    if len(set(directories))!=3:raise ValueError('separate target/member/helper evidence roots required')
    for directory in directories:
        if (not directory.is_absolute()or directory!=Path(os.path.abspath(directory))
                or any(p.is_symlink()for p in (directory,*directory.parents))or not directory.is_dir()
                or directory.stat().st_uid!=os.getuid()or directory.stat().st_mode&0o077
                or directory==config.wallet_root or config.wallet_root in directory.parents):
            raise ValueError('private normal evidence roots must remain outside wallet directories')
    sequence=integer(value['admission_sequence'],'source qualification sequence',1)
    event,admitted=_source_event(store,sequence)
    if (event['kind']!='normal_financial_collector_qualified'or admitted['financial_pins']!=pins
            or admitted.get('proof_schema_versions',{}).get('pending')!=2
            or set(value['tools'])!={'policy','binding','pending'}):
        raise ValueError('actual admitted schema2 pending/Full/per-key tool set required')
    for name,tool in value['tools'].items():
        if set(tool)!={'command','sha256','evidence_directory'}or not isinstance(tool['command'],list)or len(tool['command'])!=1:
            raise ValueError('one fixed admitted pure proof executable required')
        binary=Path(tool['command'][0]);evidence=Path(tool['evidence_directory'])
        if (not binary.is_absolute()or binary.is_symlink()or not binary.is_file()or not os.access(binary,os.X_OK)
                or binary.stat().st_size>128*1024*1024 or not evidence.is_absolute()
                or evidence!=Path(os.path.abspath(evidence))or any(p.is_symlink()for p in (evidence,*evidence.parents))or not evidence.is_dir()
                or evidence.stat().st_mode&0o077 or evidence.stat().st_uid!=os.getuid()
                or config.wallet_root in evidence.parents or evidence==config.wallet_root):
            raise ValueError('actual proof tool/private evidence path differs')
        with binary.open('rb')as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=tool['sha256']:
                raise ValueError('actual proof executable hash differs')
    from .two_step_normal_factory import build_collector
    collector=build_collector(store,admission_sequence=sequence,boundary=original_boundary,
        capture_configuration=value['capture_configuration'],target_configuration=value['target_configuration'],
        member_configuration=member_configuration,tools=value['tools'],funding_configuration=value['funding_configuration'],
        wallet_root=config.wallet_root)
    collector.admission(store,pins)
    collector.capture.__self__.admission(store,{'financial_pins':pins})
    if collector.funding_reader.configuration!=value['funding_configuration']:
        raise ValueError('actual fixed funding reader configuration differs')
    # Validate bounded original membership now; independent ownership/Core joins
    # still execute again for each fresh observation, never reuse this as ready.
    collector.funding_reader.read(store,original_boundary)
    store.verify_event_chain()
    return collector
