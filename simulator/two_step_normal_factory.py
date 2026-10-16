"""Explicit installed normal collector factory; no observer-selected plugins."""
from .private_source_package import TargetTarReader
from .normal_member_source import MemberReader, bank_projection, ConfigCredential
from .public_wallet_metadata import wallet_metadata
from .descriptor_checkpoint import current_from_checkpoint
from .two_step_capture import SourceCapture
from .two_step_normal import Collector


def build_collector(store, *, admission_sequence, boundary, capture_configuration,
                    target_configuration, member_configuration, tools,
                    funding_configuration=None, wallet_root=None, architecture_profile=None):
    pending=tools.get('pending',{}).get('sha256')
    if member_configuration.get('pending_board_proof_sha256')!=pending:
        raise ValueError('pending Board framing must bind the exact installed admitted proof tool')
    native = None
    if architecture_profile is not None:
        from .b_continuing_profile import continuing_profile
        native = continuing_profile(store, architecture_profile, native_fee_tool=tools.get('native_fee'))
    target=TargetTarReader(target_configuration['command'],target_configuration['evidence_directory'],
        timeout=target_configuration['timeout'])
    member=MemberReader(member_configuration,store, native_profile=native)
    capture=SourceCapture(target.read,member.read,admission_sequence,boundary,capture_configuration,lineage_tools=tools,
        dependencies={'public_wallet_metadata':wallet_metadata,'descriptor_checkpoint':current_from_checkpoint,
            'factory':build_collector}, native_profile=native)
    funding=None
    if native is not None and funding_configuration is not None:
        raise ValueError("B profile owns its original monetary sources; A funding reader is not used")
    if funding_configuration is not None:
        if wallet_root is None:raise ValueError('original wallet root required for funding source isolation')
        from .normal_funding_reader import FundingReader
        funding=FundingReader(funding_configuration,wallet_root)
    return Collector(capture.collect,admission_sequence,tools,funding_reader=funding,native_profile=native)
