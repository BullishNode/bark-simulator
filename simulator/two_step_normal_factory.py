"""Explicit installed normal collector factory; no observer-selected plugins."""
from .private_source_package import TargetTarReader
from .normal_member_source import MemberReader, bank_projection, ConfigCredential
from .public_wallet_metadata import wallet_metadata
from .descriptor_checkpoint import current_from_checkpoint
from .two_step_capture import SourceCapture
from .two_step_normal import Collector


def build_collector(store, *, admission_sequence, boundary, capture_configuration,
                    target_configuration, member_configuration, tools, architecture_profile=None):
    native = None
    if architecture_profile is not None:
        from .b_normal_profile_adapter import initial_profile
        native = initial_profile(store, architecture_profile)
    target=TargetTarReader(target_configuration['command'],target_configuration['evidence_directory'],
        timeout=target_configuration['timeout'])
    member=MemberReader(member_configuration,store, native_profile=native)
    capture=SourceCapture(target.read,member.read,admission_sequence,boundary,capture_configuration,
        dependencies={'public_wallet_metadata':wallet_metadata,'descriptor_checkpoint':current_from_checkpoint,
            'factory':build_collector}, native_profile=native)
    return Collector(capture.collect,admission_sequence,tools,native_profile=native)
