"""Explicit installed normal collector factory; no observer-selected plugins."""
from .private_source_package import TargetTarReader
from .normal_member_source import MemberReader, bank_projection, ConfigCredential
from .public_wallet_metadata import wallet_metadata
from .scanned_public_wallets import scan_current
from .two_step_capture import SourceCapture
from .two_step_normal import Collector


def build_collector(store, *, admission_sequence, boundary, capture_configuration,
                    target_configuration, member_configuration, tools):
    target=TargetTarReader(target_configuration['command'],target_configuration['evidence_directory'],
        timeout=target_configuration['timeout'])
    member=MemberReader(member_configuration,store)
    capture=SourceCapture(target.read,member.read,admission_sequence,boundary,capture_configuration,
        dependencies={'public_wallet_metadata':wallet_metadata,'descriptor_scan':scan_current,
            'factory':build_collector})
    return Collector(capture.collect,admission_sequence,tools)
