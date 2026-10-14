"""Security-focused detectors for AI agent monitoring."""

from .credentials import (
    CredentialAccessDetector,
    CredentialExfiltrationDetector,
    SecretInOutputDetector,
)
from .injection import (
    HiddenInstructionDetector,
    IndirectInjectionDetector,
    PromptInjectionDetector,
)
from .network import (
    C2CommunicationDetector,
    DataExfiltrationDetector,
    DNSExfiltrationDetector,
    NetworkAnomalyDetector,
    UndeclaredEgressDetector,
)
from .privilege import (
    DangerousCommandDetector,
    MassFileOperationDetector,
    PrivilegeEscalationDetector,
    SensitiveDirectoryAccessDetector,
)
from .secret_scanner import SecretLeakScanner
from .supply_chain import (
    MaliciousSkillDetector,
    NewSkillExecutionDetector,
    SkillChainDetector,
    SkillInstallDetector,
    SkillNetworkActivityDetector,
)

__all__ = [
    # Credential detectors
    "CredentialAccessDetector",
    "SecretInOutputDetector",
    "CredentialExfiltrationDetector",
    "SecretLeakScanner",
    # Injection detectors
    "PromptInjectionDetector",
    "HiddenInstructionDetector",
    "IndirectInjectionDetector",
    # Network detectors
    "NetworkAnomalyDetector",
    "DataExfiltrationDetector",
    "C2CommunicationDetector",
    "DNSExfiltrationDetector",
    "UndeclaredEgressDetector",
    # Privilege detectors
    "PrivilegeEscalationDetector",
    "DangerousCommandDetector",
    "MassFileOperationDetector",
    "SensitiveDirectoryAccessDetector",
    # Supply chain detectors
    "MaliciousSkillDetector",
    "SkillNetworkActivityDetector",
    "NewSkillExecutionDetector",
    "SkillChainDetector",
    "SkillInstallDetector",
]


def get_all_security_detectors():
    """Return instances of all security detectors with default settings."""
    return [
        # Credentials
        CredentialAccessDetector(),
        SecretInOutputDetector(),
        CredentialExfiltrationDetector(),
        SecretLeakScanner(),
        # Injection
        PromptInjectionDetector(),
        HiddenInstructionDetector(),
        IndirectInjectionDetector(),
        # Network
        NetworkAnomalyDetector(),
        DataExfiltrationDetector(),
        C2CommunicationDetector(),
        DNSExfiltrationDetector(),
        UndeclaredEgressDetector(),
        # Privilege
        PrivilegeEscalationDetector(),
        DangerousCommandDetector(),
        MassFileOperationDetector(),
        SensitiveDirectoryAccessDetector(),
        # Supply chain
        MaliciousSkillDetector(),
        SkillNetworkActivityDetector(),
        NewSkillExecutionDetector(),
        SkillChainDetector(),
        SkillInstallDetector(),
    ]
