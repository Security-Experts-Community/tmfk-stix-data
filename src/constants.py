from pathlib import Path
from enum import Enum

TMFK_PATH = Path(__file__).parent.parent / "ms-matrix" / "Threat-Matrix-for-Kubernetes"

TACTICS_PATH = TMFK_PATH / "docs" / "tactics"
TECHNIQUES_PATH = TMFK_PATH / "docs" / "techniques"
MITIGATIONS_PATH = TMFK_PATH / "docs" / "mitigations"

TMFK_TACTICS_MAP = {
    "InitialAccess": "MS-T0100",
    "Execution": "MS-T0200",
    "Persistence": "MS-T0300",   
    "PrivilegeEscalation": "MS-T0400",
    "DefenseEvasion": "MS-T0500",    
    "CredentialAccess": "MS-T0600",
    "Discovery":"MS-T0700",   
    "LateralMovement":"MS-T0800",
    "Collection": "MS-T0900",      
    "Impact": "MS-T1000",
}

TMFK_VERSION = "0.1"
ATTACK_SPEC_VERSION = "2.1.0"
TMFK_PLATFORM = "Kubernetes"

class Mode(Enum):
    strict = 1
    attack_compatible = 2
    
# DEFAULT_MODE = Mode.strict
DEFAULT_MODE = Mode.attack_compatible

def GET_TMFK_DOMAIN(mode=DEFAULT_MODE):
    match mode:
        case Mode.strict: 
            return "tmfk"
        case Mode.attack_compatible: 
            return "enterprise-attack"
        case _: 
            raise Exception("Unexpected mode")

def GET_TMFK_SOURCE(mode=DEFAULT_MODE):
    match mode:
        case Mode.strict: 
            return "tmfk"
        case Mode.attack_compatible: 
            return "mitre-attack"
        case _: 
            raise Exception("Unexpected mode")

def GET_KILL_CHAIN_NAME(mode=DEFAULT_MODE):
    match mode:
        case Mode.strict: 
            return "tmfk"
        case Mode.attack_compatible: 
            return "mitre-attack"
        case _: 
            raise Exception("Unexpected mode")

CREATOR_IDENTITY = "identity--5dcf0a7a-875b-470b-8a01-7c6a84c5e68e"
DEFAULT_CREATOR_JSON = f"""
{{
    "id": "{CREATOR_IDENTITY}",
    "type": "identity",
    "identity_class": "organization",
    "created": "2024-02-05T14:00:00.188Z",
    "modified": "2024-02-05T14:00:00.188Z",
    "name": "aw350m33d (Security Experts Community)",
    "spec_version": "2.1",
    "x_mitre_attack_spec_version": "2.1.0",
    "x_mitre_domains": [
        "{GET_TMFK_DOMAIN()}"
    ],
    "x_mitre_version": "{TMFK_VERSION}"
}}
"""