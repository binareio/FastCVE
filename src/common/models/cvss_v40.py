# generated by datamodel-codegen:
#   filename:  cvss-v4.0.json (file downloaded from https://nvd.nist.gov/vuln-metrics/cvss/v4.0 and adjusted/fixed to match the actual DB attributes)
#   timestamp: 2025-01-01T09:20:50+00:00

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field, confloat, constr


class Version(Enum):
    field_4_0 = '4.0'


class AttackVectorType(Enum):
    NETWORK = 'NETWORK'
    ADJACENT = 'ADJACENT'
    LOCAL = 'LOCAL'
    PHYSICAL = 'PHYSICAL'


class ModifiedAttackVectorType(Enum):
    NETWORK = 'NETWORK'
    ADJACENT = 'ADJACENT'
    LOCAL = 'LOCAL'
    PHYSICAL = 'PHYSICAL'
    NOT_DEFINED = 'NOT_DEFINED'


class AttackComplexityType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'


class ModifiedAttackComplexityType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NOT_DEFINED = 'NOT_DEFINED'


class AttackRequirementsType(Enum):
    NONE = 'NONE'
    PRESENT = 'PRESENT'


class ModifiedAttackRequirementsType(Enum):
    NONE = 'NONE'
    PRESENT = 'PRESENT'
    NOT_DEFINED = 'NOT_DEFINED'


class PrivilegesRequiredType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NONE = 'NONE'


class ModifiedPrivilegesRequiredType(Enum):
    HIGH = 'HIGH'
    LOW = 'LOW'
    NONE = 'NONE'
    NOT_DEFINED = 'NOT_DEFINED'


class UserInteractionType(Enum):
    NONE = 'NONE'
    PASSIVE = 'PASSIVE'
    ACTIVE = 'ACTIVE'


class ModifiedUserInteractionType(Enum):
    NONE = 'NONE'
    PASSIVE = 'PASSIVE'
    ACTIVE = 'ACTIVE'
    NOT_DEFINED = 'NOT_DEFINED'


class VulnCiaType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'


class ModifiedVulnCiaType(Enum):
    NONE = 'NONE'
    LOW = 'LOW'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class ModifiedSubCType(Enum):
    NEGLIGIBLE = 'NEGLIGIBLE'
    LOW = 'LOW'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class ModifiedSubIaType(Enum):
    NEGLIGIBLE = 'NEGLIGIBLE'
    LOW = 'LOW'
    HIGH = 'HIGH'
    SAFETY = 'SAFETY'
    NOT_DEFINED = 'NOT_DEFINED'


class ExploitMaturityType(Enum):
    UNREPORTED = 'UNREPORTED'
    PROOF_OF_CONCEPT = 'PROOF_OF_CONCEPT'
    ATTACKED = 'ATTACKED'
    NOT_DEFINED = 'NOT_DEFINED'


class CiaRequirementType(Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class SafetyType(Enum):
    NEGLIGIBLE = 'NEGLIGIBLE'
    PRESENT = 'PRESENT'
    NOT_DEFINED = 'NOT_DEFINED'


class automatableType(Enum):
    NO = 'NO'
    YES = 'YES'
    NOT_DEFINED = 'NOT_DEFINED'


class RecoveryType(Enum):
    AUTOMATIC = 'AUTOMATIC'
    USER = 'USER'
    IRRECOVERABLE = 'IRRECOVERABLE'
    NOT_DEFINED = 'NOT_DEFINED'


class ValueDensityType(Enum):
    DIFFUSE = 'DIFFUSE'
    CONCENTRATED = 'CONCENTRATED'
    NOT_DEFINED = 'NOT_DEFINED'


class VulnerabilityResponseEffortType(Enum):
    LOW = 'LOW'
    MODERATE = 'MODERATE'
    HIGH = 'HIGH'
    NOT_DEFINED = 'NOT_DEFINED'


class ProviderUrgencyType(Enum):
    CLEAR = 'CLEAR'
    GREEN = 'GREEN'
    AMBER = 'AMBER'
    RED = 'RED'
    NOT_DEFINED = 'NOT_DEFINED'


class NoneScoreType(BaseModel):
    __root__: confloat(ge=0.0, le=0.0)


class LowScoreType(BaseModel):
    __root__: confloat(ge=0.1, le=3.9, multiple_of=0.1)


class MediumScoreType(BaseModel):
    __root__: confloat(ge=4.0, le=6.9, multiple_of=0.1)


class HighScoreType(BaseModel):
    __root__: confloat(ge=7.0, le=8.9, multiple_of=0.1)


class CriticalScoreType(BaseModel):
    __root__: confloat(ge=9.0, le=10.0, multiple_of=0.1)


class NoneSeverityType(BaseModel):
    __root__: Any = Field('NONE', const=True)


class LowSeverityType(BaseModel):
    __root__: Any = Field('LOW', const=True)


class MediumSeverityType(BaseModel):
    __root__: Any = Field('MEDIUM', const=True)


class HighSeverityType(BaseModel):
    __root__: Any = Field('HIGH', const=True)


class CriticalSeverityType(BaseModel):
    __root__: Any = Field('CRITICAL', const=True)


class CveCvssDataModel(BaseModel):
    baseScore: Union[
        NoneScoreType, LowScoreType, MediumScoreType, HighScoreType, CriticalScoreType
    ]
    baseSeverity: Union[
        NoneSeverityType,
        LowSeverityType,
        MediumSeverityType,
        HighSeverityType,
        CriticalSeverityType,
    ]
    threatScore: Optional[
        Union[
            NoneScoreType,
            LowScoreType,
            MediumScoreType,
            HighScoreType,
            CriticalScoreType,
        ]
    ] = None
    threatSeverity: Optional[
        Union[
            NoneSeverityType,
            LowSeverityType,
            MediumSeverityType,
            HighSeverityType,
            CriticalSeverityType,
        ]
    ] = None
    version: Version = Field(..., description='CVSS Version')
    vectorString: constr(
        regex=r'^CVSS:4[.]0(/AV:[NALP]|/AC:[LH]|/AT:[NP]|/PR:[NLH]|/UI:[NPA]|/VC:[HLN]|/VI:[HLN]|/VA:[HLN]|/SC:[HLN]|/SI:[HLN]|/SA:[HLN]|/E:[XAPU]|/CR:[XHML]|/IR:[XHML]|/AR:[XHML]|/MAV:[XNALP]|/MAC:[XLH]|/MAT:[XNP]|/MPR:[XNLH]|/MUI:[XNPA]|/MVC:[XNLH]|/MVI:[XNLH]|/MVA:[XNLH]|/MSC:[XNLH]|/MSI:[XNLHS]|/MSA:[XNLHS]|/S:[XNP]|/AU:[XNY]|/R:[XAUI]|/V:[XDC]|/RE:[XLMH]|/U:(X|Clear|Green|Amber|Red))*$'
    )
    attackVector: Optional[AttackVectorType] = None
    attackComplexity: Optional[AttackComplexityType] = None
    attackRequirements: Optional[AttackRequirementsType] = None
    privilegesRequired: Optional[PrivilegesRequiredType] = None
    userInteraction: Optional[UserInteractionType] = None
    vulnerableSystemConfidentiality: Optional[VulnCiaType] = None
    vulnerableSystemIntegrity: Optional[VulnCiaType] = None
    vulnerableSystemAvailability: Optional[VulnCiaType] = None
    subsequentSystemConfidentiality: Optional[VulnCiaType] = None
    subsequentSystemIntegrity: Optional[VulnCiaType] = None
    subsequentSystemAvailability: Optional[VulnCiaType] = None
    exploitMaturity: Optional[ExploitMaturityType] = 'NOT_DEFINED'
    confidentialityRequirements: Optional[CiaRequirementType] = 'NOT_DEFINED'
    integrityRequirements: Optional[CiaRequirementType] = 'NOT_DEFINED'
    availabilityRequirements: Optional[CiaRequirementType] = 'NOT_DEFINED'
    modifiedAttackVector: Optional[ModifiedAttackVectorType] = 'NOT_DEFINED'
    modifiedAttackComplexity: Optional[ModifiedAttackComplexityType] = 'NOT_DEFINED'
    modifiedAttackRequirements: Optional[ModifiedAttackRequirementsType] = 'NOT_DEFINED'
    modifiedPrivilegesRequired: Optional[ModifiedPrivilegesRequiredType] = 'NOT_DEFINED'
    modifiedUserInteraction: Optional[ModifiedUserInteractionType] = 'NOT_DEFINED'
    modifiedVulnerableSystemConfidentiality: Optional[ModifiedVulnCiaType] = 'NOT_DEFINED'
    modifiedVulnerableSystemIntegrity: Optional[ModifiedVulnCiaType] = 'NOT_DEFINED'
    modifiedVulnerableSystemAvailability: Optional[ModifiedVulnCiaType] = 'NOT_DEFINED'
    modifiedSubsequentSystemConfidentiality: Optional[ModifiedSubCType] = 'NOT_DEFINED'
    modifiedSubsequentSystemIntegrity: Optional[ModifiedSubIaType] = 'NOT_DEFINED'
    modifiedSubsequentSystemAvailability: Optional[ModifiedSubIaType] = 'NOT_DEFINED'
    safety: Optional[SafetyType] = 'NOT_DEFINED'
    automatable: Optional[automatableType] = 'NOT_DEFINED'
    recovery: Optional[RecoveryType] = 'NOT_DEFINED'
    valueDensity: Optional[ValueDensityType] = 'NOT_DEFINED'
    vulnerabilityResponseEffort: Optional[
        VulnerabilityResponseEffortType
    ] = 'NOT_DEFINED'
    providerUrgency: Optional[ProviderUrgencyType] = 'NOT_DEFINED'
