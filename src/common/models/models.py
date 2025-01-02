"""
Pydantic Datamodel for the Binare Vulnerability's search input options

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""

from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, root_validator, validator
from pydantic.error_wrappers import ErrorWrapper, ValidationError
from datetime import date, timedelta
import re

from common.models.cvss_v2 import (
    AccessVectorType as AccessVectorTypeV2,
    AccessComplexityType as AccessComplexityTypeV2,
    AuthenticationType as AuthenticationTypeV2,
    CiaType as CiaTypeV2,
    ExploitabilityType as ExploitabilityTypeV2,
    RemediationLevelType as RemediationLevelTypeV2,
    ReportConfidenceType as ReportConfidenceTypeV2,
    CollateralDamagePotentialType as CollateralDamagePotentialTypeV2,
    TargetDistributionType as TargetDistributionTypeV2,
    CiaRequirementType as CiaRequirementTypeV2,
    CveCvssDataModel as CveCvssV2,
)
from common.models.cvss_v31 import (
    AttackVectorType as AttackVectorTypeV31,
    AttackComplexityType as AttackComplexityTypeV31,
    PrivilegesRequiredType as PrivilegesRequiredTypeV31,
    UserInteractionType as UserInteractionTypeV31,
    ScopeType as ScopeTypeV31,
    CiaType as CiaTypeV31,
    ExploitCodeMaturityType as ExploitCodeMaturityTypeV31,
    RemediationLevelType as RemediationLevelTypeV31,
    ConfidenceType as ConfidenceTypeV31,
    CiaRequirementType as CiaRequirementTypeV31,
    CveCvssDataModel as CveCvssV31,
)
from common.models.cvss_v40 import (
    AttackVectorType as AttackVectorTypeV40,
    AttackComplexityType as AttackComplexityTypeV40,
    AttackRequirementsType as AttackRequirementsTypeV40,
    PrivilegesRequiredType as PrivilegesRequiredTypeV40,
    UserInteractionType as UserInteractionTypeV40,
    VulnCiaType as VulnCiaTypeV40,
    ModifiedAttackVectorType as ModifiedAttackVectorTypeV40,
    ModifiedAttackComplexityType as ModifiedAttackComplexityTypeV40,
    ModifiedAttackRequirementsType as ModifiedAttackRequirementsTypeV40,
    ModifiedPrivilegesRequiredType as ModifiedPrivilegesRequiredTypeV40,
    ModifiedUserInteractionType as ModifiedUserInteractionTypeV40,
    ModifiedVulnCiaType as ModifiedVulnCiaTypeV40,
    ModifiedSubCType as ModifiedSubCTypeV40,
    ModifiedSubIaType as ModifiedSubIaTypeV40,
    ExploitMaturityType as ExploitMaturityTypeV40,
    CiaRequirementType as CiaRequirementTypeV40,
    SafetyType as SafetyTypeV40,
    automatableType as AutomatableTypeV40,
    RecoveryType as RecoveryTypeV40,
    ValueDensityType as ValueDensityTypeV40,
    VulnerabilityResponseEffortType as VulnerabilityResponseEffortTypeV40,
    ProviderUrgencyType as ProviderUrgencyTypeV40,
    CveCvssDataModel as CveCvssV40,
)

from common.models.cvss_v30 import CveCvssDataModel as CveCvssV30


CPE23_REGEX_STR: str = 'cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&\'\(\)\+,\/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){3,5}(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&\'\(\)\+,\/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){0,5}'


class SearchInfoType(str, Enum):
    cve = "cve"
    cwe = "cwe"
    cpe = "cpe"
    capec = "capec"
    status = "status"


class CveSeverityV2(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class CveSeverityV3(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class CveSeverityV4(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class OutputType(str, Enum):
    id = "id"
    json = "json"


class SearchOptions(BaseModel):
    """Search Options"""

    searchInfo: SearchInfoType = Field(description="the type of information to search for", alias="search-info")
    keywordSearch: Optional[List[str]] = Field(default=None, description="regexp to search for CVE/CPE/CWE/CAPEC in the title/name/summary", cli=('-k', '--keyword'), alias="keyword")
    cpeName: Optional[str] = Field(default=None, description="CPE2.3 filter specification to search for", alias="cpe23")
    cveId: Optional[List[str]] = Field(default=None, description="CVE IDs to search for", alias="cve")
    cweId: Optional[List[str]] = Field(default=None, description="Related CWE IDs to search for", alias="cwe")
    capecId: Optional[List[str]] = Field(default=None, description="Related CAPEC IDs to search for", alias="capec")
    cvssV2Metrics: Optional[str] = Field(default=None, description="CVSS V2.0 vector string to search for", alias="cvss-metrics-v2")
    cvssV3Metrics: Optional[str] = Field(default=None, description="CVSS V3.x vector string to search for", alias="cvss-metrics-v3")
    cvssV4Metrics: Optional[str] = Field(default=None, description="CVSS V4.0 vector string to search for", alias="cvss-metrics-v4")
    cvssV2Severity: Optional[CveSeverityV2] = Field(default=None, description="CVSS V2.0 Severity to search for", alias="cvss-severity-v2")
    cvssV3Severity: Optional[CveSeverityV3] = Field(default=None, description="CVSS V3.x Severity to search", alias="cvss-severity-v3")
    cvssV4Severity: Optional[CveSeverityV4] = Field(default=None, description="CVSS V4.0 Severity to search", alias="cvss-severity-v4")
    epssScoreGt: Optional[float] = Field(default=None, description="Filter by EPSS score greater than", alias="epss-score-gt", ge=0)   # New field for EPSS score greater than
    epssScoreLt: Optional[float] = Field(default=None, description="Filter by EPSS score less than", alias="epss-score-lt", ge=0)  # New field for EPSS score less than
    epssPercGt: Optional[float] = Field(default=None, description="Filter by EPSS percentile greater than", alias="epss-perc-gt", ge=0)  # New field for EPSS percentile greater than
    epssPercLt: Optional[float] = Field(default=None, description="Filter by EPSS percentile less than", alias="epss-perc-lt", ge=0) # New field for EPSS percentile less than
    exploitable: Optional[bool] = Field(default=False, description="If true, will fetch cve with kev info")
    lastModStartDate: Optional[date] = Field(default=None, description="Last modified start date", alias="last-mod-start-date")
    lastModEndDate: Optional[date] = Field(default=None, description="Last modified end date", alias="last-mod-end-date")
    pubStartDate: Optional[date] = Field(default=None, description="CVE Published start date", alias="pub-start-date")
    pubEndDate: Optional[date] = Field(default=None, description="CVE Published start date", alias="pub-end-date")
    vulnerable: Optional[bool] = Field(default=True, description="CVE found by the CPEs that are marked as vulnerable", alias="vulnerable")
    pageSize: Optional[int] = Field(description="Number of results per page", default=100, alias="page-size", ge=10, le=3000)
    pageIdx: Optional[int] = Field(default=0, description="Starting index", alias="page-idx", ge=0)
    days: Optional[int] = Field(default=None, description="Number of days back when the CVEs were last modified", alias="days-back", ge=0)
    deprecated: Optional[bool] = Field(default=False, description="If set to true, will fetch only the deprecated CPE names", alias="deprecated")
    profile: Optional[bool] = Field(default=None, description="Would also run the profile execution of the search and save the results in a file")
    output: OutputType = Field(default=OutputType.json, description="Define the output format")

    class Config:
        allow_population_by_field_name = True

    @validator('cpeName', pre=True)
    def validate_cpe_name(cls, value):
        """Validate CPE2.3 filter specification"""

        if value and not re.match(CPE23_REGEX_STR, value):
            exc = ValueError(f"Invalid CPE name: {value}")
            raise ValidationError([ErrorWrapper(exc, loc=cls.__fields__['cpeName'].alias)], cls)
        return value

    @root_validator()
    def validate_mandatory_fields(cls, inst):
        """Implement the root validator"""

        # Validate input parameters in case of search-info set as CVE
        if inst.get('searchInfo', None) in (SearchInfoType.cve, SearchInfoType.cpe):
            if inst['lastModStartDate'] and inst['lastModEndDate'] and inst['lastModStartDate'] > inst['lastModEndDate']:
                exc = ValueError('Last modified start date must be before last modified end date')
                raise ValidationError([ErrorWrapper(exc, loc=cls.__fields__['lastModStartDate'].alias)], cls)
            if inst['pubStartDate'] and inst['pubEndDate'] and inst['pubStartDate'] > inst['pubEndDate']:
                exc = ValueError('CVE Published start date must be before CVE Published end date')
                raise ValidationError([ErrorWrapper(exc, loc=cls.__fields__['pubStartDate'].alias)], cls)

        if inst.get('searchInfo', None) in (SearchInfoType.cwe, SearchInfoType.cve, SearchInfoType.capec) and inst['deprecated'] == True:
            exc = ValueError('deperecated attribute cannot be used with searchInfo=cve, cwe, or capec')
            raise ValidationError([ErrorWrapper(exc, loc=cls.__fields__['deprecated'].alias)], cls)

        # transfer the days into lastModStartDate
        if inst.get('days', None):
            if inst.get('lastModStartDate', None):
                exc = ValueError('Either days or lastModStartDate must be set')
                raise ValidationError([ErrorWrapper(exc, loc=cls.__fields__['deprecated'].alias)], cls)
            else:
                inst['lastModStartDate'] = date.today() - timedelta(days=inst['days'])
                inst['days'] = None

        return inst


metrics_mapping: dict = dict(
    # -------------------------------------------------------------------------
    V2=dict(
        regex=CveCvssV2.__fields__['vectorString'].type_.regex,

        AV=dict(json_dict='[{"cvssData":{"accessVector":"{value}"}}]',
            N=AccessVectorTypeV2.NETWORK, A=AccessVectorTypeV2.ADJACENT_NETWORK,
            L=AccessVectorTypeV2.LOCAL),

        AC=dict(json_dict='[{"cvssData":{"accessComplexity":"{value}"}}]',
            H=AccessComplexityTypeV2.HIGH, M=AccessComplexityTypeV2.MEDIUM, L=AccessComplexityTypeV2.LOW),

        Au=dict(json_dict='[{"cvssData":{"authentication":"{value}"}}]',
            M=AuthenticationTypeV2.MULTIPLE, S=AuthenticationTypeV2.SINGLE, N=AuthenticationTypeV2.NONE),

        C=dict(json_dict='[{"cvssData":{"confidentialityImpact":"{value}"}}]',
            C=CiaTypeV2.COMPLETE, P=CiaTypeV2.PARTIAL, N=CiaTypeV2.NONE),

        I=dict(json_dict='[{"cvssData":{"integrityImpact":"{value}"}}]',
            C=CiaTypeV2.COMPLETE, P=CiaTypeV2.PARTIAL, N=CiaTypeV2.NONE),

        A=dict(json_dict='[{"cvssData":{"availabilityImpact":"{value}"}}]',
            C=CiaTypeV2.COMPLETE, P=CiaTypeV2.PARTIAL, N=CiaTypeV2.NONE),

        E=dict(json_dict='[{"cvssData":{"exploitability":"{value}"}}]',
            U=ExploitabilityTypeV2.UNPROVEN, POC=ExploitabilityTypeV2.PROOF_OF_CONCEPT,
            H=ExploitabilityTypeV2.HIGH, F=ExploitabilityTypeV2.FUNCTIONAL,
            ND=ExploitabilityTypeV2.NOT_DEFINED),

        RL=dict(json_dict='[{"cvssData":{"remediationLevel":"{value}"}}]',
            OF=RemediationLevelTypeV2.OFFICIAL_FIX, TF=RemediationLevelTypeV2.TEMPORARY_FIX,
            U=RemediationLevelTypeV2.UNAVAILABLE, W=RemediationLevelTypeV2.WORKAROUND,
            ND=RemediationLevelTypeV2.NOT_DEFINED),

        RC=dict(json_dict='[{"cvssData":{"reportConfidence":"{value}"}}]',
            UC=ReportConfidenceTypeV2.UNCONFIRMED, UR=ReportConfidenceTypeV2.UNCORROBORATED,
            C=ReportConfidenceTypeV2.CONFIRMED, ND=ReportConfidenceTypeV2.NOT_DEFINED),

        CDP=dict(json_dict='[{"cvssData":{"collateralDamagePotential":"{value}"}}]',
            N=CollateralDamagePotentialTypeV2.NONE, L=CollateralDamagePotentialTypeV2.LOW,
            LM=CollateralDamagePotentialTypeV2.LOW_MEDIUM, MH=CollateralDamagePotentialTypeV2.MEDIUM_HIGH,
            H=CollateralDamagePotentialTypeV2.HIGH, ND=CollateralDamagePotentialTypeV2.NOT_DEFINED),

        TD=dict(json_dict='[{"cvssData":{"targetDistribution":"{value}"}}]',
            N=TargetDistributionTypeV2.NONE, L=TargetDistributionTypeV2.LOW,
            H=TargetDistributionTypeV2.HIGH, ND=TargetDistributionTypeV2.NOT_DEFINED),

        CR=dict(json_dict='[{"cvssData":{"confidentialityRequirements":"{value}"}}]',
            L=CiaRequirementTypeV2.LOW, M=CiaRequirementTypeV2.MEDIUM,
            H=CiaRequirementTypeV2.HIGH, ND=CiaRequirementTypeV2.NOT_DEFINED),

        IR=dict(json_dict='[{"cvssData":{"integrityRequirements":"{value}"}}]',
            L=CiaRequirementTypeV2.LOW, M=CiaRequirementTypeV2.MEDIUM,
            H=CiaRequirementTypeV2.HIGH, ND=CiaRequirementTypeV2.NOT_DEFINED),

        AR=dict(json_dict='[{"cvssData":{"availabilityRequirements":"{value}"}}]',
            L=CiaRequirementTypeV2.LOW, M=CiaRequirementTypeV2.MEDIUM,
            H=CiaRequirementTypeV2.HIGH, ND=CiaRequirementTypeV2.NOT_DEFINED)
    ),
    # -------------------------------------------------------------------------
    V31 = dict(
        regex=CveCvssV31.__fields__['vectorString'].type_.regex,
        AV=dict(
            json_dict='[{"cvssData":{"attackVector":"{value}"}}]',
            N=AttackVectorTypeV31.NETWORK, A=AttackVectorTypeV31.ADJACENT_NETWORK,
            L=AttackVectorTypeV31.LOCAL, P=AttackVectorTypeV31.PHYSICAL),

        AC=dict(json_dict='[{"cvssData":{"attackComplexity":"{value}"}}]',
            L=AttackComplexityTypeV31.LOW, H=AttackComplexityTypeV31.HIGH),

        PR=dict(json_dict='[{"cvssData":{"privilegesRequired":"{value}"}}]',
            N=PrivilegesRequiredTypeV31.NONE, L=PrivilegesRequiredTypeV31.LOW,
            H=PrivilegesRequiredTypeV31.HIGH),

        UI=dict(json_dict='[{"cvssData":{"userInteraction":"{value}"}}]',
            N=UserInteractionTypeV31.NONE, L=UserInteractionTypeV31.REQUIRED),

        S=dict(json_dict='[{"cvssData":{"scope":"{value}"}}]',
            U=ScopeTypeV31.UNCHANGED, C=ScopeTypeV31.CHANGED),

        C=dict(json_dict='[{"cvssData":{"confidentialityImpact":"{value}"}}]',
            H=CiaTypeV31.HIGH, P=CiaTypeV31.LOW, N=CiaTypeV31.NONE),

        I=dict(json_dict='[{"cvssData":{"integrityImpact":"{value}"}}]',
            H=CiaTypeV31.HIGH, P=CiaTypeV31.LOW, N=CiaTypeV31.NONE),

        A=dict(json_dict='[{"cvssData":{"availabilityImpact":"{value}"}}]',
            H=CiaTypeV31.HIGH, P=CiaTypeV31.LOW, N=CiaTypeV31.NONE),

        E=dict(json_dict='[{"cvssData":{"exploitCodeMaturity":"{value}"}}]',
            X=ExploitCodeMaturityTypeV31.NOT_DEFINED, U=ExploitCodeMaturityTypeV31.UNPROVEN,
            H=ExploitCodeMaturityTypeV31.HIGH, F=ExploitCodeMaturityTypeV31.FUNCTIONAL,
            P=ExploitCodeMaturityTypeV31.PROOF_OF_CONCEPT),

        RL=dict(json_dict='[{"cvssData":{"remediationLevel":"{value}"}}]',
            U=RemediationLevelTypeV31.UNAVAILABLE, X=RemediationLevelTypeV31.NOT_DEFINED,
            W=RemediationLevelTypeV31.WORKAROUND, T=RemediationLevelTypeV31.TEMPORARY_FIX,
            O=RemediationLevelTypeV31.OFFICIAL_FIX),

        RC=dict(json_dict='[{"cvssData":{"reportConfidence":"{value}"}}]',
            X=ConfidenceTypeV31.NOT_DEFINED, C=ConfidenceTypeV31.CONFIRMED,
            R=ConfidenceTypeV31.REASONABLE, U=ConfidenceTypeV31.UNKNOWN),

        CR=dict(json_dict='[{"cvssData":{"confidentialityRequirements":"{value}"}}]',
            X=CiaRequirementTypeV31.NOT_DEFINED, L=CiaRequirementTypeV31.LOW,
            M=CiaRequirementTypeV31.MEDIUM, H=CiaRequirementTypeV31.HIGH),

        IR=dict(json_dict='[{"cvssData":{"integrityRequirements":"{value}"}}]',
            X=CiaRequirementTypeV31.NOT_DEFINED, L=CiaRequirementTypeV31.LOW,
            M=CiaRequirementTypeV31.MEDIUM, H=CiaRequirementTypeV31.HIGH),

        AR=dict(json_dict='[{"cvssData":{"availabilityRequirements":"{value}"}}]',
            X=CiaRequirementTypeV31.NOT_DEFINED, L=CiaRequirementTypeV31.LOW,
            M=CiaRequirementTypeV31.MEDIUM, H=CiaRequirementTypeV31.HIGH),
    ),
    # -------------------------------------------------------------------------
    V40 = dict(
        # Regex reference from the vectorString in the CveCvssV40 model
        regex=CveCvssV40.__fields__['vectorString'].type_.regex,

        AV=dict(
            json_dict='[{"cvssData":{"attackVector":"{value}"}}]',
            N=AttackVectorTypeV40.NETWORK, A=AttackVectorTypeV40.ADJACENT,
            L=AttackVectorTypeV40.LOCAL, P=AttackVectorTypeV40.PHYSICAL,
        ),

        AC=dict(
            json_dict='[{"cvssData":{"attackComplexity":"{value}"}}]',
            L=AttackComplexityTypeV40.LOW, H=AttackComplexityTypeV40.HIGH,
        ),

        AT=dict(
            json_dict='[{"cvssData":{"attackRequirements":"{value}"}}]',
            N=AttackRequirementsTypeV40.NONE, P=AttackRequirementsTypeV40.PRESENT,
        ),

        PR=dict(
            json_dict='[{"cvssData":{"privilegesRequired":"{value}"}}]',
            N=PrivilegesRequiredTypeV40.NONE, L=PrivilegesRequiredTypeV40.LOW,
            H=PrivilegesRequiredTypeV40.HIGH,
        ),

        UI=dict(
            json_dict='[{"cvssData":{"userInteraction":"{value}"}}]',
            N=UserInteractionTypeV40.NONE, P=UserInteractionTypeV40.PASSIVE,
            A=UserInteractionTypeV40.ACTIVE,
        ),

        VC=dict(
            json_dict='[{"cvssData":{"vulnerableSystemConfidentiality":"{value}"}}]',
            H=VulnCiaTypeV40.HIGH, L=VulnCiaTypeV40.LOW, N=VulnCiaTypeV40.NONE,
        ),

        VI=dict(
            json_dict='[{"cvssData":{"vulnerableSystemIntegrity":"{value}"}}]',
            H=VulnCiaTypeV40.HIGH, L=VulnCiaTypeV40.LOW, N=VulnCiaTypeV40.NONE,
        ),

        VA=dict(
            json_dict='[{"cvssData":{"vulnerableSystemAvailability":"{value}"}}]',
            H=VulnCiaTypeV40.HIGH, L=VulnCiaTypeV40.LOW, N=VulnCiaTypeV40.NONE,
        ),

        SC=dict(
            json_dict='[{"cvssData":{"subsequentSystemConfidentiality":"{value}"}}]',
            H=VulnCiaTypeV40.HIGH, L=VulnCiaTypeV40.LOW, N=VulnCiaTypeV40.NONE,
        ),

        SI=dict(
            json_dict='[{"cvssData":{"subsequentSystemIntegrity":"{value}"}}]',
            H=VulnCiaTypeV40.HIGH, L=VulnCiaTypeV40.LOW, N=VulnCiaTypeV40.NONE,
        ),

        SA=dict(
            json_dict='[{"cvssData":{"subsequentSystemAvailability":"{value}"}}]',
            H=VulnCiaTypeV40.HIGH, L=VulnCiaTypeV40.LOW, N=VulnCiaTypeV40.NONE,
        ),

        E=dict(
            json_dict='[{"cvssData":{"exploitMaturity":"{value}"}}]',
            X=ExploitMaturityTypeV40.NOT_DEFINED, A=ExploitMaturityTypeV40.ATTACKED,
            P=ExploitMaturityTypeV40.PROOF_OF_CONCEPT, U=ExploitMaturityTypeV40.UNREPORTED,
        ),

        CR=dict(
            json_dict='[{"cvssData":{"confidentialityRequirements":"{value}"}}]',
            X=CiaRequirementTypeV40.NOT_DEFINED, H=CiaRequirementTypeV40.HIGH,
            M=CiaRequirementTypeV40.MEDIUM, L=CiaRequirementTypeV40.LOW,
        ),

        IR=dict(
            json_dict='[{"cvssData":{"integrityRequirements":"{value}"}}]',
            X=CiaRequirementTypeV40.NOT_DEFINED, H=CiaRequirementTypeV40.HIGH,
            M=CiaRequirementTypeV40.MEDIUM, L=CiaRequirementTypeV40.LOW,
        ),

        AR=dict(
            json_dict='[{"cvssData":{"availabilityRequirements":"{value}"}}]',
            X=CiaRequirementTypeV40.NOT_DEFINED, H=CiaRequirementTypeV40.HIGH,
            M=CiaRequirementTypeV40.MEDIUM, L=CiaRequirementTypeV40.LOW,
        ),

        MAV=dict(
            json_dict='[{"cvssData":{"modifiedAttackVector":"{value}"}}]',
            X=ModifiedAttackVectorTypeV40.NOT_DEFINED, N=ModifiedAttackVectorTypeV40.NETWORK,
            A=ModifiedAttackVectorTypeV40.ADJACENT, L=ModifiedAttackVectorTypeV40.LOCAL,
            P=ModifiedAttackVectorTypeV40.PHYSICAL,
        ),

        MAC=dict(
            json_dict='[{"cvssData":{"modifiedAttackComplexity":"{value}"}}]',
            X=ModifiedAttackComplexityTypeV40.NOT_DEFINED, L=ModifiedAttackComplexityTypeV40.LOW,
            H=ModifiedAttackComplexityTypeV40.HIGH,
        ),

        MAT=dict(
            json_dict='[{"cvssData":{"modifiedAttackRequirements":"{value}"}}]',
            X=ModifiedAttackRequirementsTypeV40.NOT_DEFINED, N=ModifiedAttackRequirementsTypeV40.NONE,
            P=ModifiedAttackRequirementsTypeV40.PRESENT,
        ),

        MPR=dict(
            json_dict='[{"cvssData":{"modifiedPrivilegesRequired":"{value}"}}]',
            X=ModifiedPrivilegesRequiredTypeV40.NOT_DEFINED, N=ModifiedPrivilegesRequiredTypeV40.NONE,
            L=ModifiedPrivilegesRequiredTypeV40.LOW, H=ModifiedPrivilegesRequiredTypeV40.HIGH,
        ),

        MUI=dict(
            json_dict='[{"cvssData":{"modifiedUserInteraction":"{value}"}}]',
            X=ModifiedUserInteractionTypeV40.NOT_DEFINED, N=ModifiedUserInteractionTypeV40.NONE,
            P=ModifiedUserInteractionTypeV40.PASSIVE, A=ModifiedUserInteractionTypeV40.ACTIVE,
        ),

        MVC=dict(
            json_dict='[{"cvssData":{"modifiedvulnerableSystemConfidentiality":"{value}"}}]',
            X=ModifiedVulnCiaTypeV40.NOT_DEFINED, H=ModifiedVulnCiaTypeV40.HIGH,
            L=ModifiedVulnCiaTypeV40.LOW, N=ModifiedVulnCiaTypeV40.NONE,
        ),

        MVI=dict(
            json_dict='[{"cvssData":{"modifiedvulnerableSystemIntegrity":"{value}"}}]',
            X=ModifiedVulnCiaTypeV40.NOT_DEFINED, H=ModifiedVulnCiaTypeV40.HIGH,
            L=ModifiedVulnCiaTypeV40.LOW, N=ModifiedVulnCiaTypeV40.NONE,
        ),

        MVA=dict(
            json_dict='[{"cvssData":{"modifiedvulnerableSystemAvailability":"{value}"}}]',
            X=ModifiedVulnCiaTypeV40.NOT_DEFINED, H=ModifiedVulnCiaTypeV40.HIGH,
            L=ModifiedVulnCiaTypeV40.LOW, N=ModifiedVulnCiaTypeV40.NONE,
        ),

        MSC=dict(
            json_dict='[{"cvssData":{"modifiedsubsequentSystemConfidentiality":"{value}"}}]',
            X=ModifiedSubCTypeV40.NOT_DEFINED, N=ModifiedSubCTypeV40.NEGLIGIBLE,
            L=ModifiedSubCTypeV40.LOW, H=ModifiedSubCTypeV40.HIGH,
        ),

        MSI=dict(
            json_dict='[{"cvssData":{"modifiedsubsequentSystemIntegrity":"{value}"}}]',
            X=ModifiedSubIaTypeV40.NOT_DEFINED, N=ModifiedSubIaTypeV40.NEGLIGIBLE,
            L=ModifiedSubIaTypeV40.LOW, H=ModifiedSubIaTypeV40.HIGH,
            S=ModifiedSubIaTypeV40.SAFETY,
        ),

        MSA=dict(
            json_dict='[{"cvssData":{"modifiedSubsequentSystemAvailability":"{value}"}}]',
            X=ModifiedSubIaTypeV40.NOT_DEFINED, N=ModifiedSubIaTypeV40.NEGLIGIBLE,
            L=ModifiedSubIaTypeV40.LOW, H=ModifiedSubIaTypeV40.HIGH,
            S=ModifiedSubIaTypeV40.SAFETY,
        ),

        S=dict(
            json_dict='[{"cvssData":{"safety":"{value}"}}]',
            X=SafetyTypeV40.NOT_DEFINED, N=SafetyTypeV40.NEGLIGIBLE,
            P=SafetyTypeV40.PRESENT,
        ),

        AU=dict(
            json_dict='[{"cvssData":{"automatable":"{value}"}}]',
            X=AutomatableTypeV40.NOT_DEFINED, N=AutomatableTypeV40.NO,
            Y=AutomatableTypeV40.YES,
        ),

        R=dict(
            json_dict='[{"cvssData":{"recovery":"{value}"}}]',
            X=RecoveryTypeV40.NOT_DEFINED, A=RecoveryTypeV40.AUTOMATIC,
            U=RecoveryTypeV40.USER, I=RecoveryTypeV40.IRRECOVERABLE,
        ),

        V=dict(
            json_dict='[{"cvssData":{"valueDensity":"{value}"}}]',
            X=ValueDensityTypeV40.NOT_DEFINED, D=ValueDensityTypeV40.DIFFUSE,
            C=ValueDensityTypeV40.CONCENTRATED,
        ),

        RE=dict(
            json_dict='[{"cvssData":{"vulnerabilityResponseEffort":"{value}"}}]',
            X=VulnerabilityResponseEffortTypeV40.NOT_DEFINED, L=VulnerabilityResponseEffortTypeV40.LOW,
            M=VulnerabilityResponseEffortTypeV40.MODERATE, H=VulnerabilityResponseEffortTypeV40.HIGH,
        ),

        U=dict(
            json_dict='[{"cvssData":{"providerUrgency":"{value}"}}]',
            X=ProviderUrgencyTypeV40.NOT_DEFINED, Clear=ProviderUrgencyTypeV40.CLEAR,
            Green=ProviderUrgencyTypeV40.GREEN, Amber=ProviderUrgencyTypeV40.AMBER,
            Red=ProviderUrgencyTypeV40.RED,
        ),
    )
)
metrics_mapping['V30'] = dict(
    regex=CveCvssV30.__fields__['vectorString'].type_.regex,
    **{k: v for k, v in metrics_mapping['V31'].items() if k not in ['regex']}
)
