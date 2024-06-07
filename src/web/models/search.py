"""
Pydantic data models used in the search endpoints outputs

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""
from pydantic import BaseModel
from fastapi import Query
from typing import List, Optional
from datetime import datetime, date
from common.models.cve import CveItem
from common.models.cpe import CpeItem
from common.models import CveSeverityV2, CveSeverityV3


class CveOutput(BaseModel):
    search: dict
    result: List[CveItem]


class CpeOutput(BaseModel):
    search: dict
    result: List[CpeItem]


class StatusItemOutput(BaseModel):
    update_date: datetime
    count: int


class StatusOutput(BaseModel):

    capec: Optional[StatusItemOutput]
    cve: Optional[StatusItemOutput]
    cpe: Optional[StatusItemOutput]
    cwe: Optional[StatusItemOutput]
    epss: Optional[StatusItemOutput]

class SearchInputCommon:

    def __init__(self, *,
            page_idx: Optional[int] = Query(default=0, description="Results page index", alias="page-idx", ge=0),
            page_size: Optional[int] = Query(description="Results page size", default=10, alias="page-size", ge=10, le=3000),
            keyword_search: Optional[List[str]] = Query(default=None, description="regexp to search for CPE in the description", alias="keyword")
        ) -> None:

        self.page_idx = page_idx
        self.page_size = page_size
        self.keyword_search = keyword_search

class SearchInputCve:

    def __init__(self, *,
        cve_id: Optional[List[str]] = Query(default=None, description="Related CVE IDs to search for", alias="cve"),
        cpe_name: Optional[str] = Query(default=None, description="CPE2.3 filter specification to search for", alias="cpe23"),
        cwe_id: Optional[List[str]] = Query(default=None, description="Related CWE IDs to search for", alias="cwe"),
        last_mod_start_date: Optional[date] = Query(default=None, description="Last modified start date", alias="last-mod-start-date"),
        last_mod_end_date: Optional[date] = Query(default=None, description="Last modified end date", alias="last-mod-end-date"),
        pub_start_date: Optional[date] = Query(default=None, description="CVE Published start date", alias="pub-start-date"),
        pub_end_date: Optional[date] = Query(default=None, description="CVE Published start date", alias="pub-end-date"),
        cvss_v2_severity: Optional[CveSeverityV2] = Query(default=None, description="CVSS V2.0 Severity to search for", alias="cvss-severity-v2"),
        cvss_v3_severity: Optional[CveSeverityV3] = Query(default=None, description="CVSS V3.x Severity to search", alias="cvss-severity-v3"),
        cvss_v2_metrics: Optional[str] = Query(default=None, description="CVSS V2.0 vector string to search for", alias="cvss-metrics-v2"),
        cvss_v3_metrics: Optional[str] = Query(default=None, description="CVSS V3.x vector string to search for", alias="cvss-metrics-v3"),
        epss_score_gt: Optional[float] = Query(default=None, description="Greater EPSS score float to search for", alias="epss-score-gt", ge=0, le=1),
        epss_score_lt: Optional[float] = Query(default=None, description="Less EPSS score float to search for", alias="epss-score-lt", ge=0, le=1),
        epss_perc_gt: Optional[float] = Query(default=None, description="Greater EPSS percentile float to search for", alias="epss-perc-gt", ge=0, le=1),
        epss_perc_lt: Optional[float] = Query(default=None, description="Less EPSS percentile float to search for", alias="epss-perc-lt", ge=0, le=1),
        exploitable: Optional[bool] = Query(default=False, description="Known Exploited Vulnerabilities to search for", alias="exploitable"),
        vulnerable: Optional[bool] = Query(default=True, description="CVEs found by the CPEs that are marked as vulnerable", alias="vulnerable"),
        days: Optional[int] = Query(default=None, description="Number of days back when the CVEs were last modified", alias="days-back", ge=0),

    ) -> None:
        
        self.cve_id = cve_id
        self.cpe_name = cpe_name
        self.cwe_id = cwe_id
        self.last_mod_start_date = last_mod_start_date
        self.last_mod_end_date = last_mod_end_date
        self.pub_start_date = pub_start_date
        self.pub_end_date = pub_end_date
        self.cvss_v2_severity = cvss_v2_severity
        self.cvss_v3_severity = cvss_v3_severity
        self.cvss_v2_metrics = cvss_v2_metrics
        self.cvss_v3_metrics = cvss_v3_metrics
        self.epss_Score_Gt = epss_score_gt
        self.epss_Score_Lt = epss_score_lt
        self.epss_Perc_Gt = epss_perc_gt
        self.epss_Perc_Lt = epss_perc_lt
        self.exploitable = exploitable
        self.vulnerable = vulnerable
        self.days = days


class SearchInputCpe:

    def __init__(self, *,
        cpe_name: Optional[str] = Query(default=None, description="CPE2.3 filter specification to search for", alias="cpe23"),
        last_mod_start_date: Optional[date] = Query(default=None, description="Last modified start date", alias="last-mod-start-date"),
        last_mod_end_date: Optional[date] = Query(default=None, description="Last modified end date", alias="last-mod-end-date"),
        days: Optional[int] = Query(default=None, description="Number of days back when the CPEs were last modified", alias="days-back", ge=0),
        deprecated: Optional[bool] = Query(default=False, description="If set to true, will fetch only the deprecated CPE names", alias="deprecated"),
    ) -> None:

        self.cpe_name = cpe_name
        self.last_mod_start_date = last_mod_start_date
        self.last_mod_end_date = last_mod_end_date
        self.days = days
        self.deprecated = deprecated

class SearchInputCwe:

    def __init__(self, *,
        cwe_id: Optional[List[str]] = Query(default=None, description="Related CWE IDs to search for", alias="cwe"),
    ) -> None:

        self.cwe_id = cwe_id


class SearchInputCapec:

    def __init__(self, *,
        capec_id: Optional[List[str]] = Query(default=None, description="Related CAPEC IDs to search for", alias="capec"),
    ) -> None:

        self.capec_id = capec_id
