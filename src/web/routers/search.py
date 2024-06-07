"""
Search endpoints implementation for the Binare Vulndb API.

Copyright (c) 2020 to date, Binare Oy (license@binare.io) All rights reserved.
"""
import logging
from pydantic.error_wrappers import ValidationError as PydanticValidationError
from fastapi import APIRouter, Depends, Query, status, HTTPException
from generic.context import ApplicationContext
from dependencies import get_app_cntxt
from typing import Any
from common.models import SearchInfoType, SearchOptions
from common.search import search_data, ValidationError
from web.models.search import (
    CveOutput, 
    CpeOutput, 
    SearchInputCommon,
    SearchInputCve,
    SearchInputCpe,
    SearchInputCwe,
    SearchInputCapec,
)

router = APIRouter(prefix="/search", tags=["search"])


# ------------------------------------------------------------------------------
def search(appctx: ApplicationContext, opts: SearchOptions) -> any:

    logger = logging.getLogger('web')
    logger.info(f'search: {opts}')

    try:
        result = search_data(appctx, opts)
    except ValidationError as exc:
        logger.exception(exc)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return result


# ------------------------------------------------------------------------------
@router.get("/cve", name="Search CVE", response_model=CveOutput)
async def search_cve(cmn_opts: SearchInputCommon = Depends(SearchInputCommon),
                     cve_opts: SearchInputCve = Depends(SearchInputCve),
                     appctx: ApplicationContext = Depends(get_app_cntxt),
    ) -> CveOutput:

    """API to search for CVEs"""

    try:
        opts = SearchOptions(
            searchInfo=SearchInfoType.cve,
            pageIdx=cmn_opts.page_idx,
            pageSize=cmn_opts.page_size,
            keywordSearch=cmn_opts.keyword_search,
            cveId=cve_opts.cve_id,
            cpeName=cve_opts.cpe_name,
            cweId=cve_opts.cwe_id,
            lastModStartDate=cve_opts.last_mod_start_date,
            lastModEndDate=cve_opts.last_mod_end_date,
            pubStartDate=cve_opts.pub_start_date,
            pubEndDate=cve_opts.pub_end_date,
            cvssV2Severity=cve_opts.cvss_v2_severity,
            cvssV3Severity=cve_opts.cvss_v3_severity,
            cvssV2Metrics=cve_opts.cvss_v2_metrics,
            cvssV3Metrics=cve_opts.cvss_v3_metrics,
            epssScoreGt=cve_opts.epss_Score_Gt,
            epssScoreLt=cve_opts.epss_Score_Lt,
            epssPercGt=cve_opts.epss_Perc_Gt,
            epssPercLt=cve_opts.epss_Perc_Lt,
            exploitable=cve_opts.exploitable,
            vulnerable=cve_opts.vulnerable,
            days=cve_opts.days
        )
    except PydanticValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return search(appctx, opts)


# ------------------------------------------------------------------------------
@router.get("/cpe", name="Search CPE", response_model=CpeOutput)
async def search_cpe(cmn_opts: SearchInputCommon = Depends(SearchInputCommon),
                     cpe_opts: SearchInputCpe = Depends(SearchInputCpe),
                     appctx: ApplicationContext = Depends(get_app_cntxt),
    ) -> CpeOutput:

    """API to search for CPEs"""

    try:
        opts = SearchOptions(
            searchInfo=SearchInfoType.cpe,
            pageIdx=cmn_opts.page_idx,
            pageSize=cmn_opts.page_size,
            keywordSearch=cmn_opts.keyword_search,
            cpeName=cpe_opts.cpe_name,
            lastModStartDate=cpe_opts.last_mod_start_date,
            lastModEndDate=cpe_opts.last_mod_end_date,
            days=cpe_opts.days,
            deprecated=cpe_opts.deprecated
        )
    except PydanticValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return search(appctx, opts)


# ------------------------------------------------------------------------------
@router.get("/cwe", name="Search CWE")
async def search_cwe(cmn_opts: SearchInputCommon = Depends(SearchInputCommon),
                     cwe_opts: SearchInputCwe = Depends(SearchInputCwe),
                     appctx: ApplicationContext = Depends(get_app_cntxt),
    ) -> Any:

    """API to search for CWEs"""

    try:
        opts = SearchOptions(
            searchInfo=SearchInfoType.cwe,
            pageIdx=cmn_opts.page_idx,
            pageSize=cmn_opts.page_size,
            keywordSearch=cmn_opts.keyword_search,
            cweId=cwe_opts.cwe_id,
        )
    except PydanticValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return search(appctx, opts)


# ------------------------------------------------------------------------------
@router.get("/capec", name="Search CAPEC", )
async def search_capec(cmn_opts: SearchInputCommon = Depends(SearchInputCommon),
                       capec_opts: SearchInputCapec = Depends(SearchInputCapec),
                       appctx: ApplicationContext = Depends(get_app_cntxt)
    ) -> Any:

    """API to search for CAPECs"""

    try:
        opts = SearchOptions(
            searchInfo=SearchInfoType.capec,
            pageIdx=cmn_opts.page_idx,
            pageSize=cmn_opts.page_size,
            keywordSearch=cmn_opts.keyword_search,
            capecId=capec_opts.capec_id,
        )
    except PydanticValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return search(appctx, opts)
