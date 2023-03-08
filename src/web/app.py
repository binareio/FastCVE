from fastapi import FastAPI, HTTPException, Depends, status
from generic import ApplicationContext
from common.models import SearchOptions, SearchInfoType
from common.search import search_data
from dependencies import get_app_cntxt
from web.routers.search import router as router_search
from web.models.search import StatusOutput

app = FastAPI(title="FastCVE", description="fast, rich and API-based search for CVE and more (CPE, CWE, CAPEC)", version="0.1.0")


@app.get("/status", tags=['status'], name="DB status", response_model=StatusOutput)
async def get_status(appctx: ApplicationContext = Depends(get_app_cntxt)) -> StatusOutput:
    """Get the current DB status update"""

    try:
        opts = SearchOptions(searchInfo=SearchInfoType.status)
        result = search_data(appctx, opts)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    return result

app.include_router(router_search, prefix="/api")

