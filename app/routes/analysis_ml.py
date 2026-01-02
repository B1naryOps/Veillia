from fastapi import APIRouter, Request, Depends
from app.ml.service import save_analysis_and_audit
from app.ml.schemas import AnalysisRequest, MLAnalysisResponse
from app.core.auth import get_current_user_id

router = APIRouter(
    prefix="/analysis",
    tags=["ML"]
)


@router.post("/ml", response_model=MLAnalysisResponse)
async def analyze_ml(request_data: AnalysisRequest, request: Request):
    user_id = get_current_user_id(request)
    result = save_analysis_and_audit(
        text=request_data.content,
        request=request,
        user_id=user_id
    )
    return result
