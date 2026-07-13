from pydantic import BaseModel, ConfigDict, Field
from typing import Any, Dict, List

class AnalysisRequest(BaseModel):
    content: str


class MLAnalysisResponse(BaseModel):
    is_phishing: bool
    probability: float
    confidence: float
    ml_score: int
    llm_score: int
    final_score: int
    decision_source: str
    engine_disagreement: bool
    features: Dict[str, Any] = Field(default_factory=dict)
    explanation: List[str] = Field(default_factory=list)
    attack_type: str = "Unknown"
    techniques: List[str] = Field(default_factory=list)
    recommended_training: List[str] = Field(default_factory=list)
    quiz: Dict[str, Any] = Field(default_factory=dict)

class MLHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    content: str
    is_phishing: bool
    probability: float
    confidence: float
    created_at: str # will be formatted
