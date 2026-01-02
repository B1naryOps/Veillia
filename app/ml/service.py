from app.ml.loader import model, vectorizer
from app.database import SessionLocal
from app.models.ml_analysis import MLAnalysis
from app.core.audit import log_audit
from fastapi import Request

def analyze_text_ml(text: str):
    X = vectorizer.transform([text])
    probability = float(model.predict_proba(X)[0][1])
    confidence = float(round(probability * 100, 2))
    is_phishing = bool(probability >= 0.5)

    return {
        "is_phishing": is_phishing,
        "probability": round(probability, 4),
        "confidence": confidence
    }


def save_analysis_and_audit(text: str, request: Request, user_id: int | None = None):

    result = analyze_text_ml(text)

    # sauvegarde ML
    db = SessionLocal()
    analysis = MLAnalysis(
        user_id=user_id,
        content=text,
        is_phishing=result["is_phishing"],
        probability=result["probability"],
        confidence=result["confidence"]
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # audit
    log_audit(
        user_id=user_id,
        action="ML_ANALYSIS",
        endpoint=str(request.url.path),
        method=request.method,
        ip_address=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("User-Agent", "unknown"),
        status_code=200
    )

    db.close()
    return result
