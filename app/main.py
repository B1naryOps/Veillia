from fastapi import FastAPI
from app.database import engine, Base
from app.routes.users import router as users_router
from app.routes.auth import router as auth_router
from app.middleware.audit import AuditMiddleware
from app.routes.analysis_ml import router as analysis_ml_router

app = FastAPI(title="AI Guardian")

Base.metadata.create_all(bind=engine)

app.include_router(users_router)
app.include_router(auth_router)
app.add_middleware(AuditMiddleware)
app.include_router(analysis_ml_router)

@app.get("/")
def root():
    return {"message": "AI Guardian backend is running"}
