from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.audit_log import AuditLogs
from datetime import datetime
from app.core.auth import get_current_user_id 

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        method = request.method
        endpoint = request.url.path
        user_agent = request.headers.get("user-agent", "unknown")
        user_id = get_current_user_id(request)

        response = await call_next(request)

        db: Session = next(get_db())
        log = AuditLogs(
            user_id=user_id,
            action="access",
            endpoint=endpoint,
            method=method,
            ip_address=ip,
            user_agent=user_agent,
            status_code=response.status_code,
            created_at=datetime.utcnow().isoformat()
        )
        db.add(log)
        db.commit()

        return response
