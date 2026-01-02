from app.database import SessionLocal
from app.models.audit_log import AuditLogs

def log_audit(user_id, action, endpoint, method, ip_address, user_agent, status_code):
    db = SessionLocal()
    log = AuditLogs(
        user_id=user_id,
        action=action,
        endpoint=endpoint,
        method=method,
        ip_address=ip_address,
        user_agent=user_agent,
        status_code=status_code
    )
    db.add(log)
    db.commit()
    db.close()
