import os
from datetime import timedelta

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://camille:password@localhost:5432/ai_guardian"
)

SECRET_KEY = "CHANGE_ME_SUPER_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60