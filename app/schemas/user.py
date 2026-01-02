from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    nom: str
    prenoms: str
    mot_de_passe: str
    role: str | None = "EMPLOYEE"

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    nom: str
    prenoms: str
    role: str

    class Config:
        from_attributes = True
