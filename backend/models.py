#====================
# External Libraries
#====================

from pydantic import BaseModel, Field, validator
from typing import Optional
import re

#========
# Models 
#========

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateNewUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    employee_id: int = Field(..., gt=0)
    password: str

    @validator('username')
    def validate_username_security(cls, v):
        if not v.strip():
            raise ValueError('Username cannot be empty or whitespace')
        if ';' in v:
            raise ValueError('Username contains invalid character: ;')
        if '--' in v:
             raise ValueError('Username contains invalid sequence: --')
        return v.strip()

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    is_manager: bool

class CustomerSearchRequest(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None

    @validator('name', 'company', 'city', 'country')
    def validate_search_content(cls, v):
        if v is None:
            return v
            
        # 2. Whitelist Characters (Defense in Depth)
        # Allow only: Letters, Numbers, Spaces, Hyphens, Apostrophes, dots
        # This rejects inputs like "Rome; DROP" or "<script>" or "100%"
        if not re.match(r"^[a-zA-Z0-9\s\-\'\.]+$", v):
            raise ValueError('Search contains invalid characters')
            
        return v.strip()

    # Custom validator for email to accept other characters
    @validator('email')
    def validate_email_simple(cls, v):
        if v is None:
            return v

        # Allow @ and . for emails, plus standard alphanumerics
        if not re.match(r"^[a-zA-Z0-9\s\-\'\.\@]+$", v):
            raise ValueError('Email contains invalid characters')

        return v.strip()
