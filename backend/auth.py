# ===================
# External Libraries 
# ===================

import jwt
from datetime import datetime, timedelta, timezone
import uuid
import os

# =================
# Global Variables 
# =================

ACCESS_TOKEN_MINUTES_DURATION = 5 # Default
REFRESH_TOKEN_MINUTES_DURATION = 60 # Default
ALGORITHM = "HS256"
ACCESS_TOKEN_SECRET = os.environ.get('ACCESS_TOKEN_SECRET')
REFRESH_TOKEN_SECRET = os.environ.get('REFRESH_TOKEN_SECRET')

if not ACCESS_TOKEN_SECRET or not REFRESH_TOKEN_SECRET:
    raise ValueError("ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET environment variables must be set")
    
# ===============
# Token creation
# ===============

def create_access_token(username: str, minutes: int = ACCESS_TOKEN_MINUTES_DURATION) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }

    return jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm=ALGORITHM)

def create_refresh_token(username: str, minutes: int = REFRESH_TOKEN_MINUTES_DURATION) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }

    return jwt.encode(payload, REFRESH_TOKEN_SECRET, algorithm=ALGORITHM)

# ===================
# Token verification
# ===================

def verify_access_token(token: str) -> dict:
    """
    Validates the access token purely using the secret key (Stateless).
    Returns the payload if valid.
    Raises jwt.ExpiredSignatureError, jwt.InvalidTokenError, or ValueError if invalid.
    """
    # Decode
    payload = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=[ALGORITHM])
    
    # Verify it is actually an 'access' token
    if payload.get("type") != "access":
        raise ValueError("Invalid token type: expected access token")
        
    return payload


def verify_refresh_token(token: str) -> tuple[str, int]:
    """
    Validates the refresh token purely using the secret key (Stateless).
    Returns the payload if valid.
    Raises jwt.ExpiredSignatureError, jwt.InvalidTokenError, or ValueError if invalid.
    """
    # Decode 
    payload = jwt.decode(token, REFRESH_TOKEN_SECRET, algorithms=[ALGORITHM])
    
    # Verify it is actually a 'refresh' token
    if payload.get("type") != "refresh":
        raise ValueError("Invalid token type: expected refresh token")

    return payload["sub"] 
