#====================
# EXTERNAL LIBRARIES 
#====================
# build the api 
from fastapi import FastAPI, HTTPException, status, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
# host the server 
import uvicorn
# access date and time 
from datetime import datetime, timedelta, timezone
# logging
import logging
#====================
# INTERNAL LIBRARIES 
#====================
from security import (
    verify_password, 
    hash_token,
    hash_password,
    validate_password_complexity
)
from db import (
    get_user_password_hash,
    get_user_id,
    get_user_employee_id,
    store_refresh_token_hash,
    create_user,
    get_expiration_of_token_hash,
    delete_refresh_token_by_hash,
    delete_refresh_token_by_user,
    get_employee_title,
    get_customers_for_employee,
    set_user_password_hash
)
from auth import (
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    verify_access_token,
    REFRESH_TOKEN_MINUTES_DURATION
)
from models import (
    LoginRequest,
    CreateNewUserRequest,
    TokenResponse,
    CustomerSearchRequest,
    ChangePasswordRequest  
)
#==================
# GLOBAL VARIABLES 
#==================
app = FastAPI(title="Chinook Database Backend Server")

# CORS (Cross Cross-Origin Resource Sharing) middleware
# This is to allows request from the local host, in production allow only trusted domain
origins = [
    "http://localhost",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development - allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create separate loggers for different purposes
activity_logger = logging.getLogger('activity')
security_logger = logging.getLogger('security')
error_logger = logging.getLogger('error')

#===========================
# HELPER FUNCTIONS 
#===========================
def mask_token(token: str) -> str:
    """Mask token for logging - show only first and last 4 chars"""
    if not token or len(token) < 12:
        return "***"
    return f"{token[:4]}...{token[-4:]}"

def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_current_user_token(authorization: str = Header(...)):
    """Verify user token validity and return payload"""
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            security_logger.warning(
                "Invalid authentication scheme attempted",
                extra={'scheme': scheme}
            )
            raise ValueError("Invalid scheme")
        
        payload = verify_access_token(token)
        activity_logger.info(
            f"Token validated for user: {payload.get('sub', 'unknown')}"
        )
        return payload
        
    except ValueError as e:
        security_logger.warning(f"Token validation failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Unauthorized")
    except Exception as e:
        security_logger.error(f"Unexpected error during token validation: {str(e)}")
        raise HTTPException(status_code=401, detail="Unauthorized")

def is_manager(username: str) -> bool:
    """Check if user has manager privileges"""
    try:
        employee_id = get_user_employee_id(username)
        if employee_id is None:
            activity_logger.info(f"No employee_id found for user: {username}")
            return False
        
        title = get_employee_title(employee_id)
        if title is None:
            activity_logger.info(f"No title found for employee_id: {employee_id}")
            return False
        
        is_mgr = "manager" in title.lower()
        activity_logger.info(
            f"Manager check for {username}: {is_mgr}",
            extra={'employee_id': employee_id, 'title': title}
        )
        return is_mgr
        
    except Exception as e:
        error_logger.error(
            f"Error checking manager status for {username}: {str(e)}"
        )
        return False

#===============
# API ENDPOINTS 
#===============
@app.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, http_request: Request):
    """Authenticate user and issue tokens"""
    client_ip = get_client_ip(http_request)
    username = request.username
    
    activity_logger.info(
        f"Login attempt for user: {username}",
        extra={'ip': client_ip, 'endpoint': '/login'}
    )
    
    try:
        # Get stored password hash
        password_hash = get_user_password_hash(username)
        if password_hash is None:
            security_logger.warning(
                f"Login failed - user not found: {username}",
                extra={'ip': client_ip}
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password (never log the actual password)
        if not verify_password(request.password, password_hash):
            security_logger.warning(
                f"Login failed - invalid password for user: {username}",
                extra={'ip': client_ip}
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get user details
        user_id = get_user_id(username)
        activity_logger.info(f"User authenticated successfully: {username}")
        manager_status = is_manager(username)
        
        if manager_status:
            access_duration = 5
            refresh_duration = 60
        else:
            access_duration = 5
            refresh_duration = 5 

        activity_logger.info(f"Generating tokens for {username} (Manager: {manager_status}) - Duration: {access_duration}m")

        # Create tokens (log masked versions only)
        access_token = create_access_token(username, minutes=access_duration)
        refresh_token = create_refresh_token(username, minutes=access_duration)
        
        activity_logger.info(
            f"Tokens generated for user: {username}",
            extra={
                'access_token_preview': mask_token(access_token),
                'refresh_token_preview': mask_token(refresh_token)
            }
        )
        
        refresh_token_hash = hash_token(refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=refresh_duration)
        store_refresh_token_hash(user_id, refresh_token_hash, expires_at.isoformat())
        
        activity_logger.info(f"Refresh token stored for user: {username}",extra={'expires_at': expires_at.isoformat()})
        activity_logger.info(f"Login successful for user: {username}",extra={'ip': client_ip,'is_manager': manager_status,'user_id': user_id})
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            is_manager=manager_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        error_logger.error(
            f"Unexpected error during login for {username}: {str(e)}",
            extra={'ip': client_ip},
            exc_info=True
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str, http_request: Request):
    """Refresh access token using refresh token"""
    client_ip = get_client_ip(http_request)
    token_preview = mask_token(refresh_token)
    
    activity_logger.info(
        "Token refresh attempt",
        extra={'ip': client_ip, 'token_preview': token_preview}
    )
    
    try:
        # Verify token signature and decode
        username = verify_refresh_token(refresh_token)
        activity_logger.info(f"Refresh token decoded for user: {username}")
        
    except Exception as e:
        security_logger.warning(
            f"Invalid refresh token signature",
            extra={'ip': client_ip, 'error': str(e)}
        )
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    try:
        # Verify token exists in database
        token_hash = hash_token(refresh_token)
        expires_at_str = get_expiration_of_token_hash(token_hash)
        
        if expires_at_str is None:
            security_logger.warning(
                f"Refresh token not found in database for user: {username}",
                extra={'ip': client_ip}
            )
            raise HTTPException(status_code=401, detail="Refresh token not found or revoked")
        
        # Check expiration
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at < datetime.now(timezone.utc):
            delete_refresh_token_by_hash(token_hash)
            security_logger.warning(
                f"Expired refresh token used by user: {username}",
                extra={'ip': client_ip, 'expired_at': expires_at_str}
            )
            raise HTTPException(status_code=401, detail="Refresh token expired")
        
        # Delete old refresh token
        delete_refresh_token_by_hash(token_hash)
        activity_logger.info(f"Old refresh token invalidated for user: {username}")
        
        # Create new tokens
        new_access = create_access_token(username)
        new_refresh = create_refresh_token(username)
        
        activity_logger.info(
            f"New tokens generated for user: {username}",
            extra={
                'access_token_preview': mask_token(new_access),
                'refresh_token_preview': mask_token(new_refresh)
            }
        )
        
        # Store new refresh token
        user_id = get_user_id(username)
        new_hash = hash_token(new_refresh)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_MINUTES_DURATION)
        store_refresh_token_hash(user_id, new_hash, expires_at.isoformat())
        
        activity_logger.info(
            f"Token refresh successful for user: {username}",
            extra={
                'ip': client_ip,
                'expires_at': expires_at.isoformat()
            }
        )
        
        manager_status = is_manager(username)
        
        return TokenResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            is_manager=manager_status
        )
        
    except HTTPException:
        raise
    except Exception as e:
        error_logger.error(
            f"Unexpected error during token refresh for {username}: {str(e)}",
            extra={'ip': client_ip},
            exc_info=True
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/logout")
def logout(access_token: dict = Depends(get_current_user_token),http_request: Request = None):
    """Logout user and invalidate refresh tokens"""
    client_ip = get_client_ip(http_request)
    username = access_token["sub"]
    
    activity_logger.info(
        f"Logout initiated for user: {username}",
        extra={'ip': client_ip}
    )
    
    try:
        user_id = get_user_id(username)
        delete_refresh_token_by_user(user_id)
        
        activity_logger.info(
            f"Logout successful for user: {username}",
            extra={'ip': client_ip, 'user_id': user_id}
        )
        
        return {"detail": "Logged out"}
        
    except Exception as e:
        error_logger.error(
            f"Error during logout for {username}: {str(e)}",
            extra={'ip': client_ip},
            exc_info=True
        )
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/create_new_user")
def create_new_user(request: CreateNewUserRequest, http_request: Request):
    """Create new user account with hardcoded password validation"""
    client_ip = get_client_ip(http_request)
    username = request.username
    employee_id = request.employee_id
    
    activity_logger.info(
        f"User creation attempt - username: {username}, employee_id: {employee_id}",
        extra={'ip': client_ip}
    )
    
    try:
        # Validate password (never log actual password)
        if request.password != "Jo5hu4!":
            security_logger.warning(
                f"User creation failed - incorrect authorization password",
                extra={'ip': client_ip, 'attempted_username': username}
            )
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Incorrect password provided."
            )
        
        # Validate employee exists
        new_employee_title = get_employee_title(employee_id)
        if new_employee_title is None:
            activity_logger.warning(
                f"User creation failed - invalid employee_id: {employee_id}",
                extra={'ip': client_ip, 'username': username}
            )
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid employee_id: {employee_id}. Employee does not exist."
            )
        
        activity_logger.info(
            f"Employee validated for user creation",
            extra={'employee_id': employee_id, 'title': new_employee_title}
        )
        
        # Check if username exists
        existing_user = get_user_id(username)
        if existing_user is not None:
            activity_logger.warning(
                f"User creation failed - username already exists: {username}",
                extra={'ip': client_ip, 'employee_id': employee_id}
            )
            raise HTTPException(
                status_code=400, 
                detail=f"Username '{username}' already exists"
            )
        
        # Create user (password is hashed, never logged)
        password_hash = hash_password(request.password)
        create_user(username, employee_id, password_hash)
        
        activity_logger.info(
            f"User created successfully - username: {username}, employee_id: {employee_id}",
            extra={
                'ip': client_ip,
                'employee_title': new_employee_title
            }
        )
        
        return {
            "detail": "User created successfully",
            "username": username,
            "employee_id": employee_id,
            "created_by": "System (Auth Bypass)"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        error_logger.error(
            f"Unexpected error during user creation for {username}: {str(e)}",
            extra={'ip': client_ip, 'employee_id': employee_id},
            exc_info=True
        )
        raise HTTPException(
            status_code=500, 
            detail=f"User creation failed: {str(e)}"
        )

@app.post("/change_password")
def change_password(
    request: ChangePasswordRequest,
    access_token: dict = Depends(get_current_user_token),
    http_request: Request = None
):
    """Change password for authenticated user"""
    client_ip = get_client_ip(http_request)
    username = access_token["sub"]
    
    activity_logger.info(
        f"Password change initiated for user: {username}",
        extra={'ip': client_ip}
    )
    
    try:
        # Verify current password (never log actual passwords)
        stored_hash = get_user_password_hash(username)
        if not verify_password(request.current_password, stored_hash):
            security_logger.warning(
                f"Password change failed - incorrect current password for user: {username}",
                extra={'ip': client_ip}
            )
            raise HTTPException(
                status_code=400,
                detail="Current password is incorrect"
            )
        
        # Verify new password is different
        if verify_password(request.new_password, stored_hash):
            activity_logger.warning(
                f"Password change failed - new password same as current for user: {username}",
                extra={'ip': client_ip}
            )
            raise HTTPException(
                status_code=400,
                detail="New password must be different from current password"
            )
        
        # Validate complexity (without logging the actual password)
        if not validate_password_complexity(request.new_password):
            activity_logger.warning(
                f"Password change failed - complexity requirements not met for user: {username}",
                extra={'ip': client_ip}
            )
            raise HTTPException(
                status_code=400, 
                detail="Password must be 6-14 characters and contain at least 3 of: uppercase, lowercase, numbers, special characters"
            )
        
        # Update password
        new_hash = hash_password(request.new_password)
        set_user_password_hash(username, new_hash)
        
        activity_logger.info(
            f"Password changed successfully for user: {username}",
            extra={'ip': client_ip}
        )
        
        return {"detail": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        error_logger.error(
            f"Unexpected error during password change for {username}: {str(e)}",
            extra={'ip': client_ip},
            exc_info=True
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/customers/search")
def search_my_customers(
    request: CustomerSearchRequest, 
    token_data: dict = Depends(get_current_user_token),
    http_request: Request = None
):
    client_ip = get_client_ip(http_request)
    username = token_data["sub"]

    employee_id = get_user_employee_id(username)
    
    if not employee_id:
        activity_logger.warning(f"Search failed - User {username} is not linked to an employee record")
        raise HTTPException(status_code=403, detail="User is not an employee")

    activity_logger.info(
        f"Customer search initiated by {username}",
        extra={
            'ip': client_ip,
            'filters': request.dict(exclude_none=True)
        }
    )

    try:
        # pass request.dict() to make parsing easier in db.py
        results = get_customers_for_employee(employee_id, request.dict(exclude_none=True))
        
        activity_logger.info(f"Search returned {len(results)} results for {username}")
        return {"count": len(results), "customers": results}

    except Exception as e:
        error_logger.error(f"Search error for {username}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during search")
#======
# MAIN
#======
def configure_logging():
    """Configure logging with separate handlers for different log types"""
    
    # Base configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Activity logger - tracks user actions
    activity_handler = logging.FileHandler('logs/activity.log')
    activity_handler.setFormatter(
        logging.Formatter('%(asctime)s | ACTIVITY | %(levelname)s | %(message)s', '%Y-%m-%d %H:%M:%S')
    )
    activity_logger.addHandler(activity_handler)
    activity_logger.setLevel(logging.INFO)
    
    # Security logger - tracks authentication/authorization events
    security_handler = logging.FileHandler('logs/security.log')
    security_handler.setFormatter(
        logging.Formatter('%(asctime)s | SECURITY | %(levelname)s | %(message)s', '%Y-%m-%d %H:%M:%S')
    )
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    # Error logger - tracks errors and exceptions
    error_handler = logging.FileHandler('logs/errors.log')
    error_handler.setFormatter(
        logging.Formatter('%(asctime)s | ERROR | %(levelname)s | %(message)s | %(pathname)s:%(lineno)d', '%Y-%m-%d %H:%M:%S')
    )
    error_logger.addHandler(error_handler)
    error_logger.setLevel(logging.ERROR)
    
    # Also keep general server log
    general_handler = logging.FileHandler('logs/server.log')
    general_handler.setFormatter(
        logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s', '%Y-%m-%d %H:%M:%S')
    )
    logging.getLogger().addHandler(general_handler)

def main():
    """Start the FastAPI server with configured logging"""
    configure_logging()
    
    logging.info("=" * 60)
    logging.info("SERVER STARTING")
    logging.info(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    logging.info("=" * 60)
    
    try:
        uvicorn.run(app, host="0.0.0.0", port=5000)
    except Exception as e:
        error_logger.critical(f"Server crashed: {str(e)}", exc_info=True)
    finally:
        logging.info("=" * 60)
        logging.info("SERVER SHUTTING DOWN")
        logging.info(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        logging.info("=" * 60)

if __name__ == '__main__':
    main()
