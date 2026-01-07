import bcrypt
import hashlib
import re

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def validate_password_complexity(password: str) -> bool:
    """
    Validate password meets requirements:
    - Length: 6-14 characters
    - At least 3 of 4 categories: uppercase, lowercase, numbers, special chars
    """
    if len(password) < 6 or len(password) > 14:
        return False
    
    categories = 0
    
    if re.search(r'[A-Z]', password):  # Uppercase
        categories += 1
    if re.search(r'[a-z]', password):  # Lowercase
        categories += 1
    if re.search(r'[0-9]', password):  # Numbers
        categories += 1
    if re.search(r'[^A-Za-z0-9]', password):  # Special characters
        categories += 1
    
    return categories >= 3
