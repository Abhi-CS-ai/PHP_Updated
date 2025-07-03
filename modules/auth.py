from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from app import db

def register_user(username, email, password):
    """
    Register a new user
    
    Args:
        username (str): Username
        email (str): Email address
        password (str): Password
        
    Returns:
        tuple: (success, message)
    """
    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return False, "Email already registered"
    
    # Create new user
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email, password=hashed_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return True, "Registration successful"
    except Exception as e:
        db.session.rollback()
        return False, f"Error creating user: {str(e)}"

def authenticate_user(email, password):
    """
    Authenticate a user
    
    Args:
        email (str): Email address
        password (str): Password
        
    Returns:
        tuple: (user, message)
    """
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return None, "Invalid email or password"
    
    if not check_password_hash(user.password, password):
        return None, "Invalid email or password"
    
    return user, "Login successful"