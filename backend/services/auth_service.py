"""
Authentication Service
Handles login, registration, and token verification
"""

from backend.models.user_model import User, Session

class AuthService:
    """Authentication service"""
    
    @staticmethod
    def register(username, email, password):
        """Register a new user"""
        # Validate inputs
        if not username or len(username) < 3:
            return {'success': False, 'error': 'Username must be at least 3 characters'}
        
        if not email or '@' not in email:
            return {'success': False, 'error': 'Invalid email address'}
        
        if not password or len(password) < 6:
            return {'success': False, 'error': 'Password must be at least 6 characters'}
        
        # Check if username exists
        if User.username_exists(username):
            return {'success': False, 'error': 'Username already exists'}
        
        # Check if email exists
        if User.email_exists(email):
            return {'success': False, 'error': 'Email already registered'}
        
        # Create and save user
        user = User(username, email, password)
        if user.save():
            return {
                'success': True,
                'message': 'User registered successfully',
                'user': user.to_dict()
            }
        else:
            return {'success': False, 'error': 'Failed to register user'}
    
    @staticmethod
    def login(username, password):
        """Login user and return token"""
        # Validate inputs
        if not username or not password:
            return {'success': False, 'error': 'Username and password required'}
        
        # Verify credentials
        user = User.verify_credentials(username, password)
        
        if not user:
            return {'success': False, 'error': 'Invalid username or password'}
        
        # Create token
        token = Session.create_token(user.id, user.username)
        
        return {
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        }
    
    @staticmethod
    def verify_token(token):
        """Verify token and return user info"""
        payload = Session.verify_token(token)
        
        if not payload:
            return {'success': False, 'error': 'Invalid or expired token'}
        
        user = User.get_by_id(payload['user_id'])
        
        if not user:
            return {'success': False, 'error': 'User not found'}
        
        return {
            'success': True,
            'user': user.to_dict()
        }
    
    @staticmethod
    def get_user_profile(token):
        """Get user profile from token"""
        payload = Session.verify_token(token)
        
        if not payload:
            return None
        
        return User.get_by_id(payload['user_id'])
