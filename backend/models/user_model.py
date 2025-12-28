import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from backend.config import Config

class User:
    """User model for authentication and profile management"""
    
    def __init__(self, username, email, password=None, user_id=None, created_at=None):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = None
        if password:
            self.password_hash = generate_password_hash(password)
        self.created_at = created_at or datetime.now().isoformat()
        self.last_login = None
        self.is_active = True
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'is_active': self.is_active
        }
    
    def save(self):
        """Save user to database"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, created_at, is_active)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.username, self.email, self.password_hash, self.created_at, 1))
            
            conn.commit()
            self.id = cursor.lastrowid
            conn.close()
            return True
        except sqlite3.IntegrityError as e:
            return False
        except Exception as e:
            print(f"Error saving user: {e}")
            return False
    
    @staticmethod
    def get_by_username(username):
        """Get user by username"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(
                    username=row[1],
                    email=row[2],
                    user_id=row[0],
                    created_at=row[4]
                )
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(
                    username=row[1],
                    email=row[2],
                    user_id=row[0],
                    created_at=row[4]
                )
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                user = User(
                    username=row[1],
                    email=row[2],
                    user_id=row[0],
                    created_at=row[4]
                )
                user.last_login = row[5]
                user.is_active = bool(row[6])
                return user
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    @staticmethod
    def verify_credentials(username, password):
        """Verify username and password"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            conn.close()
            
            if row and check_password_hash(row[3], password):
                # Update last login
                User.update_last_login(row[0])
                return User(
                    username=row[1],
                    email=row[2],
                    user_id=row[0],
                    created_at=row[4]
                )
            return None
        except Exception as e:
            print(f"Error verifying credentials: {e}")
            return None
    
    @staticmethod
    def update_last_login(user_id):
        """Update last login timestamp"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (datetime.now().isoformat(), user_id)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error updating last login: {e}")
    
    @staticmethod
    def username_exists(username):
        """Check if username already exists"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception as e:
            print(f"Error checking username: {e}")
            return False
    
    @staticmethod
    def email_exists(email):
        """Check if email already exists"""
        try:
            db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM users WHERE email = ?', (email,))
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception as e:
            print(f"Error checking email: {e}")
            return False


class Session:
    """Session management using JWT tokens"""
    
    @staticmethod
    def create_token(user_id, username):
        """Create JWT token for user"""
        import jwt
        from datetime import datetime, timedelta
        
        payload = {
            'user_id': user_id,
            'username': username,
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')
    
    @staticmethod
    def verify_token(token):
        """Verify JWT token"""
        import jwt
        
        try:
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
