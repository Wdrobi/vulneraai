"""
Authentication Routes
"""

from flask import Blueprint, request, jsonify
from backend.services.auth_service import AuthService

auth_routes = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_routes.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        result = AuthService.register(
            data.get('username'),
            data.get('email'),
            data.get('password')
        )
        
        return jsonify(result), 201 if result['success'] else 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@auth_routes.route('/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        result = AuthService.login(
            data.get('username'),
            data.get('password')
        )
        
        return jsonify(result), 200 if result['success'] else 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@auth_routes.route('/verify', methods=['POST'])
def verify_token():
    """Verify token"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token required'}), 400
        
        result = AuthService.verify_token(token)
        return jsonify(result), 200 if result['success'] else 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@auth_routes.route('/profile', methods=['GET'])
def get_profile():
    """Get user profile from token"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token required'}), 401
        
        result = AuthService.verify_token(token)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
