"""
VulneraAI Backend - Configuration
"""

import os
from datetime import timedelta
from pathlib import Path

class Config:
    """Base configuration"""
    
    # Flask settings
    DEBUG = True
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 5000))
    SECRET_KEY = os.environ.get('SECRET_KEY', 'vulneraai-secret-key-dev-2025')
    
    # Database settings
    DATABASE_PATH = Path(__file__).parent.parent / 'data'
    DATABASE_FILE = 'vulneraai.db'
    
    # API Keys - Set these in your environment variables or .env file
    CENSYS_API_ID = os.environ.get('CENSYS_API_ID', '')
    CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET', '')
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # Scanning settings
    SCAN_TIMEOUT = 600  # 10 minutes
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017
    ]
    
    # Security settings
    MAX_SCAN_WORKERS = 5
    RATE_LIMIT_SCANS_PER_HOUR = 100
    
    # AI/ML settings (for future integration)
    ENABLE_AI_ASSESSMENT = True
    MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models')
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'vulneraai.log')
    
    # Data retention
    SCAN_DATA_RETENTION_DAYS = 90
    AUTO_CLEANUP_ENABLED = True
