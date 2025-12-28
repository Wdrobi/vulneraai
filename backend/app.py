"""
VulneraAI Backend - Main Flask Application
"""

import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime
import json
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
from backend.config import Config
app.config.from_object(Config)

# Database initialization
from backend.models.scan_model import init_db
init_db()

# Database and services imports
from backend.models.scan_model import Scan
from backend.models.user_model import Session
from backend.services.scanner import VulnerabilityScanner
from backend.services.risk_assessor import RiskAssessor
from backend.services.report_generator import ReportGenerator
from backend.services.auth_service import AuthService

# Import routes
from backend.routes.auth_routes import auth_routes

# Register blueprints
app.register_blueprint(auth_routes)

# ====================================
# Authentication Middleware
# ====================================

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'success': False, 'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        # Verify token
        payload = Session.verify_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401
        
        # Pass user info to route
        request.user_id = payload['user_id']
        request.username = payload['username']
        return f(*args, **kwargs)
    
    return decorated

# ====================================
# Error Handlers
# ====================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ====================================
# Health Check
# ====================================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

# ====================================
# Scan Routes
# ====================================

@app.route('/api/scans/start', methods=['POST'])
@token_required
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scanType', 'standard')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Create new scan with user association
        scan = Scan(target=target, scan_type=scan_type, user_id=request.user_id)
        scan.save()

        # Start scanner in background (in production, use Celery)
        scanner = VulnerabilityScanner(scan.id, target, scan_type)
        scanner.start()

        return jsonify({
            'scanId': scan.id,
            'target': target,
            'scanType': scan_type,
            'status': 'started',
            'createdAt': scan.created_at.isoformat()
        }), 200

    except Exception as e:
        print(f"Error starting scan: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>/status', methods=['GET'])
@token_required
def get_scan_status(scan_id):
    """Get scan status and progress"""
    try:
        scan = Scan.get_by_id(scan_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Verify user owns this scan
        if scan.user_id != request.user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        return jsonify({
            'scanId': scan.id,
            'target': scan.target,
            'status': scan.status,
            'progress': scan.progress,
            'vulnerabilitiesFound': len(scan.vulnerabilities),
            'startedAt': scan.created_at.isoformat(),
            'updatedAt': scan.updated_at.isoformat(),
            'estimatedTimeRemaining': scan.estimate_remaining_time()
        }), 200

    except Exception as e:
        print(f"Error getting scan status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>/results', methods=['GET'])
@token_required
def get_scan_results(scan_id):
    """Get scan results and vulnerabilities"""
    try:
        scan = Scan.get_by_id(scan_id)
        
        if not scan:
            print(f"DEBUG: Scan {scan_id} not found in database")
            return jsonify({'error': 'Scan not found'}), 404
        
        # Verify user owns this scan
        if scan.user_id != request.user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        # Allow viewing results even if scan is not completed yet (for debugging)
        print(f"DEBUG: Scan {scan_id} status: {scan.status}, vulnerabilities: {len(scan.vulnerabilities)}")
        
        if scan.status != 'completed':
            print(f"DEBUG: Scan {scan_id} is still {scan.status}, returning incomplete results")
            # Return what we have so far
            pass

        return jsonify({
            'scanId': scan.id,
            'target': scan.target,
            'completedAt': scan.updated_at.isoformat(),
            'vulnerabilities': [v.to_dict() for v in scan.vulnerabilities],
            'stats': {
                'critical': sum(1 for v in scan.vulnerabilities if v.severity == 'critical'),
                'high': sum(1 for v in scan.vulnerabilities if v.severity == 'high'),
                'medium': sum(1 for v in scan.vulnerabilities if v.severity == 'medium'),
                'low': sum(1 for v in scan.vulnerabilities if v.severity == 'low')
            },
            'status': scan.status,
            'progress': scan.progress
        }), 200

    except Exception as e:
        print(f"Error getting scan results: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/<scan_id>/cancel', methods=['POST'])
@token_required
def cancel_scan(scan_id):
    """Cancel a running scan"""
    try:
        scan = Scan.get_by_id(scan_id)
        
        # Verify user owns this scan
        if scan.user_id != request.user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        scan.status = 'cancelled'
        scan.save()

        return jsonify({
            'scanId': scan.id,
            'status': 'cancelled',
            'message': 'Scan cancelled successfully'
        }), 200

    except Exception as e:
        print(f"Error cancelling scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ====================================
# Risk Assessment Routes
# ====================================

@app.route('/api/risk/<scan_id>', methods=['GET'])
@token_required
def get_risk_score(scan_id):
    """Get AI-powered risk score for a scan"""
    try:
        scan = Scan.get_by_id(scan_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Verify user owns this scan
        if scan.user_id != request.user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        # Calculate risk score
        assessor = RiskAssessor(scan)
        risk_data = assessor.assess()

        return jsonify(risk_data), 200

    except Exception as e:
        print(f"Error calculating risk score: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ====================================
# Report Routes
# ====================================

@app.route('/api/reports/history', methods=['GET'])
@token_required
def get_scan_history():
    """Get scan history for authenticated user"""
    try:
        # Get limit from query params
        limit = request.args.get('limit', default=20, type=int)
        
        # Get recent scans for user
        scans = Scan.get_recent_scans(limit, request.user_id)

        return jsonify([{
            'scanId': scan.id,
            'target': scan.target,
            'status': scan.status,
            'riskScore': scan.risk_score,
            'riskLevel': scan.risk_level,
            'vulnerabilityCount': len(scan.vulnerabilities),
            'completedAt': scan.updated_at.isoformat()
        } for scan in scans]), 200

    except Exception as e:
        print(f"Error getting scan history: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/generate', methods=['POST'])
@token_required
def generate_report():
    """Generate downloadable report"""
    try:
        data = request.get_json()
        scan_id = data.get('scanId')
        report_format = data.get('format', 'json')  # json, pdf, csv

        scan = Scan.get_by_id(scan_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Verify user owns this scan
        if scan.user_id != request.user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        # Generate report
        generator = ReportGenerator(scan)

        # Use target name for filename, sanitize it
        target_name = scan.target.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
        filename_base = f"{target_name}-report"

        # Return as file download based on requested format
        if report_format == 'pdf':
            pdf_data = generator.generate_pdf()
            # generator.generate_pdf() may return bytes (preferred) or str (fallback)
            pdf_bytes = pdf_data if isinstance(pdf_data, (bytes, bytearray)) else str(pdf_data).encode('latin-1')
            filename = f"{filename_base}.pdf"
            return Response(
                pdf_bytes,
                mimetype='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename="{filename}"'
                }
            )
        elif report_format == 'json':
            json_str = generator.generate_json()
            filename = f"{filename_base}.json"
            return Response(
                json_str,
                mimetype='application/json',
                headers={
                    'Content-Disposition': f'attachment; filename="{filename}"'
                }
            )
        elif report_format == 'csv':
            csv_str = generator.generate_csv()
            filename = f"{filename_base}.csv"
            return Response(
                csv_str,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename="{filename}"'
                }
            )
        else:
            return jsonify({'error': 'Invalid report format'}), 400

    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ====================================
# Contact Routes
# ====================================

@app.route('/api/contact', methods=['POST'])
def contact():
    """Handle contact form submissions"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'subject', 'message']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        subject = data.get('subject', '').strip()
        message = data.get('message', '').strip()
        
        # Basic validation
        if not name or not email or not subject or not message:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(message) < 10:
            return jsonify({'error': 'Message must be at least 10 characters'}), 400
        
        # In production, integrate with email service (SendGrid, AWS SES, etc.)
        # For now, log the contact message
        contact_log = {
            'timestamp': datetime.now().isoformat(),
            'name': name,
            'email': email,
            'subject': subject,
            'message': message
        }
        
        # TODO: Implement email sending via backend service
        print(f"[CONTACT] {json.dumps(contact_log)}")
        
        return jsonify({
            'success': True,
            'message': 'Thank you for contacting us. We will respond soon.'
        }), 200
        
    except Exception as e:
        print(f"Error processing contact form: {str(e)}")
        return jsonify({'error': 'Failed to process contact form'}), 500

# ====================================
# Statistics Routes
# ====================================

@app.route('/api/stats/summary', methods=['GET'])
def get_stats_summary():
    """Get overall statistics"""
    try:
        stats = {
            'totalScans': Scan.count_all(),
            'completedScans': Scan.count_by_status('completed'),
            'averageRiskScore': Scan.get_average_risk_score(),
            'criticalVulnerabilities': Scan.count_vulnerabilities_by_severity('critical'),
            'highVulnerabilities': Scan.count_vulnerabilities_by_severity('high'),
            'recentScans': 7  # Last 7 days
        }

        return jsonify(stats), 200

    except Exception as e:
        print(f"Error getting statistics: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ====================================
# Main
# ====================================

if __name__ == '__main__':
    # Create database if not exists
    from models.scan_model import init_db
    init_db()

    # Run Flask app
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    )
