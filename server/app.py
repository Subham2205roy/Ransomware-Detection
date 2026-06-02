import os
from flask import Flask, request, jsonify, render_template, send_file
from functools import wraps
from datetime import datetime, timezone
from dotenv import load_dotenv
from extensions import db
import models  # This ensures models are registered with SQLAlchemy
from reporting import generate_incident_report

# Load environment variables from .env
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///ransomware.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-dev-key')
    
    # Initialize Extensions
    db.init_app(app)
    
    # Initialize Database on first run
    with app.app_context():
        db.create_all()
        
    # Security Decorator
    def require_api_key(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if api_key and api_key == os.getenv('API_KEY', 'test-api-key'):
                return f(*args, **kwargs)
            return jsonify({"error": "Unauthorized"}), 401
        return decorated_function
        
    @app.route('/')
    def index():
        agents = models.Agent.query.all()
        alerts = models.Alert.query.order_by(models.Alert.timestamp.desc()).limit(50).all()
        return render_template('dashboard.html', agents=agents, alerts=alerts)
        
    @app.route('/api/dashboard_data')
    def dashboard_data():
        agents = models.Agent.query.all()
        alerts = models.Alert.query.order_by(models.Alert.timestamp.desc()).limit(50).all()
        
        agents_data = [{
            'id': a.id,
            'hostname': a.hostname,
            'ip_address': a.ip_address,
            'last_seen': a.last_seen.strftime('%Y-%m-%d %H:%M:%S') if a.last_seen else 'N/A',
            'status': a.status
        } for a in agents]
        
        alerts_data = [{
            'id': a.id,
            'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'agent': a.agent.hostname if a.agent else a.agent_id,
            'alert_type': a.alert_type,
            'severity': a.severity,
            'description': a.description
        } for a in alerts]
        
        return jsonify({'agents': agents_data, 'alerts': alerts_data})

    @app.route('/report/download/<int:alert_id>')
    def download_report(alert_id):
        alert = models.Alert.query.get_or_404(alert_id)
        pdf_buffer = generate_incident_report(alert)
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f"REWARS_Incident_Report_{alert_id}.pdf",
            mimetype='application/pdf'
        )
        
    @app.route('/api/register', methods=['POST'])
    @require_api_key
    def register_agent():
        data = request.json
        agent_id = data.get('agent_id')
        hostname = data.get('hostname')
        ip_address = request.remote_addr
        
        if not agent_id or not hostname:
            return jsonify({"error": "Missing agent_id or hostname"}), 400
            
        agent = models.Agent.query.get(agent_id)
        if not agent:
            agent = models.Agent(id=agent_id, hostname=hostname, ip_address=ip_address)
            db.session.add(agent)
        else:
            agent.hostname = hostname
            agent.ip_address = ip_address
            agent.last_seen = datetime.now(timezone.utc)
            
        db.session.commit()
        return jsonify({"message": "Agent registered successfully", "agent_id": agent_id}), 200

    @app.route('/api/heartbeat', methods=['POST'])
    @require_api_key
    def heartbeat():
        data = request.json
        agent_id = data.get('agent_id')
        
        agent = models.Agent.query.get(agent_id)
        if not agent:
            return jsonify({"error": "Agent not found"}), 404
            
        agent.last_seen = datetime.now(timezone.utc)
        agent.status = "active"
        db.session.commit()
        
        return jsonify({"message": "Heartbeat received"}), 200

    @app.route('/api/alert', methods=['POST'])
    @require_api_key
    def create_alert():
        data = request.json
        agent_id = data.get('agent_id')
        alert_type = data.get('alert_type')
        severity = data.get('severity', 'HIGH')
        description = data.get('description', '')
        
        if not agent_id or not alert_type:
            return jsonify({"error": "Missing required fields"}), 400
            
        # Optional: Log the specific file event if included
        file_path = data.get('file_path')
        entropy = data.get('entropy')
        
        if file_path:
            event = models.EventLog(
                agent_id=agent_id,
                file_path=file_path,
                event_type='THREAT_DETECTED',
                entropy=entropy
            )
            db.session.add(event)
            
        alert = models.Alert(
            agent_id=agent_id,
            alert_type=alert_type,
            severity=severity,
            description=description
        )
        db.session.add(alert)
        db.session.commit()
        
        return jsonify({"message": "Alert recorded successfully"}), 201
        
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=os.getenv('FLASK_DEBUG', '1') == '1', port=5000)
