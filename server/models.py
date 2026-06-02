from extensions import db
from datetime import datetime, timezone

class Agent(db.Model):
    __tablename__ = 'agents'
    id = db.Column(db.String(36), primary_key=True) # UUID for agent
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    status = db.Column(db.String(50), default="active")
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    events = db.relationship('EventLog', backref='agent', lazy=True)
    alerts = db.relationship('Alert', backref='agent', lazy=True)

class EventLog(db.Model):
    __tablename__ = 'event_logs'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(36), db.ForeignKey('agents.id'), nullable=False)
    file_path = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(50), nullable=False) # e.g. CREATED, MODIFIED, DELETED
    entropy = db.Column(db.Float, nullable=True) # Shannon entropy score
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(36), db.ForeignKey('agents.id'), nullable=False)
    alert_type = db.Column(db.String(100), nullable=False) # e.g. HIGH_ENTROPY, MASS_MODIFICATION
    severity = db.Column(db.String(50), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    description = db.Column(db.Text, nullable=True)
    resolved = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
