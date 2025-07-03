from extensions import db
import datetime

class ScanResult(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source_type = db.Column(db.String(10), nullable=False)  # 'file' or 'url'
    source = db.Column(db.String(255), nullable=False)  # Filename or URL
    results = db.Column(db.Text, nullable=False)  # JSON string of results
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanResult {self.id}>'