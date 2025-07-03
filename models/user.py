from flask_login import UserMixin
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    # Relationship with scan results
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'