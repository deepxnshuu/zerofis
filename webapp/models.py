from webapp.extensions import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text)
    result = db.Column(db.String(50))
    risk_score = db.Column(db.Integer)
    user = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())