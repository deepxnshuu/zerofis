from webapp.app import db, User, Scan

def get_all_users():
    return User.query.all()

def get_all_scans():
    return Scan.query.order_by(Scan.id.desc()).all()