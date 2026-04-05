from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

from webapp.threat_engine import analyze_url

app = Flask(__name__)

# 🔐 SECRET KEY
app.secret_key = os.getenv("SECRET_KEY", "dev_secret")

# 🗄️ DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ==========================
# 🧑 USER MODEL
# ==========================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# ==========================
# 📊 SCAN MODEL
# ==========================
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text)
    result = db.Column(db.String(50))
    risk_score = db.Column(db.Integer)
    user = db.Column(db.String(100))

# ==========================
# 🔥 CREATE DB
# ==========================
with app.app_context():
    db.create_all()

# ==========================
# 🏠 HOME
# ==========================
@app.route('/')
def home():
    if 'user' in session:
        return redirect('/scan')
    return redirect('/login')

# ==========================
# 🔐 SIGNUP
# ==========================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        if User.query.filter_by(username=username).first():
            return "User already exists"

        db.session.add(User(username=username, password=password))
        db.session.commit()

        return redirect('/login')

    return render_template('signup.html')

# ==========================
# 🔐 LOGIN
# ==========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user'] = username
            return redirect('/scan')

        return "Invalid credentials"

    return render_template('login.html')

# ==========================
# 🚪 LOGOUT
# ==========================
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ==========================
# 🔍 SCAN (FIXED)
# ==========================
@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if 'user' not in session:
        return redirect('/login')

    if request.method == 'POST':
        url = request.form['url']

        try:
            data = analyze_url(url)

            result = data[0]
            risk_score = data[1]
            threats = data[2] if len(data) > 2 else []
            stats = data[3] if len(data) > 3 else {}

        except Exception as e:
            result = "Error"
            risk_score = 0
            threats = [str(e)]
            stats = {}

        # 💾 SAVE
        db.session.add(Scan(
            url=url,
            result=result,
            risk_score=risk_score,
            user=session['user']
        ))
        db.session.commit()

        return render_template(
            'scan.html',
            result=result,
            risk_score=risk_score,
            threats=threats,
            stats=stats,
            url=url
        )

    return render_template('scan.html')

# ==========================
# 📜 HISTORY
# ==========================
@app.route('/history')
def history():
    if 'user' not in session:
        return redirect('/login')

    scans = Scan.query.filter_by(user=session['user']).all()
    return render_template('history.html', scans=scans)

# ==========================
# 📊 STATS
# ==========================
@app.route('/stats')
def stats():
    if 'user' not in session:
        return redirect('/login')

    scans = Scan.query.filter_by(user=session['user']).all()

    total = len(scans)
    phishing = len([s for s in scans if s.result == "Phishing"])
    safe = len([s for s in scans if s.result == "Safe"])

    avg_risk = round(sum(s.risk_score for s in scans) / total, 2) if total > 0 else 0

    return render_template(
        'stats.html',
        total=total,
        phishing=phishing,
        safe=safe,
        avg_risk=avg_risk
    )

# ==========================
# 👤 PROFILE
# ==========================
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')

    scans = Scan.query.filter_by(user=session['user']).all()

    total = len(scans)
    phishing = len([s for s in scans if s.result == "Phishing"])
    safe = len([s for s in scans if s.result == "Safe"])

    return render_template(
        'profile.html',
        user=session['user'],
        total=total,
        phishing=phishing,
        safe=safe,
        scans=scans[:5]
    )

# ==========================
# 🚀 RUN
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)