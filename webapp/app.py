from flask import Flask, request, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from webapp.threat_engine import analyze_url

app = Flask(__name__)
app.secret_key = "supersecretkey"

# 🔥 SESSION FIX
app.config['SESSION_PERMANENT'] = False

# ---------------- CONFIG ----------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scan_history.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ---------------- MODELS ----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500))
    result = db.Column(db.String(50))
    risk_score = db.Column(db.Integer)
    user = db.Column(db.String(100))

# ❌ REMOVE THIS (no longer needed)
# import pickle
# model = pickle.load(open("model/phishing_model.pkl", "rb"))

# ---------------- AUTH ----------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        existing = User.query.filter_by(username=username).first()
        if existing:
            return "User already exists"

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        user = User(username=username, password=hashed)
        db.session.add(user)
        db.session.commit()

        return redirect("/login")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session.clear()
            session["user"] = username
            session.permanent = False
            return redirect("/")
        else:
            return "Invalid credentials"

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ---------------- HOME / SCAN ----------------

@app.route("/")
def home():
    if "user" not in session:
        return redirect("/login")

    scans = Scan.query.filter_by(user=session["user"]).order_by(Scan.id.desc()).limit(10)

    return render_template("scan.html", scans=scans)


@app.route("/scan", methods=["POST"])
def scan():
    if "user" not in session:
        return redirect("/login")

    url = request.form["url"]

    # ✅ FIXED (ONLY ONE ARGUMENT)
    result, risk_score, threats, stats = analyze_url(url)

    # Save to DB
    new_scan = Scan(
        url=url,
        result=result,
        risk_score=risk_score,
        user=session["user"]
    )

    db.session.add(new_scan)
    db.session.commit()

    scans = Scan.query.filter_by(user=session["user"]).order_by(Scan.id.desc()).limit(10)

    return render_template(
        "scan.html",
        url=url,
        result=result,
        risk_score=risk_score,
        threats=threats,
        stats=stats,
        scans=scans
    )


# ---------------- HISTORY ----------------

@app.route("/history")
def history():
    if "user" not in session:
        return redirect("/login")

    scans = Scan.query.filter_by(user=session["user"]).order_by(Scan.id.desc()).all()

    return render_template("history.html", scans=scans)


# ---------------- STATS ----------------

@app.route("/stats")
def stats():
    if "user" not in session:
        return redirect("/login")

    user = session["user"]

    total = Scan.query.filter_by(user=user).count()
    phishing = Scan.query.filter_by(user=user, result="Phishing").count()
    safe = Scan.query.filter_by(user=user, result="Safe").count()

    avg_risk = db.session.query(db.func.avg(Scan.risk_score)).filter_by(user=user).scalar()
    avg_risk = round(avg_risk or 0, 2)

    return render_template(
        "stats.html",
        total=total,
        phishing=phishing,
        safe=safe,
        avg_risk=avg_risk
    )


# ---------------- PROFILE ----------------

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect("/login")

    user = session["user"]

    total = Scan.query.filter_by(user=user).count()
    phishing = Scan.query.filter_by(user=user, result="Phishing").count()
    safe = Scan.query.filter_by(user=user, result="Safe").count()

    recent = Scan.query.filter_by(user=user).order_by(Scan.id.desc()).limit(5)

    return render_template(
        "profile.html",
        user=user,
        total=total,
        phishing=phishing,
        safe=safe,
        recent=recent
    )


# ---------------- RUN ----------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)