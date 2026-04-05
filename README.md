# ⚡ ZeroFis — AI-Powered Phishing Detection System

ZeroFis is a real-time phishing detection web application that analyzes URLs using intelligent heuristics and threat intelligence APIs to identify malicious websites and provide explainable security insights.

---

## 🌐 Live Demo
👉 https://zerofis.onrender.com

---

## 🧠 Features

- 🔍 **Real-Time URL Scanning**
- 🧠 **Heuristic-Based Detection Engine**
- 🌐 **VirusTotal API Integration**
- 🔐 **SSL Certificate Validation**
- 📊 **User Dashboard (History & Stats)**
- 👤 **Authentication System (Login/Signup)**
- ⚡ **Interactive UI with Risk Visualization**
- 🤖 **AI-Based Explanation of Results**

---

## ⚙️ Tech Stack

**Frontend**
- HTML, CSS, JavaScript
- FontAwesome Icons
- Responsive UI Design

**Backend**
- Python (Flask)
- SQLAlchemy (Database ORM)
- Flask-Bcrypt (Authentication)

**Security Engine**
- Rule-Based Heuristics
- SSL Inspection (Socket + SSL)
- VirusTotal Threat Intelligence API

**Deployment**
- Render (Cloud Hosting)
- Gunicorn (Production Server)

---

## 🧪 How It Works

1. User inputs a URL
2. System extracts features:
   - URL length
   - Special characters
   - Subdomains
   - Keywords
3. SSL certificate is validated
4. VirusTotal API checks for known threats
5. Risk score is calculated
6. Result is classified:
   - Safe
   - Suspicious
   - Phishing
7. Explanation + stats are displayed

---

## 📊 Detection Logic

ZeroFis uses a **hybrid approach**:

- 🔹 Heuristic analysis (pattern-based detection)
- 🔹 External threat intelligence (VirusTotal)
- 🔹 SSL validation
- 🔹 Domain-based risk signals

---

## 🧠 Project Architecture
User Input → Feature Extraction → Risk Engine → API Validation → Decision → UI Output


---

## 🔐 Authentication System

- Secure password hashing using bcrypt
- Session-based login system
- Separate user scan history

---

## 📂 Project Structure
webapp/
│
├── app.py
├── threat_engine.py
├── templates/
│ ├── login.html
│ ├── signup.html
│ ├── scan.html
│ ├── history.html
│ ├── stats.html
│ ├── profile.html
│
├── static/


## ⚡ Installation (Local Setup)

git clone https://github.com/yourusername/zerofis.git

cd zerofis

pip install -r requirements.txt

python webapp/app.py
