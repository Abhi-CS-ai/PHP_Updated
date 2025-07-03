from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import datetime
import uuid

# 🧠 LLM + Regex Analyzer
from modules.analyzer import analyze_php_file, analyze_php_url

# Extensions and models
from extensions import db, login_manager
from models.user import User
from models.scan_result import ScanResult

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key-for-development')

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'database', 'scan_results.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(os.path.join(basedir, 'database'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email,
                    password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).limit(5).all()
    for scan in scans:
        scan.parsed_results = json.loads(scan.results)
    return render_template('dashboard.html', results=scans)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        filename, url, scan_results = None, None, None

        if scan_type == 'file':
            file = request.files.get('file')
            if not file or file.filename == '':
                flash('Please select a valid PHP file.', 'error')
                return redirect(request.url)

            if not file.filename.endswith('.php'):
                flash('Only .php files are allowed.', 'error')
                return redirect(request.url)

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            scan_results = analyze_php_file(filepath)
            os.remove(filepath)

        elif scan_type == 'url':
            url = request.form.get('url')
            if not url:
                flash('URL is required.', 'error')
                return redirect(request.url)
            scan_results = analyze_php_url(url)

        if scan_results:
            scan_id = str(uuid.uuid4())
            new_scan = ScanResult(
                id=scan_id,
                user_id=current_user.id,
                source_type=scan_type,
                source=filename if scan_type == 'file' else url,
                results=json.dumps(scan_results),
                timestamp=datetime.datetime.now()
            )
            db.session.add(new_scan)
            db.session.commit()
            return redirect(url_for('scan_result', scan_id=scan_id))

    return render_template('scan.html')

@app.route('/scan_result/<scan_id>')
@login_required
def scan_result(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    results = json.loads(scan.results)

    # Ensure consistent keys to avoid template errors
    results.setdefault("summary", {
        "total_vulnerabilities": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0
    })
    results.setdefault("vulnerabilities", [])

    try:
        results["llm_analysis_parsed"] = json.loads(results.get("llm_analysis_raw", "{}") or "{}")
    except Exception:
        results["llm_analysis_parsed"] = {}

    try:
        results["validated_findings_parsed"] = json.loads(results.get("validated_findings", "{}") or "{}")
    except Exception:
        results["validated_findings_parsed"] = {}

    return render_template('scan_result.html', scan=scan, results=results)

@app.route('/history')
@login_required
def history():
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).all()
    for scan in scans:
        scan.parsed_results = json.loads(scan.results)
    return render_template('history.html', results=scans)

@app.route('/delete_scan/<scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted successfully.', 'success')
    return redirect(url_for('history'))

@app.route('/api/export/<scan_id>')
@login_required
def export_scan(scan_id):
    scan = ScanResult.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    results = json.loads(scan.results)
    return jsonify({
        'scan_id': scan.id,
        'scan_type': scan.source_type,
        'source': scan.source,
        'timestamp': scan.timestamp.isoformat(),
        'results': results
    })

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
