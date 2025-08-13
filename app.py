from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import datetime
import uuid
from modules.analyzer import analyze_php_file, analyze_php_url
from extensions import db, login_manager
from models.user import User
from models.scan_result import ScanResult

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key-for-development')

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'database', 'scan_results.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure database and upload directories exist
os.makedirs(os.path.join(basedir, 'database'), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

print("DB Path:", db_path)

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validate input
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('register'))

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(new_user)
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

    # Parse results JSON in Python before passing to the template
    for scan in scans:
        scan.parsed_results = json.loads(scan.results)

    return render_template('dashboard.html', recent_scans=scans)


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        
        # Initialize variables
        filename = None
        url = None
        scan_results = None
        
        if scan_type == 'file':
            # File upload handling
            if 'file' not in request.files:
                flash('No file part', 'error')
                return redirect(request.url)
            
            file = request.files['file']
            
            if file.filename == '':
                flash('No selected file', 'error')
                return redirect(request.url)
            
            if file and file.filename.endswith('.php'):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Analyze the PHP file
                scan_results = analyze_php_file(filepath)
                
                # Delete the file after analysis
                os.remove(filepath)
            else:
                flash('Only PHP files are allowed', 'error')
                return redirect(request.url)
        
        elif scan_type == 'url':
            url = request.form.get('url')
            if not url:
                flash('URL is required', 'error')
                return redirect(request.url)
            
            # Analyze the URL
            scan_results = analyze_php_url(url)
        
        if scan_results:
            # Create a unique ID for this scan
            scan_id = str(uuid.uuid4())
            
            # Save the scan results to the database
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
    return render_template('scan_result.html', scan=scan, results=results)

@app.route('/history')
@login_required
def history():
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).all()
    for scan in scans:
        scan.parsed_results = json.loads(scan.results)
    return render_template('history.html', scans=scans)

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
    
    response = {
        'scan_id': scan.id,
        'scan_type': scan.source_type,
        'source': scan.source,
        'timestamp': scan.timestamp.isoformat(),
        'results': results
    }
    
    return jsonify(response)

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)