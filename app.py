import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta
from dotenv import load_dotenv

# ─────────────────────────────────────────────
# Load .env file
# ─────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)

# ─────────────────────────────────────────────
# App Config
# ─────────────────────────────────────────────
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-dev-key-change-in-production')
app.permanent_session_lifetime = timedelta(minutes=15)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE']   = False  
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ─────────────────────────────────────────────
# AWS S3 Config
# ─────────────────────────────────────────────
S3_BUCKET = os.environ.get('S3_BUCKET', 'aws-project-virtualclassroom')
S3_REGION = os.environ.get('S3_REGION', 'eu-north-1')

s3 = boto3.client(
    's3',
    region_name=S3_REGION,
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)

# ─────────────────────────────────────────────
# Database Config
# ─────────────────────────────────────────────
DB_HOST     = os.environ.get('DB_HOST')
DB_USER     = os.environ.get('DB_USER', 'admin')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME     = os.environ.get('DB_NAME', 'virtual_classroom')

# ─────────────────────────────────────────────
# File Upload Config
# ─────────────────────────────────────────────
ALLOWED_TYPES = {'application/pdf', 'image/jpeg', 'image/png'}
MAX_FILE_SIZE  = 5 * 1024 * 1024  # 5 MB


# ─────────────────────────────────────────────
# Helper: DB Connection
# ─────────────────────────────────────────────
def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5
    )


# ─────────────────────────────────────────────
# Helper: File Size Check
# ─────────────────────────────────────────────
def get_file_size(file):
    file.seek(0, 2)        
    size = file.tell()    
    file.seek(0)           
    return size


# ─────────────────────────────────────────────
# Route: Home
# ─────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html')


# ─────────────────────────────────────────────
# Route: Register
# ─────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validation
        if not email or not password:
            flash('Email and password are required!', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        try:
            conn   = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (email, hashed_password)
            )
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        except pymysql.MySQLError as e:
            if e.args[0] == 1062:
                flash('This email is already registered!', 'danger')
            else:
                flash(f"Database Error: {str(e)}", 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')


# ─────────────────────────────────────────────
# Route: Login
# ─────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Validation
        if not username or not password:
            flash('Username and password are required!', 'danger')
            return render_template('login.html')

        try:
            conn   = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session.permanent = True
                session['username'] = username
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('content'))
            else:
                flash('Invalid email or password!', 'danger')

        except pymysql.MySQLError as e:
            flash(f"Database Error: {str(e)}", 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')


# ─────────────────────────────────────────────
# Route: Content (Upload + List Files)
# ─────────────────────────────────────────────
@app.route('/content', methods=['GET', 'POST'])
def content():
    # Login check
    if 'username' not in session:
        flash('Please login to access content!', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')

        if not file or file.filename == '':
            flash('No file selected!', 'danger')

        else:
            size = get_file_size(file)

            if size > MAX_FILE_SIZE:
                flash('File size exceeds 5MB limit!', 'danger')

            elif file.mimetype not in ALLOWED_TYPES:
                flash('Only PDF, JPG, PNG files are allowed!', 'danger')

            else:
                try:
                    # Secure + Unique filename
                    safe_name   = secure_filename(file.filename)
                    unique_name = f"{uuid.uuid4()}_{safe_name}"

                    # Upload to S3
                    s3.upload_fileobj(
                        file,
                        S3_BUCKET,
                        unique_name,
                        ExtraArgs={'ContentType': file.mimetype}
                    )
                    flash(f'"{safe_name}" uploaded successfully!', 'success')

                except Exception as e:
                    flash(f"Upload error: {str(e)}", 'danger')

    # Fetch files from S3 with Presigned URLs
    files = []
    try:
        response = s3.list_objects_v2(Bucket=S3_BUCKET)
        for obj in response.get('Contents', []):
            url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': S3_BUCKET, 'Key': obj['Key']},
                ExpiresIn=900  # 15 minutes
            )
            files.append({
                'key'          : obj['Key'],
                'size'         : round(obj['Size'] / 1024, 2),  # KB
                'last_modified': obj['LastModified'],
                'url'          : url
            })
    except Exception as e:
        flash(f"Error fetching files: {str(e)}", 'danger')

    return render_template('content.html', files=files)


# ─────────────────────────────────────────────
# Route: Logout
# ─────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'info')
    return redirect(url_for('home'))


# ─────────────────────────────────────────────
# Run App
# ─────────────────────────────────────────────
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)