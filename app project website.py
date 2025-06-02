
import os
import socket
import nmap
import csv
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from werkzeug.utils import secure_filename
import pyotp
from Crypto.Cipher import AES
import base64
from PIL import Image
import stepic
from io import BytesIO
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'png'}

login_manager = LoginManager()
login_manager.init_app(app)

users = {
    "user@example.com": {
        "password": "password123",
        "secret_key": pyotp.random_base32(),
        "security_answer": "blue",
        "pattern": "1479",
        "typing_pattern": "fast"
    }
}

messages = {}
aes_key = os.urandom(16)
scan_results_cache = []

class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def encrypt_text(text):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_text(encrypted_text):
    data = base64.b64decode(encrypted_text.encode())
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        if email in users:
            flash('Email already registered.', 'warning')
            return redirect(url_for('signup'))
        users[email] = {
            "password": password,
            "secret_key": pyotp.random_base32(),
            "security_answer": "blue",
            "pattern": "1479",
            "typing_pattern": "fast"
        }
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        if email in users and users[email]["password"] == password:
            session['pending_user'] = email
            return redirect(url_for('pattern_unlock'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/pattern_unlock', methods=['GET', 'POST'])
def pattern_unlock():
    if request.method == 'POST':
        pattern = request.form.get('pattern')
        email = session.get('pending_user')
        if email and users[email]["pattern"] == pattern:
            return redirect(url_for('typing_test'))
        flash("Wrong pattern!", 'danger')
    return render_template('pattern_unlock.html')

@app.route('/typing_test', methods=['GET', 'POST'])
def typing_test():
    if request.method == 'POST':
        speed = request.form.get('speed')
        email = session.get('pending_user')
        if email and users[email]["typing_pattern"] == speed:
            return redirect(url_for('security_question'))
        flash("Typing test failed.", 'danger')
    return render_template('typing_test.html')

@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if request.method == 'POST':
        answer = request.form.get('answer')
        email = session.get('pending_user')
        if email and users[email]["security_answer"].lower() == answer.lower():
            user = User(email)
            login_user(user)
            session.pop('pending_user', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash("Security question incorrect.", 'danger')
    return render_template('security_question.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_ip = request.remote_addr
    filename = request.args.get('filename')
    user_inbox = messages.get(current_user.id, [])
    inbox = [{'from': m['from'], 'text': decrypt_text(m['text']), 'time': m['time']} for m in user_inbox]
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in request.', 'warning')
            return redirect(url_for('dashboard'))
        file = request.files['file']
        if file.filename == '':
            flash('No selected file.', 'warning')
            return redirect(url_for('dashboard'))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('dashboard', filename=filename))
    return render_template('dashboard.html', user_ip=user_ip, filename=filename, inbox=inbox)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    recipient = request.form.get('recipient')
    message = request.form.get('message')
    if not recipient or not message:
        flash('Both recipient and message are required.', 'warning')
        return redirect(url_for('dashboard'))
    if recipient not in users:
        flash('Recipient does not exist.', 'danger')
        return redirect(url_for('dashboard'))
    encrypted = encrypt_text(message)
    if recipient not in messages:
        messages[recipient] = []
    messages[recipient].append({
        'from': current_user.id,
        'text': encrypted,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    flash('Message sent successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/scan_ip', methods=['GET', 'POST'])
@login_required
def scan_ip():
    ip_result = None
    if request.method == 'POST':
        domain = request.form.get('domain')
        try:
            ip_result = socket.gethostbyname(domain)
        except Exception as e:
            flash(f"Error: {str(e)}", 'danger')
    return render_template('scan_ip.html', ip_result=ip_result)

@app.route('/nmap_scan', methods=['GET', 'POST'])
@login_required
def nmap_scan():
    global scan_results_cache
    results = []
    target = None
    if request.method == 'POST':
        target = request.form.get('target')
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='-F')
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        entry = {
                            'host': host,
                            'protocol': proto,
                            'port': port,
                            'state': nm[host][proto][port]['state'],
                            'service': nm[host][proto][port].get('name', 'unknown')
                        }
                        results.append(entry)
            scan_results_cache = results
        except Exception as e:
            flash(f"Scan failed: {str(e)}", 'danger')
    return render_template('nmap_scan.html', results=scan_results_cache, target=target)

@app.route('/download_scan_results')
@login_required
def download_scan_results():
    output = BytesIO()
    writer = csv.writer(output)
    writer.writerow(['Host', 'Protocol', 'Port', 'State', 'Service'])
    for entry in scan_results_cache:
        writer.writerow([entry['host'], entry['protocol'], entry['port'], entry['state'], entry.get('service', 'unknown')])
    output.seek(0)
    return send_file(output, mimetype='text/csv', download_name='nmap_results.csv', as_attachment=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
