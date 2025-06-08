from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory, abort, jsonify
from flask_pymongo import PyMongo
from bson import ObjectId
from datetime import datetime, timedelta
import os
import pymongo
import re
import json
import requests
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from secure_config import get_mail_config

# Load environment variables from .env file if it exists
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def datetimeformat(value, format='%b %d, %Y'):
    if isinstance(value, str):
        value = datetime.strptime(value, '%Y-%m-%d')
    return value.strftime(format)

app = Flask(__name__)
app.jinja_env.filters['datetimeformat'] = datetimeformat
# Get MongoDB URI from environment variable with fallback
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb+srv://chesstournamentcop:chesstournamentcop@cluster0.nyy0f8e.mongodb.net/chess_tournament?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=false')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg'}

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

# Get encrypted email configuration
mail_config = get_mail_config()
app.config['MAIL_USERNAME'] = mail_config['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = mail_config['MAIL_PASSWORD']
app.config['MAIL_DEFAULT_SENDER'] = mail_config['MAIL_DEFAULT_SENDER']
app.config['VERIFICATION_SALT'] = os.environ.get('VERIFICATION_SALT', 'email-verification-salt')

# Initialize PyMongo with error handling
try:
    # Parse URI to determine if SSL options are needed
    mongo_uri = app.config['MONGO_URI']
    
    # Configure additional client options 
    client_options = {
        "serverSelectionTimeoutMS": 5000,  # 5 seconds timeout for server selection
        "connectTimeoutMS": 10000,  # 10 seconds timeout for connection
        "socketTimeoutMS": 30000,  # 30 seconds timeout for socket operations
        "maxPoolSize": 10,  # Maximum connection pool size
        "minPoolSize": 1,  # Minimum connection pool size
        "retryWrites": True,  # Enable retry writes
    }
    
    # Create PyMongo client with options
    mongo = PyMongo(app, connect=False)
    
    # Test connection
    mongo.db.command('ping')
    logger.info("MongoDB connection successful")
except Exception as e:
    logger.error(f"MongoDB connection error: {e}")
    # Keep using PyMongo but don't crash the app if the initial connection fails
    mongo = PyMongo(app, connect=False)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Email verification functions
def generate_verification_token(email):
    """Generate a verification token for email verification"""
    return serializer.dumps(email, salt=app.config['VERIFICATION_SALT'])

def confirm_verification_token(token, expiration=3600):
    """Confirm the verification token"""
    try:
        email = serializer.loads(
            token,
            salt=app.config['VERIFICATION_SALT'],
            max_age=expiration
        )
        return email
    except (SignatureExpired, BadSignature):
        return None

def send_verification_email(user_email, verification_link):
    """Send verification email to user"""
    msg = MIMEMultipart()
    msg['Subject'] = 'Chess Tournament - Verify Your Email'
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = user_email

    body = f"""
    <html>
    <body style="font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;">
    <div style="max-width: 600px; margin: 60px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);">
    <div style="background: linear-gradient(to right, #1e3c72, #2a5298); padding: 24px 30px;">
    <h2 style="margin: 0; color: #ffffff; font-size: 24px; text-align: center;">Welcome to the Chess Tournament Hub!</h2>
    </div>
    <div style="padding: 30px;">
    <p style="font-size: 16px; color: #333333; line-height: 1.6;">
    Hi there,
    <br><br>
    Thank you for registering with us! To get started, please verify your email address by clicking the button below:
    </p>
    <div style="text-align: center; margin: 40px 0;">
    <a href="{verification_link}" style="background: linear-gradient(to right, #1a73e8, #4285f4); color: #ffffff; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 10px rgba(26, 115, 232, 0.3); display: inline-block;">Verify Email Address</a>
    </div>
    <p style="font-size: 14px; color: #555555;">
    Please note: This link will expire in <strong>1 hour</strong>.
    </p>
    <p style="font-size: 14px; color: #999999; margin-top: 30px;">
    Didn't sign up for the Chess Tournament Hub? You can safely ignore this message.
    </p>
    </div>
    <div style="background-color: #f0f0f0; padding: 16px; text-align: center; font-size: 12px; color: #777777;">
    &copy; 2025 Chess Tournament Hub. All rights reserved.
    </div>
    </div>
    </body>
    </html>
    """

    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        logger.info(f"Verification email sent to {user_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending verification email: {e}")
        return False

# After the existing email verification functions, add new functions for password reset

def generate_password_reset_token(email):
    """Generate a password reset token"""
    return serializer.dumps(email, salt='password-reset-salt')

def confirm_password_reset_token(token, expiration=3600):
    """Confirm the password reset token with 1-hour expiration"""
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
        return email
    except (SignatureExpired, BadSignature):
        return None

def send_password_reset_email(user_email, reset_link):
    """Send password reset email to user"""
    msg = MIMEMultipart()
    msg['Subject'] = 'Chess Tournament - Password Reset'
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = user_email

    body = f"""
    <html>
    <body style="font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;">
    <div style="max-width: 600px; margin: 60px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);">
    <div style="background: linear-gradient(to right, #c31432, #240b36); padding: 24px 30px;">
    <h2 style="margin: 0; color: #ffffff; font-size: 24px; text-align: center;">Chess Tournament Hub – Password Reset</h2>
    </div>
    <div style="padding: 30px;">
    <p style="font-size: 16px; color: #333333; line-height: 1.6;">
    Hello,
    <br><br>
    We received a request to reset your password. You can set a new password by clicking the button below:
    </p>
    <div style="text-align: center; margin: 40px 0;">
    <a href="{reset_link}" style="background: linear-gradient(to right, #d32f2f, #b71c1c); color: #ffffff; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-size: 16px; font-weight: 600; box-shadow: 0 4px 10px rgba(179, 38, 30, 0.3); display: inline-block;">Reset Password</a>
    </div>
    <p style="font-size: 14px; color: #555555;">
    Please note: This link will expire in <strong>1 hour</strong>.
    </p>
    <p style="font-size: 14px; color: #999999; margin-top: 30px;">
    If you did not request a password reset, no further action is needed. You can safely ignore this message.
    </p>
    </div>
    <div style="background-color: #f0f0f0; padding: 16px; text-align: center; font-size: 12px; color: #777777;">&copy; 2025 Chess Tournament Hub. All rights reserved.</div>
    </div>
    </body>
    </html>
    """

    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        logger.info(f"Password reset email sent to {user_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending password reset email: {e}")
        return False

# Helper function to get location data for an IP address
def get_ip_location(ip_address):
    logger.info(f"Getting location data for IP: {ip_address}")
    location = {}
    # Try multiple IP geolocation services
    services = [
        f"https://ipapi.co/{ip_address}/json/",
        f"https://ipinfo.io/{ip_address}/json",
        f"https://freegeoip.app/json/{ip_address}"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for service_url in services:
        try:
            logger.info(f"Trying geolocation service: {service_url}")
            response = requests.get(service_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                location_data = response.json()
                logger.info(f"Got response from {service_url}: {location_data}")
                
                # Store the raw JSON response in ip_add_json collection
                store_ip_json(ip_address, location_data, service_url)
                
                # Format data based on which service we got a response from
                if 'ipapi.co' in service_url:
                    location = {
                        'country': location_data.get('country_name'),
                        'country_code': location_data.get('country_code'),
                        'region': location_data.get('region'),
                        'region_code': location_data.get('region_code'),
                        'city': location_data.get('city'),
                        'zip': location_data.get('postal'),
                        'latitude': location_data.get('latitude'),
                        'longitude': location_data.get('longitude'),
                        'timezone': location_data.get('timezone'),
                        'isp': location_data.get('org'),
                        'asn': location_data.get('asn')
                    }
                elif 'ipinfo.io' in service_url:
                    loc = location_data.get('loc', '').split(',')
                    latitude = loc[0] if len(loc) > 0 else None
                    longitude = loc[1] if len(loc) > 1 else None
                    
                    location = {
                        'country': location_data.get('country'),
                        'region': location_data.get('region'),
                        'city': location_data.get('city'),
                        'zip': location_data.get('postal'),
                        'latitude': latitude,
                        'longitude': longitude,
                        'timezone': location_data.get('timezone'),
                        'isp': location_data.get('org')
                    }
                elif 'freegeoip.app' in service_url:
                    location = {
                        'country': location_data.get('country_name'),
                        'country_code': location_data.get('country_code'),
                        'region': location_data.get('region_name'),
                        'region_code': location_data.get('region_code'),
                        'city': location_data.get('city'),
                        'zip': location_data.get('zip_code'),
                        'latitude': location_data.get('latitude'),
                        'longitude': location_data.get('longitude'),
                        'timezone': location_data.get('time_zone')
                    }
                
                # If we got location data, try to enhance it with more detailed address
                if location.get('latitude') and location.get('longitude'):
                    try:
                        geo_response = requests.get(
                            f"https://nominatim.openstreetmap.org/reverse?format=json&lat={location['latitude']}&lon={location['longitude']}&zoom=18&addressdetails=1",
                            headers={'User-Agent': 'ChessTournament/1.0'}, 
                            timeout=5
                        )
                        if geo_response.status_code == 200:
                            geo_data = geo_response.json()
                            if 'address' in geo_data:
                                location['detailed_address'] = geo_data['address']
                                
                                # Store OpenStreetMap data as well
                                store_ip_json(ip_address, geo_data, "OpenStreetMap")
                    except Exception as geo_error:
                        logger.error(f"Error getting detailed geo data: {geo_error}")
                
                # We have data, no need to try other services
                break
        except Exception as e:
            logger.error(f"Error with service {service_url}: {e}")
    
    return location

# Function to store the raw IP JSON data
def store_ip_json(ip_address, json_data, source):
    try:
        # Create document to store in ip_add_json collection
        ip_json_doc = {
            'ip_address': ip_address,
            'json_data': json_data,
            'source': source,
            'timestamp': datetime.utcnow()
        }
        
        # Store in the ip_add_json collection
        mongo.db.ip_add_json.insert_one(ip_json_doc)
        logger.info(f"Stored IP JSON data for {ip_address} from {source}")
    except Exception as e:
        logger.error(f"Error storing IP JSON data: {e}")

class IP_JSON:
    def __init__(self, ip_address, json_data, source):
        self.ip_address = ip_address
        self.json_data = json_data
        self.source = source
        self.timestamp = datetime.utcnow()
    
    @staticmethod
    def get_collection():
        return mongo.db.ip_add_json

class VisitorLog:
    def __init__(self, ip_address, headers, location=None, page=None, timestamp=None, tournament_id=None, tournament_title=None):
        self.ip_address = ip_address
        self.headers = headers
        self.location = location or {}
        self.page = page
        self.timestamp = timestamp or datetime.utcnow()
        self.tournament_id = tournament_id
        self.tournament_title = tournament_title
    
    @staticmethod
    def get_collection():
        return mongo.db.visitor_logs

class Organizer:
    def __init__(self, username, password, name, type, location, contact=None, is_admin=False, email_verified=False):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.name = name
        self.type = type
        self.location = location
        self.contact = contact or {}
        self.is_admin = is_admin
        self.email_verified = email_verified
        self.created_at = datetime.utcnow()

    @staticmethod
    def get_collection():
        return mongo.db.organizers

class Tournament:
    def __init__(self, organizer_id, title, fide_status, prize_details, 
                 age_categories, gender_category, mode, format, state, dates, tournament_type=None):
        self.organizer_id = organizer_id
        self.title = title
        self.fide_status = fide_status
        self.prize_details = prize_details
        self.age_categories = age_categories
        self.gender_category = gender_category
        self.mode = mode
        self.format = format
        self.state = state
        self.dates = dates
        self.description = ''
        self.files = []
        self.created_at = datetime.utcnow()
        self.tournament_type = tournament_type  # Field for tournament type: Classical, Rapid, or Blitz
        # No longer setting time_control based on tournament type

    @staticmethod
    def get_collection():
        return mongo.db.tournaments

@app.route('/tournament/<tournament_id>')
def tournament_detail(tournament_id):
    tournament = Tournament.get_collection().find_one({'_id': ObjectId(tournament_id)})
    if not tournament:
        abort(404)
    
    organizer = Organizer.get_collection().find_one({'_id': ObjectId(tournament['organizer_id'])})
    return render_template('tournament_detail.html', 
                         tournament=tournament,
                         organizer=organizer)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def home():
    filters = {}
    
    # Apply filters only if they are provided
    if request.args.get('state'):
        filters['state'] = request.args.get('state')
    if request.args.get('format'):
        filters['format'] = request.args.get('format')
    if request.args.get('fide') == 'yes':
        filters['fide_status'] = True
    if request.args.get('gender') and request.args.get('gender') != 'Open':
        filters['gender_category'] = {'$in': [request.args.get('gender'), 'Open']}
    
    # Age filtering - search within the array of age_categories with regex
    if request.args.getlist('age'):
        age_filters = []
        for age in request.args.getlist('age'):
            age_filters.append({'age_categories': {'$regex': age, '$options': 'i'}})
        if age_filters:
            filters['$or'] = age_filters
    
    if request.args.get('mode'):
        filters['mode'] = request.args.get('mode')
    if request.args.get('tournament_type'):
        filters['tournament_type'] = request.args.get('tournament_type')
    
    # Date filtering
    if request.args.get('start_date') and request.args.get('end_date'):
        filters['dates'] = {
            '$gte': datetime.strptime(request.args['start_date'], '%Y-%m-%d'),
            '$lte': datetime.strptime(request.args['end_date'], '%Y-%m-%d')
        }
    
    # Fetch tournaments based on filters
    tournaments = []
    try:
        tournaments = list(Tournament.get_collection().find(filters).sort('created_at', -1))
    except Exception as e:
        logger.error(f"Error fetching tournaments: {e}")
        flash("Could not connect to the database. Please try again later.", "warning")
    
    current_year = datetime.now().year
    return render_template('home.html', tournaments=tournaments, current_year=current_year)

# Authentication routes
# In the registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')

        # Password complexity validation
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters')
            return redirect(url_for('register'))
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])', password):
            flash('Password must contain: 1 uppercase, 1 lowercase, 1 number, 1 special character')
            return redirect(url_for('register'))
        if username.lower() in password.lower():
            flash('Password cannot contain your username')
            return redirect(url_for('register'))
        
        if mongo.db.organizers.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('register'))
        if not email:
            flash('Email is required')
            return redirect(url_for('register'))
        if mongo.db.organizers.find_one({'contact.email': email}):
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Check if this is an admin account
        is_admin = request.form.get('type') == 'admin'
        
        # Create new organizer (with email_verified=False, unless it's an admin)
        organizer = Organizer(
            username=username,
            password=request.form['password'],
            name=request.form['name'],
            type=request.form.get('type'),
            location=request.form.get('location'),
            contact={
                'whatsapp': request.form.get('whatsapp'),
                'email': email
            },
            is_admin=is_admin,
            email_verified=is_admin  # Auto-verify admin emails
        )
        
        # Insert organizer record first
        organizer_id = Organizer.get_collection().insert_one(organizer.__dict__).inserted_id
        
        # For non-admin accounts, send verification email if mail is configured
        if not is_admin and app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
            # Generate verification token and URL
            token = generate_verification_token(email)
            verify_url = url_for('verify_email', token=token, _external=True)
            
            # Send verification email
            email_sent = send_verification_email(email, verify_url)
            if email_sent:
                flash('Registration successful! Please check your email to verify your account.')
            else:
                flash('Registration successful, but there was a problem sending the verification email. Please contact support.')
        else:
            # Admin accounts are automatically verified
            if is_admin:
                flash('Admin account created successfully! You can now login.')
            else:
                logger.warning("Email credentials not configured. Skipping email verification.")
                # If email settings aren't configured, mark as verified automatically
                Organizer.get_collection().update_one(
                    {'_id': ObjectId(organizer_id)},
                    {'$set': {'email_verified': True}}
                )
                flash('Registration successful! Please login.')
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash('The verification link is invalid or has expired.')
        return redirect(url_for('login'))
    
    # Find organizer with this email and update verification status
    organizer = mongo.db.organizers.find_one({'contact.email': email})
    if organizer:
        mongo.db.organizers.update_one(
            {'_id': organizer['_id']},
            {'$set': {'email_verified': True}}
        )
        flash('Your email has been verified! You can now login.')
    else:
        flash('There was a problem verifying your email.')
    
    return redirect(url_for('login'))

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        organizer = mongo.db.organizers.find_one({'contact.email': email})
        
        if not organizer:
            flash('No account found with that email address.')
            return render_template('resend_verification.html')
        
        if organizer.get('email_verified', False):
            flash('This email is already verified. You can login now.')
            return redirect(url_for('login'))
        
        # Generate new token and send verification email
        token = generate_verification_token(email)
        verify_url = url_for('verify_email', token=token, _external=True)
        
        if send_verification_email(email, verify_url):
            flash('Verification email has been sent. Please check your inbox.')
            return redirect(url_for('login'))
        else:
            flash('There was a problem sending the verification email. Please try again later.')
    
    return render_template('resend_verification.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Find the organizer by username
        organizer = Organizer.get_collection().find_one({'username': username})
        
        if organizer and 'password_hash' in organizer and check_password_hash(organizer['password_hash'], password):
            # Set session variables - skip email verification since username exists in database
            session['organizer_id'] = str(organizer['_id'])
            session['is_admin'] = organizer.get('is_admin', False)
            
            # Redirect based on admin status
            if session['is_admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/organizer-profile', endpoint='organizer_profile')
def organizer_profile():
    if 'organizer_id' not in session:
        return redirect(url_for('login'))
    organizer = Organizer.get_collection().find_one({'_id': ObjectId(session['organizer_id'])})
    tournaments = list(Tournament.get_collection().find({'organizer_id': session['organizer_id']}).sort('created_at', -1))
    return render_template('organizer_profile.html', organizer=organizer, tournaments=tournaments)

@app.route('/dashboard')
def dashboard():
    if 'organizer_id' not in session:
        return redirect(url_for('login'))
    tournaments = list(Tournament.get_collection().find({'organizer_id': session['organizer_id']}).sort('created_at', -1))
    return render_template('dashboard.html', tournaments=tournaments)

@app.route('/admin')
def admin_panel():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    # Convert the cursor to a list to ensure we can access the tournaments in the template
    tournaments = list(Tournament.get_collection().find().sort('created_at', -1))
    # Convert the cursor to a list to ensure we can access the organizers in the template
    organizers = list(Organizer.get_collection().find().sort('created_at', -1))
    
    # Get visitor analytics data
    total_visitors = VisitorLog.get_collection().count_documents({})
    
    # Count visitors from today
    today_start = datetime.combine(datetime.today(), datetime.min.time())
    visitors_today = VisitorLog.get_collection().count_documents({
        'timestamp': {'$gte': today_start}
    })
    
    # Count unique visitors (by IP address)
    unique_ips = VisitorLog.get_collection().distinct('ip_address')
    unique_visitors = len(unique_ips)
    
    # Count unique visitors today
    unique_visitors_today = len(VisitorLog.get_collection().distinct('ip_address', {
        'timestamp': {'$gte': today_start}
    }))
    
    # Count of total IP JSON records
    ip_json_count = mongo.db.ip_add_json.count_documents({})
    
    return render_template('admin_panel.html', 
                          tournaments=tournaments, 
                          organizers=organizers,
                          total_visitors=total_visitors,
                          visitors_today=visitors_today,
                          unique_visitors=unique_visitors,
                          unique_visitors_today=unique_visitors_today,
                          ip_json_count=ip_json_count)

@app.route('/create-tournament', methods=['GET', 'POST'])
def create_tournament():
    if 'organizer_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Process start and end dates
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            dates = [start_date, end_date] if start_date != end_date else [start_date]
            
            # Get age range from the single text field
            age_range = request.form.get('age_range', '').strip()
            
            tournament = Tournament(
                organizer_id=session['organizer_id'],
                title=request.form['title'],
                fide_status=request.form.get('fide_status', 'no') == 'yes',
                prize_details=request.form['prize_details'],
                age_categories=[age_range],  # Use the age_range field directly
                gender_category=request.form['gender_category'],
                mode=request.form['mode'],
                format=request.form['format'],
                state=request.form['state'],
                dates=dates,
                tournament_type=request.form.get('tournament_type')
            )
            tournament.description = request.form.get('description', '')
            tournament.entry_fee = request.form.get('entry_fee', '0')
            
            if 'file' in request.files:
                file = request.files['file']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    tournament.files.append(filename)
            
            Tournament.get_collection().insert_one(tournament.__dict__)
            flash('Tournament created successfully!')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error creating tournament: {str(e)}')
    
    return render_template('create_tournament.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/logout')
def logout():
    session.pop('organizer_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('home'))

# Add middleware to track visitor information
@app.before_request
def track_visitor():
    # Only track home page and tournament detail pages
    track_pages = ['home', 'tournament_detail']
    if request.endpoint not in track_pages:
        return
    
    try:
        # Get real IP address with fallbacks for proxy servers
        ip_address = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            ip_address = request.headers.get('X-Real-IP')
        elif request.headers.get('CF-Connecting-IP'):  # Cloudflare
            ip_address = request.headers.get('CF-Connecting-IP')
        
        # Get current page path
        current_page = request.path
        
        # Get tournament ID if applicable
        tournament_id = None
        if request.endpoint == 'tournament_detail' and 'tournament_id' in request.view_args:
            tournament_id = request.view_args['tournament_id']
        
        # Check for existing visit from this IP to this page within past 24 hours
        try:
            twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
            existing_visit = VisitorLog.get_collection().find_one({
                'ip_address': ip_address,
                'page': current_page,
                'tournament_id': tournament_id,  # Will be None for home page, actual ID for tournament detail
                'timestamp': {'$gte': twenty_four_hours_ago}
            })
            
            # If we found an existing visit from this IP to this page in the last 24 hours, don't create a new log
            if existing_visit:
                logger.info(f"Skipping duplicate visit log for {ip_address} on {current_page}")
                return
        except Exception as db_err:
            logger.warning(f"Could not check for existing visits: {db_err}")
        
        logger.info(f"Track visitor: {ip_address} on page {request.endpoint}")
        
        # Get browser headers (convert to dict for storage)
        headers = {key: value for key, value in request.headers.items()}
        
        # Get location data from IP using our helper function
        location = {}
        try:
            location = get_ip_location(ip_address)
        except Exception as loc_err:
            logger.warning(f"Could not get location data: {loc_err}")
        
        # Add tournament info if viewing a tournament detail page
        tournament_title = None
        if tournament_id:
            try:
                tournament = Tournament.get_collection().find_one({'_id': ObjectId(tournament_id)})
                if tournament:
                    tournament_title = tournament.get('title')
            except Exception as e:
                logger.error(f"Error getting tournament details: {e}")
        
        # Store session ID to link with real IP later
        session_id = session.get('_id', str(ObjectId()))
        session['_id'] = session_id
        
        # Create visitor log
        visitor_log = VisitorLog(
            ip_address=ip_address,
            headers=headers,
            location=location,
            page=current_page,
            tournament_id=tournament_id,
            tournament_title=tournament_title
        )
        visitor_log.session_id = session_id  # Add session ID for linking
        visitor_log.reported_ip = ip_address  # Store this as reported IP
        visitor_log.real_ips = []  # Will be populated via JavaScript detection
        
        # Save to MongoDB
        try:
            VisitorLog.get_collection().insert_one(visitor_log.__dict__)
            logger.info(f"Created visitor log for {ip_address} on {current_page}")
        except Exception as e:
            logger.error(f"Error saving visitor log: {e}")

    except Exception as e:
        # Log the error but don't fail the request
        logger.error(f"Error tracking visitor: {e}")
        # Continue processing the request

@app.route('/admin/visitor-logs')
def admin_visitor_logs():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    # Get visitor logs, most recent first
    visitor_logs = list(VisitorLog.get_collection().find().sort('timestamp', -1).limit(100))
    return render_template('admin_visitor_logs.html', visitor_logs=visitor_logs)

# API endpoint to receive real IP address from WebRTC detection
@app.route('/log-real-ip', methods=['POST'])
def log_real_ip():
    try:
        data = request.get_json()
        logger.info(f"Received real IP data: {data}")
        
        # Store the raw WebRTC detection data
        if data:
            store_ip_json("webrtc_detection", data, "WebRTC-Client")
        
        # Get the session ID to link to the correct visitor log
        session_id = session.get('_id')
        if not session_id:
            logger.warning("No session found")
            return jsonify({'status': 'error', 'message': 'No session found'}), 400
        
        # Get the most recent log for this session
        log = VisitorLog.get_collection().find_one(
            {'session_id': session_id},
            sort=[('timestamp', -1)]
        )
        
        if not log:
            logger.warning(f"No log found for session {session_id}")
            return jsonify({'status': 'error', 'message': 'No visitor log found for this session'}), 404
        
        # Handle the case where client detection failed and we need to use server-side detection
        if not data.get('real_ips') or len(data.get('real_ips', [])) == 0:
            logger.info("No client-side IPs detected, using server-side detection")
            
            # Try to get the IP from headers or remote_addr
            real_ip = None
            potential_headers = [
                'X-Forwarded-For', 
                'X-Real-IP', 
                'CF-Connecting-IP',  # Cloudflare
                'True-Client-IP',    # Akamai/Cloudflare
                'X-Client-IP',       # AWS load balancer
                'Forwarded'          # Standard header (RFC 7239)
            ]
            
            # Try each header
            for header in potential_headers:
                if request.headers.get(header):
                    # Handle comma-separated lists in headers like X-Forwarded-For
                    ip = request.headers.get(header).split(',')[0].strip()
                    if ip and not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.'):
                        real_ip = ip
                        logger.info(f"Found real IP in header {header}: {real_ip}")
                        break
            
            # If no IP found in headers, fall back to remote_addr
            if not real_ip:
                real_ip = request.remote_addr
                logger.info(f"Using remote_addr as fallback: {real_ip}")
            
            # Store the detected header data
            header_data = {
                'detected_ip': real_ip,
                'from_header': True,
                'headers': {key: value for key, value in request.headers.items()}
            }
            store_ip_json(real_ip, header_data, "Server-Headers")
            
            # Update data for processing
            data['real_ips'] = [real_ip]
            
        # Set the real IP information from the first detected IP
        real_ip = data['real_ips'][0]
        logger.info(f"Using real IP: {real_ip}")
        
        # Always get location data for the real IP
        real_ip_location = get_ip_location(real_ip)
        logger.info(f"Got location data for real IP: {real_ip_location}")
        
        # Update the log with the real IP addresses and location
        update_data = {
            'real_ips': data['real_ips'],
            'system_ip': real_ip,
            'real_ip_location': real_ip_location
        }
        
        # If there's no existing location data, also use the real IP location as primary
        if not log.get('location') or not log['location'].get('country'):
            update_data['location'] = real_ip_location
        
        # Update the visitor log
        VisitorLog.get_collection().update_one(
            {'_id': log['_id']},
            {'$set': update_data}
        )
        logger.info(f"Updated visitor log with real IP data: {update_data}")

        return jsonify({
            'status': 'success',
            'location': real_ip_location
        }), 200
    except Exception as e:
        logger.exception(f"Error processing real IP: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Admin endpoint to view IP JSON data
@app.route('/admin/ip-json')
def admin_ip_json():
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    ip = request.args.get('ip')
    
    # Get IP JSON records, filtered by IP if provided
    query = {}
    if ip:
        query['ip_address'] = ip
    
    ip_json_data = list(mongo.db.ip_add_json.find(query).sort('timestamp', -1).limit(100))
    
    # Get unique IPs for the filter dropdown
    unique_ips = mongo.db.ip_add_json.distinct('ip_address')
    
    return render_template('admin_ip_json.html', ip_json_data=ip_json_data, unique_ips=unique_ips, selected_ip=ip)

# Direct endpoint to get location data for an IP
@app.route('/get-location/<ip_address>', methods=['GET'])
def get_location(ip_address):
    try:
        logger.info(f"Location request for IP: {ip_address}")
        location = get_ip_location(ip_address)
        return jsonify({
            'status': 'success',
            'location': location
        })
    except Exception as e:
        logger.exception(f"Error getting location: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Download IP JSON data
@app.route('/admin/download-ip-json/<format>')
def download_ip_json(format):
    if not session.get('is_admin'):
        return redirect(url_for('login'))
    
    ip = request.args.get('ip')
    
    # Get IP JSON records, filtered by IP if provided
    query = {}
    if ip:
        query['ip_address'] = ip
    
    # Get the data
    ip_json_data = list(mongo.db.ip_add_json.find(query).sort('timestamp', -1))
    
    # Format the data for download
    if format == 'csv':
        import csv
        import io
        
        output = io.StringIO()
        fieldnames = ['timestamp', 'ip_address', 'source']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in ip_json_data:
            writer.writerow({
                'timestamp': item['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': item['ip_address'],
                'source': item['source']
            })
        
        response = app.response_class(
            response=output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=ip_json_data.csv'}
        )
        return response
    
    elif format == 'json':
        # Convert ObjectId to string for JSON serialization
        for item in ip_json_data:
            item['_id'] = str(item['_id'])
            item['timestamp'] = item['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        response = app.response_class(
            response=json.dumps(ip_json_data, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=ip_json_data.json'}
        )
        return response
    
    else:
        abort(400, description="Invalid format specified")

# Add the forgotten password routes after the existing authentication routes
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Check if user with this email exists
        organizer = mongo.db.organizers.find_one({'contact.email': email})
        
        if not organizer:
            flash('If this email is registered, you will receive a password reset link.')
            return redirect(url_for('login'))
            
        # Generate reset token and URL
        token = generate_password_reset_token(email)
        reset_url = url_for('reset_password', token=token, _external=True)
        
        # Send password reset email
        if send_password_reset_email(email, reset_url):
            flash('Password reset instructions have been sent to your email.')
        else:
            flash('There was a problem sending the password reset email. Please try again later.')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # First verify the token
    email = confirm_password_reset_token(token)
    
    if not email:
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Password validation
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('reset_password', token=token))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters')
            return redirect(url_for('reset_password', token=token))
        
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])', password):
            flash('Password must contain: 1 uppercase, 1 lowercase, 1 number, 1 special character')
            return redirect(url_for('reset_password', token=token))
        
        # Find organizer and update password
        organizer = mongo.db.organizers.find_one({'contact.email': email})
        if organizer:
            # Update the password hash
            mongo.db.organizers.update_one(
                {'_id': organizer['_id']},
                {'$set': {'password_hash': generate_password_hash(password)}}
            )
            flash('Your password has been updated! You can now login.')
            return redirect(url_for('login'))
        else:
            flash('There was a problem resetting your password.')
            return redirect(url_for('forgot_password'))
    
    # GET request - show the reset password form
    return render_template('reset_password.html', token=token)

# Add a route for database error page
@app.route('/db-error')
def db_error():
    return render_template('db_error.html')

# Add an error handler for 500 errors
@app.errorhandler(500)
def server_error(e):
    # Check if the error might be related to database connection
    error_str = str(e)
    if 'pymongo' in error_str or 'ServerSelectionTimeoutError' in error_str or 'SSL handshake failed' in error_str:
        logger.error(f"Database-related server error: {e}")
        return render_template('db_error.html'), 500
    logger.error(f"Server error: {e}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Ensure DB connection is established before creating indexes
    try:
        # Test the MongoDB connection
        mongo.db.command('ping')
        print("MongoDB connection successful")
        
        # Create indexes
        mongo.db.organizers.create_index([('username', pymongo.ASCENDING)], unique=True)
        
        # Ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Create/update admin account
        Organizer.get_collection().update_many(
            {'is_admin': {'$exists': False}},
            {'$set': {'is_admin': False}}
        )
        
        # Check if admin exists
        admin = Organizer.get_collection().find_one({'username': 'admin'})
        if not admin:
            # Create new admin account
            admin = Organizer(
                username='admin',
                password='admin123',  # Default password
                name='Admin',
                type='admin',
                location='System',
                is_admin=True
            )
            Organizer.get_collection().insert_one(admin.__dict__)
            print('Admin account created successfully!')
        else:
            # Just ensure admin flag is set
            Organizer.get_collection().update_one(
                {'username': 'admin'},
                {'$set': {'is_admin': True}}
            )
            print('Admin account verified!')
    except Exception as e:
        print(f"Error initializing database: {e}")
    
    # Run the Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
