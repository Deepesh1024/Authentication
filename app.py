from flask import Flask, request, render_template, flash, redirect, url_for, session
import requests
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from mail import send_otp
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Load environment variables
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-here")

# Configuration
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
access_token = os.getenv("ACCESS_TOKEN")
mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

# MongoDB setup
mongo_client = MongoClient(mongo_uri)
db = mongo_client["speak_database"]
collection = db["users"]
collection2 = db["creds"]

# API URL
url = "https://speak.some.education/admin/api/v2/users"

# OTP Configuration
OTP_TTL_MIN = 10  # minutes

def generate_otp(length=6):
    """Generate a random OTP"""
    return "".join(random.choices("0123456789", k=length))

def store_pending_otp(email, otp):
    """Store OTP for verification"""
    collection2.update_one(
        {"email": email},
        {"$set": {
            "password": None,
            "otp": otp,
            "otp_expire": datetime.utcnow() + timedelta(minutes=OTP_TTL_MIN)
        }},
        upsert=True
    )

def verify_otp(email, user_otp):
    """Verify the OTP entered by user"""
    rec = collection2.find_one({"email": email})
    if not rec:
        return False, "No pending OTP. Start sign-in again."

    if datetime.utcnow() > rec.get("otp_expire", datetime.utcnow()):
        collection2.delete_one({"email": email})
        return False, "OTP expired. Please request a new one."

    stored_otp = rec.get("otp")
    print(f"DEBUG - Stored OTP: {stored_otp}, User entered: {user_otp}")
    
    if str(user_otp).strip() == str(stored_otp).strip():
        return True, "OTP verified."
    return False, f"Incorrect OTP."

def make_db():
    all_users = []
    all_admins = []
    
    try:
        # Fetch regular users
        for i in range(25): 
            querystring = {
                "role": "user",
                "page": i,
                "items_per_page": 200
            }
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
                "Lw-Client": client_id
            }
            response = requests.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()
                users = data.get("data", [])
                all_users.extend(users)
                print(f"Fetched {len(users)} users from page {i}")
                if len(users) == 0:
                    break
            else:
                print(f"Error on page {i}: {response.status_code}, {response.text}")
                continue
                
        # Fetch admin users
        for i in range(1): 
            querystring = {
                "role": "admin",
                "page": i,
                "items_per_page": 200
            }
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
                "Lw-Client": client_id
            }
            response = requests.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()
                admins = data.get("data", [])
                all_admins.extend(admins)
                print(f"Fetched {len(admins)} admins from page {i}")
            else:
                print(f"Error on page {i}: {response.status_code}, {response.text}")
                continue
                
        if all_users or all_admins:
            collection.delete_many({})
            if all_users:
                collection.insert_many(all_users)
            if all_admins:
                collection.insert_many(all_admins)
            return f"Inserted {len(all_users)} users and {len(all_admins)} admins into MongoDB."
        else:
            return "No users or admins fetched."
    except Exception as e:
        return f"Error rebuilding database: {str(e)}"

def login(email, password):
    """Login a user"""
    user = collection.find_one({"email": email})
    if user:
        verify = collection2.find_one({"email": email})
        if verify and verify.get("password"):
            if check_password_hash(verify["password"], password):
                role = "admin" if user.get("is_admin", False) else "user"
                return True, f"Login Successful. Role: {role.title()}", role, user
            else:
                return False, "Invalid password.", None, None
        else:
            return False, "Please complete sign-in process first.", None, None
    else:
        return False, f"No user found with email: {email}", None, None

# Routes
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/signin', methods=['GET', 'POST'])
def signin_page():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Please enter a valid email address.', 'error')
            return render_template('signin.html')
        
        user = collection.find_one({"email": email})
        if not user:
            flash('User not found. Reloading database...', 'warning')
            db_result = make_db()
            print(f"Database reload result: {db_result}")
            
            user = collection.find_one({"email": email})
            if not user:
                flash(f"Database reloaded but user still not found with email: {email}", 'error')
                return render_template('signin.html')
            else:
                flash("Database reloaded successfully.", 'success')
        
        try:
            otp = send_otp(email)
            if otp:
                store_pending_otp(email, otp)
                flash("OTP sent to your email address.", 'info')
                print(f"DEBUG - OTP sent and stored: {otp}")
                return redirect(url_for('otp_page', email=email))
            else:
                flash("Failed to send OTP. Please try again.", 'error')
        except Exception as e:
            flash(f"Error sending OTP: {str(e)}", 'error')
            print(f"Error in sending OTP: {str(e)}")
    
    return render_template('signin.html')

@app.route('/signin/otp', methods=['GET', 'POST'])
def otp_page():
    email = request.args.get('email') or request.form.get('email')
    
    if not email:
        flash("Invalid access. Please start sign-in process again.", 'error')
        return redirect(url_for('signin_page'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not user_otp or not password or not confirm_password:
            flash("All fields are required.", 'error')
            return render_template('otp.html', email=email)
        
        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('otp.html', email=email)
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", 'error')
            return render_template('otp.html', email=email)
        
        ok, msg = verify_otp(email, user_otp)
        if not ok:
            flash(msg, 'error')
            return render_template('otp.html', email=email)
        
        hashed_password = generate_password_hash(password)
        collection2.update_one(
            {"email": email},
            {"$set": {"password": hashed_password},
             "$unset": {"otp": "", "otp_expire": ""}}
        )
        
        flash("Sign-in completed successfully. You can now log in.", 'success')
        return redirect(url_for('login_page'))
    
    return render_template('otp.html', email=email)

@app.route('/resend-otp')
def resend_otp():
    email = request.args.get('email', '').strip()
    if not email:
        flash("Invalid request.", 'error')
        return redirect(url_for('signin_page'))
    
    try:
        otp = send_otp(email)
        if otp:
            store_pending_otp(email, otp)
            flash("New OTP sent to your email address.", 'success')
            print(f"DEBUG - New OTP sent and stored: {otp}")
        else:
            flash("Failed to send OTP. Please try again.", 'error')
    except Exception as e:
        flash(f"Error sending OTP: {str(e)}", 'error')
        print(f"Error in resending OTP: {str(e)}")
    
    return redirect(url_for('otp_page', email=email))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash("Please enter both email and password.", 'error')
            return render_template('login.html')
        
        success, message, role, user = login(email, password)
        if success:
            # Set session variables
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            session['role'] = role
            session['name'] = user.get('name', 'User')
            
            flash(message, 'success')
            
            # Redirect based on role
            if role == 'admin':
                return redirect('http://localhost:8000')
            else:
                return redirect('http://localhost:8051')
        else:
            flash(message, 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", 'info')
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5032)
