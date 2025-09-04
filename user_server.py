from flask import Flask, render_template, session, flash, redirect, url_for, request
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-here")

def login_required(f):
    @wraps(f)
    def check_login(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", 'warning')
            return redirect('http://localhost:5032/login')
        return f(*args, **kwargs)
    return check_login

@app.route('/')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html', 
                         user_name=session.get('name', 'User'),
                         email=session.get('email'),
                         role=session.get('role'))

@app.route('/profile')
@login_required
def user_profile():
    return render_template('user_profile.html')

@app.route('/settings')
@login_required
def user_settings():
    return render_template('user_settings.html')

@app.route('/logout')
def user_logout():
    session.clear()
    flash("You have been logged out successfully.", 'info')
    return redirect('http://localhost:5032/login')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8051)
