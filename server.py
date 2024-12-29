from flask import Flask, session, redirect, request, jsonify, make_response
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import sqlite3
from dotenv import load_dotenv
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, 
     supports_credentials=True, 
     origins=['https://human-memecoin.github.io'],
     allow_headers=['Content-Type', 'Authorization'],
     expose_headers=['Set-Cookie'],
     methods=['GET', 'POST', 'OPTIONS'])

app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7)
)

# Twitter OAuth 2.0 Setup
oauth = OAuth(app)
twitter = oauth.register(
    name='twitter',
    client_id=os.getenv('TWITTER_CLIENT_ID'),
    client_secret=os.getenv('TWITTER_CLIENT_SECRET'),
    api_base_url='https://api.twitter.com/2/',
    access_token_url='https://api.twitter.com/2/oauth2/token',
    authorize_url='https://twitter.com/i/oauth2/authorize',
    client_kwargs={
        'scope': 'users.read tweet.read tweet.write offline.access',
        'response_type': 'code',
        'token_endpoint_auth_method': 'client_secret_basic',
        'code_challenge_method': 'S256',
        'include_email': 'true'
    }
)

@app.route('/')
def index():
    return redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html')

@app.route('/login/twitter')
def twitter_login():
    redirect_uri = 'https://human-coin-server.onrender.com/oauth/callback'
    return twitter.authorize_redirect(
        redirect_uri,
        state=os.urandom(16).hex()
    )

@app.route('/oauth/callback')
def twitter_authorize():
    try:
        token = twitter.authorize_access_token()
        print("Token received:", token)  # Debug print
        
        # Get user profile with fields
        resp = twitter.get('users/me?user.fields=profile_image_url,username,verified,description', token=token)
        user_data = resp.json()
        print("User data:", user_data)  # Debug print
        
        if 'data' not in user_data:
            print("Invalid Twitter response:", user_data)
            return redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html?error=invalid_response')
        
        user_info = user_data['data']
        
        # Set session data
        session.permanent = True
        session['user_id'] = user_info['id']
        
        # Create response with cookies
        response = make_response(redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html'))
        
        # Set cookies for persistent login
        max_age = 7 * 24 * 60 * 60  # 7 days in seconds
        response.set_cookie(
            'user_session',
            str(user_info['id']),
            secure=True,
            httponly=True,
            samesite='None',
            max_age=max_age,
            domain='human-memecoin.github.io'
        )
        
        return response
        
    except Exception as e:
        print(f"Error during authorization: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html?error=login_failed')

@app.route('/api/user', methods=['GET', 'OPTIONS'])
def get_user():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    try:
        # Check session first
        user_id = session.get('user_id')
        
        # If no session, check cookies
        if not user_id:
            user_session = request.cookies.get('user_session')
            if user_session:
                user_id = user_session
        
        if not user_id:
            return jsonify({'error': 'Not logged in'}), 401
        
        # Initialize database connection
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Create users table if it doesn't exist
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                twitter_handle TEXT,
                avatar_url TEXT,
                points INTEGER DEFAULT 0,
                level INTEGER DEFAULT 1,
                exp INTEGER DEFAULT 0,
                created_at TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Get user data
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        
        if not user:
            # Create new user if not exists
            c.execute('''
                INSERT INTO users 
                (id, points, level, exp, created_at, last_login) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                0,  # initial points
                1,  # initial level
                0,  # initial exp
                datetime.now(),
                datetime.now()
            ))
            conn.commit()
            
            # Get the newly created user
            c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
        
        conn.close()
        
        if user:
            response = jsonify({
                'id': user[0],
                'twitter_handle': user[1],
                'avatar_url': user[2],
                'points': user[3] or 0,
                'level': user[4] or 1,
                'exp': user[5] or 0
            })
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
        
        return jsonify({'error': 'User not found'}), 404
        
    except Exception as e:
        print(f"Error in get_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/update_progress', methods=['POST'])
def update_progress():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.json
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute('''
            UPDATE users 
            SET points = ?,
                level = ?,
                exp = ?
            WHERE id = ?
        ''', (
            data['points'],
            data['level'],
            data['exp'],
            session['user_id']
        ))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            twitter_handle TEXT,
            email TEXT,
            avatar_url TEXT,
            verified BOOLEAN,
            description TEXT,
            points INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            exp INTEGER DEFAULT 0,
            created_at TIMESTAMP,
            last_login TIMESTAMP,
            last_updated TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
