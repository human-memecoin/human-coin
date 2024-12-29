from flask import Flask, session, redirect, request, jsonify, url_for, make_response
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
        'scope': 'tweet.read users.read follows.read',
        'token_endpoint_auth_method': 'client_secret_basic',
        'code_challenge_method': 'S256'
    }
)

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            twitter_handle TEXT,
            avatar_url TEXT,
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

@app.route('/')
def index():
    return redirect('https://human-memecoin.github.io/human-coin/marketing.html')

@app.route('/login/twitter')
def twitter_login():
    callback = 'https://human-coin-server.onrender.com/oauth/callback'
    return twitter.authorize_redirect(callback)

@app.route('/oauth/callback')
def twitter_authorize():
    try:
        token = twitter.authorize_access_token()
        
        # Get user profile with additional fields
        resp = twitter.get('users/me?user.fields=profile_image_url,username', token=token)
        user_data = resp.json()
        
        if 'data' not in user_data:
            print("Invalid Twitter response:", user_data)
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=invalid_twitter_response')
        
        user_info = user_data['data']
        
        # Initialize database connection
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if user exists
        c.execute('SELECT * FROM users WHERE id = ?', (user_info['id'],))
        existing_user = c.fetchone()
        
        if existing_user:
            # Update existing user
            c.execute('''
                UPDATE users 
                SET twitter_handle = ?,
                    avatar_url = ?,
                    last_login = ?
                WHERE id = ?
            ''', (
                user_info['username'],
                user_info.get('profile_image_url', ''),
                datetime.now(),
                user_info['id']
            ))
        else:
            # Create new user
            c.execute('''
                INSERT INTO users 
                (id, twitter_handle, avatar_url, points, level, exp, created_at, last_login) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_info['id'],
                user_info['username'],
                user_info.get('profile_image_url', ''),
                0,  # initial points
                1,  # initial level
                0,  # initial exp
                datetime.now(),
                datetime.now()
            ))
        
        conn.commit()
        conn.close()
        
        # Set session data
        session.permanent = True
        session['user_id'] = user_info['id']
        session['twitter_handle'] = user_info['username']
        
        # Create response with cookies
        response = make_response(redirect('https://human-memecoin.github.io/human-coin/dashboard.html'))
        
        # Set cookies for persistent login
        max_age = 7 * 24 * 60 * 60  # 7 days in seconds
        response.set_cookie(
            'user_session',
            json.dumps({
                'user_id': user_info['id'],
                'twitter_handle': user_info['username']
            }),
            secure=True,
            httponly=False,
            samesite='None',
            max_age=max_age
        )
        
        return response
        
    except Exception as e:
        print(f"Error during authorization: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=login_failed')

@app.route('/api/user')
def get_user():
    user_id = session.get('user_id')
    if not user_id:
        # Try to get user_id from cookie
        user_session = request.cookies.get('user_session')
        if user_session:
            try:
                session_data = json.loads(user_session)
                user_id = session_data.get('user_id')
            except:
                return jsonify({'error': 'Invalid session'}), 401
    
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get user data
    c.execute('''
        SELECT id, twitter_handle, avatar_url, points, level, exp, created_at, last_login, last_updated
        FROM users 
        WHERE id = ?
    ''', (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        response = jsonify({
            'id': user[0],
            'twitter_handle': user[1],
            'avatar_url': user[2],
            'points': user[3] or 0,
            'level': user[4] or 1,
            'exp': user[5] or 0,
            'created_at': user[6],
            'last_login': user[7],
            'last_updated': user[8]
        })
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    
    return jsonify({'error': 'User not found'}), 404

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
                exp = ?,
                last_updated = ?
            WHERE id = ?
        ''', (
            data['points'],
            data['level'],
            data['exp'],
            datetime.now(),
            session['user_id']
        ))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
