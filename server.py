from flask import Flask, session, redirect, request, jsonify, make_response
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import sqlite3
from dotenv import load_dotenv
import json
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, 
     supports_credentials=True, 
     origins=['https://human-memecoin.github.io', 'http://localhost:5500', 'http://127.0.0.1:5500'],
     allow_headers=['Content-Type', 'Authorization', 'Cookie'],
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
        
        # Store user data in database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Update user information
        c.execute('''
            INSERT OR REPLACE INTO users 
            (id, twitter_handle, avatar_url, points, level, exp, last_login) 
            VALUES (?, ?, ?, 
                COALESCE((SELECT points FROM users WHERE id = ?), 0),
                COALESCE((SELECT level FROM users WHERE id = ?), 1),
                COALESCE((SELECT exp FROM users WHERE id = ?), 0),
                ?)
        ''', (
            user_info['id'],
            user_info['username'],
            user_info.get('profile_image_url', ''),
            user_info['id'],
            user_info['id'],
            user_info['id'],
            datetime.now()
        ))
        
        conn.commit()
        conn.close()
        
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
            domain='onrender.com'
        )
        
        return response
        
    except Exception as e:
        print(f"Error during authorization: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html?error=login_failed')

@app.route('/api/user', methods=['GET'])
def get_user():
    try:
        if 'user_id' not in session:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        user_id = session['user_id']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT twitter_handle, avatar_url FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            response = make_response(jsonify({'error': 'User not found'}), 404)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        twitter_handle, avatar_url = user
        
        response = make_response(jsonify({
            'twitter_handle': twitter_handle,
            'avatar_url': avatar_url,
            'points': 0,
            'level': 1,
            'exp': 0
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    except Exception as e:
        print(f"Error getting user: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/signout', methods=['POST'])
def signout():
    try:
        # Clear session
        session.clear()
        
        # Create response with cookie clearing instructions
        response = make_response(jsonify({'message': 'Signed out successfully'}))
        
        # Clear cookies with correct domain and path
        response.set_cookie('user_session', '', expires=0, secure=True, httponly=True, samesite='None', domain='onrender.com')
        response.set_cookie('user_session', '', expires=0, secure=True, httponly=True, samesite='None', domain='.onrender.com')
        
        # Set CORS headers
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        
        return response
        
    except Exception as e:
        print(f"Error signing out: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/signout', methods=['OPTIONS'])
def signout_options():
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response

@app.route('/api/update_progress', methods=['POST'])
def update_progress():
    try:
        if 'user_id' not in session:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
        
        data = request.json
        user_id = session['user_id']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Update user progress
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
            user_id
        ))
        
        conn.commit()
        conn.close()
        
        response = make_response(jsonify({'success': True}))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    except Exception as e:
        print(f"Error updating progress: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/verify_follow', methods=['POST'])
def verify_follow():
    try:
        if 'user_id' not in session:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
        
        data = request.json
        account = data.get('account')
        user_id = session['user_id']
        
        # Get user's access token
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT twitter_handle FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            response = make_response(jsonify({'error': 'User not found'}), 404)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        # Verify follow using Twitter API
        accounts = {
            'human': '@TheHumanCoin',
            'essentials': '@Essentials_xyz'
        }
        
        target_account = accounts.get(account)
        if not target_account:
            response = make_response(jsonify({'error': 'Invalid account type'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        # For now, we'll simulate verification with a delay
        # In production, you would use the Twitter API to verify the follow
        time.sleep(2)  # Simulate API call
        is_following = True  # In production, this would be the actual verification result
        
        response = make_response(jsonify({
            'verified': is_following,
            'message': f'Successfully verified follow for {target_account}'
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    except Exception as e:
        print(f"Error verifying follow: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

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
