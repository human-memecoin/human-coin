from flask import Flask, session, redirect, request, jsonify, url_for, make_response
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import sqlite3
from dotenv import load_dotenv

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
            created_at TIMESTAMP
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
        resp = twitter.get('users/me', token=token)
        user_info = resp.json()
        
        if 'data' not in user_info:
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=invalid_response')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        profile_resp = twitter.get(f'users/{user_info["data"]["id"]}?user.fields=profile_image_url', token=token)
        profile_data = profile_resp.json()
        
        c.execute('''
            INSERT OR REPLACE INTO users 
            (id, twitter_handle, avatar_url, created_at) 
            VALUES (?, ?, ?, ?)
        ''', (
            user_info['data']['id'],
            user_info['data']['username'],
            profile_data['data'].get('profile_image_url', ''),
            datetime.now()
        ))
        conn.commit()
        conn.close()
        
        session.permanent = True
        session['user_id'] = user_info['data']['id']
        
        response = make_response(redirect('https://human-memecoin.github.io/human-coin/marketing.html#dashboard'))
        response.set_cookie('session_active', 'true', 
                          secure=True, 
                          httponly=False,
                          samesite='None',
                          domain='human-coin-server.onrender.com',
                          max_age=604800)  # 7 days
        return response
        
    except Exception as e:
        print(f"Error during authorization: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=' + str(e))

@app.route('/api/user')
def get_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
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

@app.route('/api/update_progress', methods=['POST'])
def update_progress():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        UPDATE users 
        SET points = ?, level = ?, exp = ?
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
