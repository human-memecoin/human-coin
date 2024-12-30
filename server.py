from flask import Flask, session, redirect, request, jsonify, make_response
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import os
from datetime import datetime, timedelta
import sqlite3
from dotenv import load_dotenv
import json
import time
import random
import string

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
        session['user_id'] = user_info['id']
        
        # Store user data in database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Update user information
        c.execute('''
            INSERT OR REPLACE INTO users 
            (id, twitter_handle, avatar_url, points, level, exp, phantom_wallet, referral_code, referred_by, tasks, created_at) 
            VALUES (?, ?, ?, 
                COALESCE((SELECT points FROM users WHERE id = ?), 0),
                COALESCE((SELECT level FROM users WHERE id = ?), 1),
                COALESCE((SELECT exp FROM users WHERE id = ?), 0),
                '',
                '',
                '',
                '',
                CURRENT_TIMESTAMP)
        ''', (
            user_info['id'],
            user_info['username'],
            user_info.get('profile_image_url', ''),
            user_info['id'],
            user_info['id'],
            user_info['id'],
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
        c.execute('SELECT twitter_handle, avatar_url, points, level, exp, phantom_wallet, referral_code FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            session.clear()
            response = make_response(jsonify({'error': 'User not found'}), 404)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        response = make_response(jsonify({
            'twitter_handle': user[0],
            'avatar_url': user[1],
            'points': user[2] or 0,
            'level': user[3] or 1,
            'exp': user[4] or 0,
            'phantom_wallet': user[5],
            'referral_code': user[6]
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
        
        # Create response
        response = make_response(jsonify({'message': 'Signed out successfully'}))
        
        # Clear session cookie
        response.set_cookie('session', '', expires=0, secure=True, httponly=True, samesite='None')
        
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

@app.route('/api/connect_wallet', methods=['POST'])
def connect_wallet():
    try:
        if 'user_id' not in session:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        data = request.json
        wallet_address = data.get('wallet_address')
        
        if not wallet_address:
            response = make_response(jsonify({'error': 'Wallet address required'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET phantom_wallet = ? WHERE id = ?', (wallet_address, session['user_id']))
        conn.commit()
        conn.close()

        response = make_response(jsonify({'message': 'Wallet connected successfully'}))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error connecting wallet: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/referral', methods=['POST'])
def use_referral():
    try:
        if 'user_id' not in session:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        data = request.json
        referral_code = data.get('referral_code')
        
        if not referral_code:
            response = make_response(jsonify({'error': 'Referral code required'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if referral code exists
        c.execute('SELECT id FROM users WHERE referral_code = ?', (referral_code,))
        referrer = c.fetchone()
        
        if not referrer:
            conn.close()
            response = make_response(jsonify({'error': 'Invalid referral code'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        # Check if user already used a referral code
        c.execute('SELECT referred_by FROM users WHERE id = ?', (session['user_id'],))
        existing_referral = c.fetchone()
        
        if existing_referral and existing_referral[0]:
            conn.close()
            response = make_response(jsonify({'error': 'Already used a referral code'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        # Update user with referral
        c.execute('UPDATE users SET referred_by = ?, points = points + 100 WHERE id = ?', 
                 (referrer[0], session['user_id']))
        
        # Give points to referrer
        c.execute('UPDATE users SET points = points + 200 WHERE id = ?', (referrer[0],))
        
        conn.commit()
        conn.close()

        response = make_response(jsonify({
            'message': 'Referral code applied successfully',
            'points_earned': 100
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error using referral: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Get top 100 users by points
        c.execute('''
            SELECT twitter_handle, points, level, phantom_wallet 
            FROM users 
            ORDER BY points DESC 
            LIMIT 100
        ''')
        
        leaderboard = []
        for i, (handle, points, level, wallet) in enumerate(c.fetchall(), 1):
            leaderboard.append({
                'rank': i,
                'handle': handle,
                'points': points,
                'level': level,
                'wallet': wallet[:6] + '...' + wallet[-4:] if wallet else None
            })
            
        conn.close()

        response = make_response(jsonify({'leaderboard': leaderboard}))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error getting leaderboard: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/verify_task', methods=['POST'])
def verify_task():
    try:
        if 'user_id' not in session:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        data = request.json
        task_type = data.get('task_type')
        
        # Simulate verification delay
        time.sleep(65)  # Wait for 65 seconds
        
        # Always verify successfully for now
        # In production, implement actual verification logic
        is_verified = True
        
        response = make_response(jsonify({
            'verified': is_verified,
            'message': f'Task {task_type} verified successfully'
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error verifying task: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/callback')
def callback():
    try:
        # Get the oauth token from query parameters
        oauth_token = request.args.get('oauth_token')
        oauth_verifier = request.args.get('oauth_verifier')
        
        if not oauth_token or not oauth_verifier:
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=missing_token')

        # Get the request token from the session
        request_token = session.get('request_token')
        if not request_token:
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=no_request_token')

        # Create OAuth1Session for verifying credentials
        twitter = OAuth1Session(
            client_key=os.getenv('TWITTER_API_KEY'),
            client_secret=os.getenv('TWITTER_API_SECRET'),
            resource_owner_key=oauth_token,
            resource_owner_secret=request_token['oauth_token_secret'],
            verifier=oauth_verifier
        )

        # Get the access token
        access_tokens = twitter.fetch_access_token('https://api.twitter.com/oauth/access_token')

        # Get user information using the access token
        twitter = OAuth1Session(
            client_key=os.getenv('TWITTER_API_KEY'),
            client_secret=os.getenv('TWITTER_API_SECRET'),
            resource_owner_key=access_tokens['oauth_token'],
            resource_owner_secret=access_tokens['oauth_token_secret']
        )

        # Get user profile information
        response = twitter.get('https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true')
        user_info = response.json()

        # Store user information in session
        session['user_id'] = user_info['id_str']
        session['access_token'] = access_tokens['oauth_token']
        session['access_token_secret'] = access_tokens['oauth_token_secret']
        session.permanent = True

        # Store user in database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if user exists
        c.execute('SELECT id FROM users WHERE id = ?', (user_info['id_str'],))
        existing_user = c.fetchone()
        
        if existing_user:
            # Update existing user
            c.execute('''
                UPDATE users 
                SET twitter_handle = ?, 
                    avatar_url = ?
                WHERE id = ?
            ''', (
                user_info['screen_name'],
                user_info['profile_image_url_https'],
                user_info['id_str']
            ))
        else:
            # Create new user
            c.execute('''
                INSERT INTO users 
                (id, twitter_handle, avatar_url, points, level, exp, referral_code) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_info['id_str'],
                user_info['screen_name'],
                user_info['profile_image_url_https'],
                0,  # points
                1,  # level
                0,  # exp
                ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))  # random referral code
            ))
        
        conn.commit()
        conn.close()

        # Redirect to dashboard with success parameter
        return redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html?login=success')

    except Exception as e:
        print(f"Error during authorization: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=login_failed')

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create users table with new fields
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            twitter_handle TEXT,
            discord_id TEXT,
            farcaster_id TEXT,
            telegram_id TEXT,
            avatar_url TEXT,
            points INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            exp INTEGER DEFAULT 0,
            phantom_wallet TEXT,
            referral_code TEXT UNIQUE,
            referred_by TEXT,
            referral_count INTEGER DEFAULT 0,
            tasks TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP
        )
    ''')
    
    # Create tasks table
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            task_type TEXT,
            points INTEGER,
            exp INTEGER,
            platform TEXT,
            requirements TEXT,
            custom_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create task completions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS task_completions (
            user_id TEXT,
            task_id TEXT,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            proof TEXT,
            verified BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (task_id) REFERENCES tasks(id),
            PRIMARY KEY (user_id, task_id)
        )
    ''')
    
    # Create default tasks
    default_tasks = [
        ('daily_checkin', 'Daily Check-in', 'Check in daily to earn points!', 'daily', 10, 20, 'all', '', ''),
        ('twitter_follow', 'Follow on Twitter', 'Follow Human Coin on Twitter', 'social', 50, 100, 'twitter', '', ''),
        ('discord_join', 'Join Discord', 'Join our Discord community', 'social', 50, 100, 'discord', '', ''),
        ('telegram_join', 'Join Telegram', 'Join our Telegram group', 'social', 50, 100, 'telegram', '', ''),
        ('farcaster_follow', 'Follow on Farcaster', 'Follow us on Farcaster', 'social', 50, 100, 'farcaster', '', '')
    ]
    
    c.executemany('''
        INSERT OR IGNORE INTO tasks 
        (id, title, description, task_type, points, exp, platform, requirements, custom_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', default_tasks)
    
    conn.commit()
    conn.close()

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    try:
        user_id = session.get('user_id')
        if not user_id:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Get all tasks
        c.execute('''
            SELECT t.*, 
                   tc.completed_at IS NOT NULL as is_completed,
                   tc.verified
            FROM tasks t
            LEFT JOIN task_completions tc 
                ON t.id = tc.task_id 
                AND tc.user_id = ?
            ORDER BY t.created_at DESC
        ''', (user_id,))
        
        tasks = []
        for row in c.fetchall():
            tasks.append({
                'id': row[0],
                'title': row[1],
                'description': row[2],
                'task_type': row[3],
                'points': row[4],
                'exp': row[5],
                'platform': row[6],
                'requirements': row[7],
                'custom_data': row[8],
                'is_completed': bool(row[9]),
                'is_verified': bool(row[10])
            })
        
        conn.close()
        
        response = make_response(jsonify({'tasks': tasks}))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error getting tasks: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/referral/stats', methods=['GET'])
def get_referral_stats():
    try:
        user_id = session.get('user_id')
        if not user_id:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Get user's referral code and count
        c.execute('''
            SELECT referral_code, referral_count,
                   (SELECT COUNT(*) FROM users WHERE referred_by = ?) as total_referrals
            FROM users 
            WHERE id = ?
        ''', (user_id, user_id))
        
        result = c.fetchone()
        if not result:
            conn.close()
            response = make_response(jsonify({'error': 'User not found'}), 404)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        referral_code, referral_count, total_referrals = result
        
        # Get recent referrals
        c.execute('''
            SELECT twitter_handle, created_at 
            FROM users 
            WHERE referred_by = ?
            ORDER BY created_at DESC
            LIMIT 5
        ''', (user_id,))
        
        recent_referrals = [{
            'handle': row[0],
            'date': row[1]
        } for row in c.fetchall()]
        
        conn.close()
        
        response = make_response(jsonify({
            'referral_code': referral_code,
            'referral_count': referral_count,
            'total_referrals': total_referrals,
            'recent_referrals': recent_referrals
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error getting referral stats: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

@app.route('/api/connect_social', methods=['POST'])
def connect_social():
    try:
        user_id = session.get('user_id')
        if not user_id:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        data = request.json
        platform = data.get('platform')
        platform_id = data.get('platform_id')
        
        if not platform or not platform_id:
            response = make_response(jsonify({'error': 'Platform and ID required'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Update user's social connection
        c.execute(f'''
            UPDATE users 
            SET {platform}_id = ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (platform_id, user_id))
        
        conn.commit()
        conn.close()

        response = make_response(jsonify({'message': f'{platform} connected successfully'}))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error connecting social: {str(e)}")
        response = make_response(jsonify({'error': str(e)}), 500)
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
