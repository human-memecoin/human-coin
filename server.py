from flask import Flask, session, redirect, request, jsonify, make_response
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import os
import json
import sqlite3
import random
import string
import secrets
from datetime import datetime, timedelta
from requests_oauthlib import OAuth1Session
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.debug = True  # Enable debug mode
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24))

CORS(app, 
     resources={r"/api/*": {"origins": ["https://human-memecoin.github.io", "http://localhost:5000"], "supports_credentials": True}},
     supports_credentials=True)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

TWITTER_API_KEY = os.getenv('TWITTER_API_KEY')
TWITTER_API_SECRET = os.getenv('TWITTER_API_SECRET')
TWITTER_CALLBACK_URL = 'https://human-coin-server.onrender.com/callback'

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

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
    try:
        # Create OAuth1Session
        twitter = OAuth1Session(
            client_key=TWITTER_API_KEY,
            client_secret=TWITTER_API_SECRET,
            callback_uri=TWITTER_CALLBACK_URL
        )
        
        # Get request token
        try:
            request_token = twitter.fetch_request_token(
                'https://api.twitter.com/oauth/request_token'
            )
        except Exception as e:
            print(f"Error fetching request token: {str(e)}")
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=token_error')
        
        # Store request token in session
        session['request_token'] = request_token
        
        # Generate state
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Get authorization url
        authorization_url = twitter.authorization_url(
            'https://api.twitter.com/oauth/authorize'
        )
        
        # Add state parameter
        authorization_url = f"{authorization_url}&state={state}"
        
        return redirect(authorization_url)
        
    except Exception as e:
        print(f"Error during Twitter login: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=login_failed')

@app.route('/callback')
def callback():
    try:
        # Verify state
        state = request.args.get('state')
        stored_state = session.get('oauth_state')
        
        if not state or not stored_state or state != stored_state:
            print("State verification failed")
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=invalid_state')
        
        # Get the oauth token and verifier
        oauth_token = request.args.get('oauth_token')
        oauth_verifier = request.args.get('oauth_verifier')
        
        if not oauth_token or not oauth_verifier:
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=missing_token')

        # Get the request token from session
        request_token = session.get('request_token')
        if not request_token:
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=no_request_token')

        # Create OAuth1Session for verifying credentials
        twitter = OAuth1Session(
            client_key=TWITTER_API_KEY,
            client_secret=TWITTER_API_SECRET,
            resource_owner_key=oauth_token,
            resource_owner_secret=request_token['oauth_token_secret'],
            verifier=oauth_verifier
        )

        try:
            # Get the access token
            access_tokens = twitter.fetch_access_token(
                'https://api.twitter.com/oauth/access_token'
            )
        except Exception as e:
            print(f"Error fetching access token: {str(e)}")
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=access_token_error')

        # Create new session with access token
        twitter = OAuth1Session(
            client_key=TWITTER_API_KEY,
            client_secret=TWITTER_API_SECRET,
            resource_owner_key=access_tokens['oauth_token'],
            resource_owner_secret=access_tokens['oauth_token_secret']
        )

        try:
            # Get user profile information
            response = twitter.get(
                'https://api.twitter.com/1.1/account/verify_credentials.json',
                params={'include_email': 'true', 'skip_status': 'true'}
            )
            
            if response.status_code != 200:
                print(f"Error getting user info: {response.text}")
                return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=profile_error')
                
            user_info = response.json()
        except Exception as e:
            print(f"Error getting user info: {str(e)}")
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=profile_error')

        # Store user information in session
        session['user_id'] = user_info['id_str']
        session['twitter_handle'] = user_info['screen_name']
        session['access_token'] = access_tokens['oauth_token']
        session['access_token_secret'] = access_tokens['oauth_token_secret']
        session.permanent = True

        # Store user in database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        try:
            # Check if user exists
            c.execute('SELECT id FROM users WHERE id = ?', (user_info['id_str'],))
            existing_user = c.fetchone()
            
            if existing_user:
                # Update existing user
                c.execute('''
                    UPDATE users 
                    SET twitter_handle = ?, 
                        avatar_url = ?,
                        last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (
                    user_info['screen_name'],
                    user_info['profile_image_url_https'].replace('_normal', ''),
                    user_info['id_str']
                ))
            else:
                # Create new user with default tasks
                referral_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
                c.execute('''
                    INSERT INTO users 
                    (id, twitter_handle, avatar_url, points, level, exp, referral_code, tasks, last_login) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    user_info['id_str'],
                    user_info['screen_name'],
                    user_info['profile_image_url_https'].replace('_normal', ''),
                    0,  # points
                    1,  # level
                    0,  # exp
                    referral_code,
                    '{}'  # empty tasks object
                ))
            
            conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")
            conn.rollback()
            return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=database_error')
        finally:
            conn.close()

        # Clear oauth state and request token
        session.pop('oauth_state', None)
        session.pop('request_token', None)

        # Redirect to dashboard
        return redirect('https://human-memecoin.github.io/human-coin/dashboard/index.html?login=success')

    except Exception as e:
        print(f"Error during callback: {str(e)}")
        return redirect('https://human-memecoin.github.io/human-coin/marketing.html?error=callback_failed')

@app.route('/api/user', methods=['GET'])
def get_user():
    try:
        # Check if user is logged in
        user_id = session.get('user_id')
        if not user_id:
            response = make_response('Unauthorized', 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Get user data
        c.execute('''
            SELECT 
                twitter_handle, 
                avatar_url, 
                points, 
                level, 
                exp, 
                phantom_wallet, 
                referral_code,
                tasks,
                last_login
            FROM users 
            WHERE id = ?
        ''', (user_id,))
        
        user = c.fetchone()
        conn.close()
        
        if not user:
            response = make_response('User not found', 404)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
        
        response = make_response(jsonify({
            'id': user_id,
            'twitter_handle': user[0],
            'avatar_url': user[1],
            'points': user[2] or 0,
            'level': user[3] or 1,
            'exp': user[4] or 0,
            'phantom_wallet': user[5],
            'referral_code': user[6],
            'tasks': user[7],
            'last_login': user[8]
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
        
    except Exception as e:
        print(f"Error getting user: {str(e)}")
        response = make_response('Internal server error', 500)
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
        
        # Get all tasks with completion status and cooldown info
        c.execute('''
            SELECT 
                t.*,
                tc.completed_at,
                CASE 
                    WHEN t.cooldown_hours > 0 
                    AND tc.completed_at IS NOT NULL 
                    AND datetime(tc.completed_at, '+' || t.cooldown_hours || ' hours') > datetime('now')
                    THEN 1
                    ELSE 0
                END as in_cooldown,
                CASE 
                    WHEN t.cooldown_hours > 0 
                    AND tc.completed_at IS NOT NULL 
                    THEN datetime(tc.completed_at, '+' || t.cooldown_hours || ' hours')
                    ELSE NULL
                END as next_available
            FROM tasks t
            LEFT JOIN task_completions tc 
                ON t.id = tc.task_id 
                AND tc.user_id = ?
            ORDER BY t.created_at DESC
        ''', (user_id,))
        
        tasks = []
        for row in c.fetchall():
            task = {
                'id': row[0],
                'title': row[1],
                'description': row[2],
                'points': row[3],
                'exp': row[4],
                'cooldown_hours': row[5],
                'platform': row[6],
                'completed_at': row[7],
                'in_cooldown': bool(row[8]),
                'next_available': row[9]
            }
            tasks.append(task)
        
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

@app.route('/api/tasks/complete', methods=['POST'])
def complete_task():
    try:
        user_id = session.get('user_id')
        if not user_id:
            response = make_response(jsonify({'error': 'Not logged in'}), 401)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        data = request.json
        task_id = data.get('task_id')
        
        if not task_id:
            response = make_response(jsonify({'error': 'Task ID required'}), 400)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if task exists
        c.execute('SELECT * FROM tasks WHERE id = ?', (task_id,))
        task = c.fetchone()
        if not task:
            conn.close()
            response = make_response(jsonify({'error': 'Task not found'}), 404)
            response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        # Check cooldown
        c.execute('''
            SELECT completed_at 
            FROM task_completions 
            WHERE user_id = ? AND task_id = ?
            ORDER BY completed_at DESC 
            LIMIT 1
        ''', (user_id, task_id))
        last_completion = c.fetchone()
        
        if last_completion and task[5] > 0:  # task[5] is cooldown_hours
            last_time = datetime.strptime(last_completion[0], '%Y-%m-%d %H:%M:%S')
            cooldown_end = last_time + timedelta(hours=task[5])
            if datetime.now() < cooldown_end:
                conn.close()
                response = make_response(jsonify({
                    'error': 'Task in cooldown',
                    'next_available': cooldown_end.isoformat()
                }), 400)
                response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                return response
        
        # Record completion
        c.execute('''
            INSERT INTO task_completions (user_id, task_id, completed_at)
            VALUES (?, ?, datetime('now'))
        ''', (user_id, task_id))
        
        # Update user points and exp
        c.execute('''
            UPDATE users 
            SET points = points + ?,
                exp = exp + ?
            WHERE id = ?
        ''', (task[3], task[4], user_id))
        
        conn.commit()
        conn.close()
        
        response = make_response(jsonify({
            'message': 'Task completed successfully',
            'points_earned': task[3],
            'exp_earned': task[4]
        }))
        response.headers.add('Access-Control-Allow-Origin', 'https://human-memecoin.github.io')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    except Exception as e:
        print(f"Error completing task: {str(e)}")
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

def init_db():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Create users table with all necessary columns
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            twitter_handle TEXT,
            avatar_url TEXT,
            points INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            exp INTEGER DEFAULT 0,
            phantom_wallet TEXT,
            referral_code TEXT UNIQUE,
            referral_count INTEGER DEFAULT 0,
            referral_points INTEGER DEFAULT 0,
            tasks TEXT DEFAULT '{}'
        )''')
        
        # Create tasks table
        c.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            points INTEGER DEFAULT 0,
            exp INTEGER DEFAULT 0,
            cooldown_hours INTEGER DEFAULT 0,
            platform TEXT DEFAULT 'all'
        )''')
        
        # Create task_completions table
        c.execute('''CREATE TABLE IF NOT EXISTS task_completions (
            user_id TEXT,
            task_id TEXT,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (task_id) REFERENCES tasks (id),
            PRIMARY KEY (user_id, task_id)
        )''')
        
        # Insert default tasks if they don't exist
        default_tasks = [
            ('daily_checkin', 'Daily Check-in', 'Check in daily to earn points', 100, 50, 24, 'all'),
            ('follow_human', 'Follow @TheHumanCoin', 'Follow @TheHumanCoin on Twitter', 200, 100, 0, 'twitter'),
            ('follow_essentials', 'Follow @essentials_xyz', 'Follow @essentials_xyz on Twitter', 200, 100, 0, 'twitter'),
            ('join_telegram', 'Join Telegram', 'Join our Telegram channel', 300, 150, 0, 'telegram')
        ]
        
        c.executemany('''INSERT OR IGNORE INTO tasks 
            (id, title, description, points, exp, cooldown_hours, platform) 
            VALUES (?, ?, ?, ?, ?, ?, ?)''', default_tasks)
        
        conn.commit()
        print("Database initialized successfully!")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
    finally:
        conn.close()

# Initialize database before running the app
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
