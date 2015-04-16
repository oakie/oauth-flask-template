# -*- coding: utf-8 -*-

import requests, base64, urllib, requests.auth, json
from functools import wraps
from uuid import uuid4
from flask import Flask, request, redirect, url_for, session, escape
from secret import CLIENT_ID, CLIENT_SECRET, HOST

AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://www.googleapis.com/oauth2/v3/token'
REDIRECT_URI = 'http://{}:5000/auth_callback'.format(HOST)

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = CLIENT_SECRET
valid_states = set()

def signin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('signin', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@signin_required
def index():
    html = 'Logged in as {}.<br><a href="{}">secret</a> <a href="{}">Sign out.</a>'
    return html.format(escape(session['email']), url_for('secret'), url_for('signout'))

@app.route('/secret')
@signin_required
def secret():
    html = 'TOP SECRET!<br><a href="{}">index</a> <a href="{}">Sign out.</a>'
    return html.format(url_for('index'), url_for('signout'))

@app.route('/signin')
def signin():
    next = request.args.get('next')
    state = base64.urlsafe_b64encode(str(uuid4()) + ';' + next)
    save_created_state(state)

    params = {'client_id': CLIENT_ID,
        'response_type': 'code',
        'state': state,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid email'}
    html = '{}<br><a href="{}">secret</a> <a href="{}">Authenticate with google</a>'
    return html.format(next, url_for('secret'), AUTH_URL + '?' + urllib.urlencode(params))

@app.route('/signout')
def signout():
    if 'email' in session:
        session.pop('email')
    return redirect(url_for('index'))

@app.route('/auth_callback')
def auth_callback():
    error = request.args.get('error', '')
    if error:
        return 'Error: ' + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        abort(403)
    next = base64.urlsafe_b64decode(state.encode('ascii')).split(';')[1]
    remove_state(state)
    code = request.args.get('code')
    id_token, access_token = get_tokens(code)

    session['email'] = id_token['email']
    return redirect(next)

def get_tokens(code):
    post_data = {'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'}
    response = requests.post(TOKEN_URL, data=post_data)
    token_json = response.json()
    ascii_str = token_json['id_token'].split('.')[1].encode('ascii')
    padded = ascii_str + '=' * (4 - len(ascii_str) % 4)
    return json.loads(base64.urlsafe_b64decode(padded)), token_json['access_token']

def save_created_state(state):
    valid_states.add(state)

def is_valid_state(state):
    if state in valid_states:
        return True
    return False

def remove_state(state):
    valid_states.remove(state)

if __name__ == '__main__':
    app.run(host=HOST, debug=True)
