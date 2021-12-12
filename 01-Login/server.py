"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps 
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

import base64

import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

CALLBACK_URL = env.get(constants.CALLBACK_URL)
CLIENT_ID = env.get(constants.CLIENT_ID)
CLIENT_SECRET = env.get(constants.CLIENT_SECRET)
BASE_URL = env.get(constants.BASE_URL)
AUTH_URL = env.get(constants.AUTH_URL)
LOGOUT_URL = env.get(constants.LOGOUT_URL)
TOKEN_URL = env.get(constants.TOKEN_URL)
AUDIENCE = env.get(constants.AUDIENCE)

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True


@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'iris',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=BASE_URL,
    access_token_url=TOKEN_URL,
    authorize_url=AUTH_URL,
    client_kwargs={
        'scope': 'openid profile email roles',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
#@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/callback')
#@app.route('/')
def callback_handling():
    token = auth0.authorize_access_token()
    print(token)
    payload_data = base64.b64decode(token["access_token"].split(".")[1])
    userinfo = json.loads(payload_data)
    print(json.dumps(userinfo, indent=4))
    #resp = auth0.get('userinfo')
    #userinfo = resp.json()

    session[constants.JWT_PAYLOAD] = userinfo
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': "https://mywiki.telekom.de/download/attachments/131074/global.logo?version=2&modificationDate=1408501526000&api=v2"
    }
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=CALLBACK_URL, audience=AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': CLIENT_ID}
    return redirect(LOGOUT_URL + '?' + urlencode(params))


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))
