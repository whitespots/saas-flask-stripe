import json
import sqlite3
import stripe
from flask import Flask, redirect, request, url_for, render_template, jsonify, abort

from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests
import settings

# Internal imports
from db import init_db_command
from user import User

####################################
# Configuration
####################################

stripe.api_key = settings.config['STRIPE_SECRET_KEY']
STRIPE_PUBLISHABLE_KEY = settings.config['STRIPE_PUBLISHABLE_KEY']
GOOGLE_CLIENT_ID = settings.config['GOOGLE_CLIENT_ID']
GOOGLE_CLIENT_SECRET = settings.config['GOOGLE_CLIENT_SECRET']
GOOGLE_DISCOVERY_URL = settings.config['GOOGLE_DISCOVERY_URL']

app = Flask(__name__)
app.secret_key = settings.config['SECRET_KEY']
app.config['SESSION_COOKIE_NAME'] = 'saas_session'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# User session management setup
login_manager = LoginManager()
login_manager.init_app(app)

# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


####################################
# Auth
####################################

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/login")
def login():
    if not request.args.get('google'):
        return render_template('login.html')
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]

        # Create a user in your db with the information provided
        # by Google
        user = User(
            id_=unique_id, name=users_name, email=users_email, profile_pic=picture
        )

        # Doesn't exist? Add it to the database.
        if not User.get(unique_id):
            User.create(unique_id, users_name, users_email, picture)

        # Begin user session by logging the user in
        login_user(user)

        # Send user back to homepage
        return redirect(url_for("private"))
    else:
        return "User email not available or not verified by Google.", 400


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


####################################
# General functions
####################################

@app.before_request
def before_request():
    if request.url.startswith('http://'):
        return redirect(request.url.replace('http://', 'https://'), code=301)


@app.route('/', methods=['GET'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('private'))
    return render_template('index.html')


@app.route('/private', methods=['POST', 'GET'])
def private():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return render_template('secret.html', current_user=current_user)


@app.route('/secret', methods=['POST', 'GET'])
def paid():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('secret.html', current_user=current_user)


####################################
# Pricing
####################################


@app.route('/thanks', methods=['GET', 'POST'])
def thanks():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.args.get('session_id'):
        # You have to keep it secure till this step. (checkout session id)
        # Otherwise, people will buy something for free.
        User.set_paid(request.args.get('session_id'))
    return redirect(url_for('paid'))


@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    print('WEBHOOK TRIGGERED')
    payload = request.get_data()
    sig_header = request.environ.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = settings.config['STRIPE_WEBHOOK_SECRET']
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        return abort(400)
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return abort(400)

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        print('checkout completed')
        # Fulfill the purchase...
        User.set_paid(session['id'])

    return redirect(url_for('paid'))


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    stripe.api_key = settings.config['STRIPE_SECRET_KEY']
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        customer_email=current_user.email,
        line_items=[{
            'price': settings.config['STRIPE_PRICE_ID'],
            'quantity': 1
        }],
        mode='payment',
        success_url=url_for('thanks', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('private', _external=True)
    )
    User.set_payment_id(current_user.id, session['id'])
    return render_template(
        'checkout.html',
        checkout_session_id=session['id'],
        checkout_public_key=settings.config['STRIPE_PUBLISHABLE_KEY']
    )


if __name__ == '__main__':
    # Important: Change those default certificates
    app.run(host='0.0.0.0', port=443, ssl_context=('/opt/ssl/certificate.crt', '/opt/ssl/private.key'))
