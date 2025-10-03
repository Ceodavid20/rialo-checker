import os
import secrets
import base64
import hashlib
import urllib.parse
from datetime import datetime, timedelta

import requests
from flask import Flask, redirect, request, session, render_template
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

CLIENT_ID = os.getenv("X_CLIENT_ID")
CLIENT_SECRET = os.getenv("X_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://127.0.0.1:5000/callback")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

SCOPES = "tweet.read users.read offline.access"

AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
ME_URL = "https://api.twitter.com/2/users/me"
TWEETS_URL = "https://api.twitter.com/2/users/{}/tweets"

# Initialize Flask
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- PKCE Helpers ---
def generate_code_verifier():
    return base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()

def code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    verifier = generate_code_verifier()
    challenge = code_challenge(verifier)
    state = secrets.token_urlsafe(16)

    session["pkce_verifier"] = verifier
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    }
    return redirect(f"{AUTH_URL}?{urllib.parse.urlencode(params)}")

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    # Validate state and code
    if not code or state != session.get("oauth_state"):
        return "Error: invalid state or missing code", 400

    # Exchange authorization code for access token
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": session.get("pkce_verifier"),
        "client_id": CLIENT_ID
    }
    resp = requests.post(TOKEN_URL, data=payload, auth=(CLIENT_ID, CLIENT_SECRET))
    tokens = resp.json()

    access_token = tokens.get("access_token")
    if not access_token:
        return f"Auth failed: {tokens}", 400

    headers = {"Authorization": f"Bearer {access_token}"}

    # Fetch user info
    user_resp = requests.get(ME_URL + "?user.fields=profile_image_url,username", headers=headers)
    user_json = user_resp.json()
    if "data" not in user_json:
        return f"Error fetching user info: {user_json}", 400

    user = user_json["data"]
    user_id = user.get("id")
    if not user_id:
        return f"User ID not found in response: {user_json}", 400

    # Fetch tweets from the last 60 days
    since = (datetime.utcnow() - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {
        "max_results": 50,
        "start_time": since,
        "tweet.fields": "created_at,text"
    }

    tweets_resp = requests.get(TWEETS_URL.format(user_id), headers=headers, params=params)
    tweets_json = tweets_resp.json()

    # Check if any tweet contains 'rialo'
    found = False
    for t in tweets_json.get("data", []):
        if "rialo" in t.get("text", "").lower():
            found = True
            break

    return render_template("fancy_card.html", user=user, eligible=found)

# --- Run the app ---
if __name__ == "__main__":
    app.run(debug=True)
