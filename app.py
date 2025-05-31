import os
from flask import Flask, redirect, url_for, request, render_template, session, jsonify
import asyncio
from typing import Dict, Any, Optional
import logging
from kinde_sdk import OAuth
from dotenv import load_dotenv
import uuid
from datetime import datetime
from permissions import Permissions

from kinde_sdk.auth.claims import Claims
from kinde_sdk.auth.feature_flags import FeatureFlags

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Configure session settings
app.config['SESSION_COOKIE_SIZE_LIMIT'] = 4093  # Set to browser limit
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Initialize Kinde OAuth client with Flask framework
kinde_oauth = OAuth(
    client_id=os.getenv("KINDE_CLIENT_ID"),
    client_secret=os.getenv("KINDE_CLIENT_SECRET"),
    redirect_uri=os.getenv("KINDE_REDIRECT_URI"),
    host=os.getenv("KINDE_HOST"),
    framework="flask",  # Use Flask framework
    app=app  # Pass Flask app for session integration
)

@app.route("/")
def index():
    # Check if user is authenticated
    user_id = session.get("user_id")
    is_authenticated = user_id and kinde_oauth.is_authenticated()
    user_info = None
    if is_authenticated:
        try:
            user_info = kinde_oauth.get_user_info()
            logger.info(f"User info retrieved: {user_info}")
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            is_authenticated = False
            session.clear()

    # Get current year for the template
    current_year = datetime.now().year

    # Initialize all displays as hidden
    return render_template("index.html", 
                         tokens_display="hidden",
                         feature_flags_display="hidden",
                         permissions_display="hidden",
                         is_authenticated=is_authenticated,
                         user_info=user_info,
                         current_year=current_year
    )

@app.route("/app_login")
async def app_login():
    try:
        login_url = await kinde_oauth.login()
        logger.info(f"Redirecting to login URL: {login_url}")
        return redirect(login_url)
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@app.route("/app_register")
async def app_register():
    try:
        register_url = await kinde_oauth.register()
        logger.info(f"Redirecting to register URL: {register_url}")
        return redirect(register_url)
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route("/app_get_tokens")
def app_get_tokens():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401

    try:
        tokens = kinde_oauth.get_tokens(user_id)
        logger.info(f"Tokens retrieved for user {user_id}: {tokens}")

        # Ensure we have a proper token response
        if not tokens:
            return jsonify({"error": "No tokens available"}), 404

        # Format tokens for display
        token_data = {
            "access_token": tokens.get("access_token", "Not available"),
            "id_token": tokens.get("id_token", "Not available"),
            "refresh_token": tokens.get("refresh_token", "Not available"),
            "expires_in": tokens.get("expires_in", "Not available")
        }

        return jsonify(token_data)
    except Exception as e:
        logger.error(f"Failed to get tokens: {str(e)}", exc_info=True)
        return jsonify({"error": f"Failed to get tokens: {str(e)}"}), 500

@app.route("/app_get_feature_flags")
def app_get_feature_flags():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401

    flag_code = request.args.get("flag_code")
    try:
        kinde_feature_flags = FeatureFlags()
        token_manager = kinde_oauth._session_manager.get_token_manager(user_id)
        logger.info(f"Token manager status: {'Available' if token_manager else 'Not available'}")
        
        if not token_manager:
            logger.warning("No token manager available - user may not be authenticated")
            return jsonify({"error": "No valid session found"}), 401

        claims = token_manager.get_claims()
        logger.info(f"Claims retrieved: {claims}")
        
        if flag_code:
            # Get specific flag
            flag = asyncio.run(kinde_feature_flags.get_flag(flag_code))
            logger.info(f"Feature flag {flag_code} retrieved: {flag.code} {flag.value}")
            return jsonify({
                "code": flag_code,
                "type": flag.type,
                "value": flag.value,
                "is_default": flag.is_default
            })
        else:
            # Get all flags
            flags = asyncio.run(kinde_feature_flags.get_all_flags())
            logger.info(f"All feature flags retrieved for user {user_id}: {flags}")
            
            # Convert the flags to a dictionary format that can be JSON serialized
            flag_dict = {
                code: {
                    "type": flag.type,
                    "value": flag.value,
                    "is_default": flag.is_default
                }
                for code, flag in flags.items()
            }
            
            return jsonify(flag_dict)
    except Exception as e:
        logger.error(f"Failed to get feature flags: {str(e)}", exc_info=True)
        return jsonify({"error": f"Failed to get feature flags: {str(e)}"}), 500

@app.route("/app_get_claims")
def app_get_claims():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401

    claim_name = request.args.get("claim_name")
    try:
        kinde_claims = Claims()
        token_manager = kinde_oauth._session_manager.get_token_manager(user_id)
        logger.info(f"Token manager status: {'Available' if token_manager else 'Not available'}")
        
        if not token_manager:
            logger.warning("No token manager available - user may not be authenticated")
            return jsonify({"error": "No valid session found"}), 401

        claims = token_manager.get_claims()
        logger.info(f"Claims retrieved: {claims}")
        
        if claim_name:
            # Get specific claim
            value = claims.get(claim_name)
            logger.info(f"Claim {claim_name} retrieved for user {user_id}: {value}")
            return jsonify({
                "name": claim_name,
                "value": value
            })
        else:
            # Get all claims
            logger.info(f"All claims retrieved for user {user_id}: {claims}")
            return jsonify(claims)
    except Exception as e:
        logger.error(f"Failed to get claims: {str(e)}")
        return jsonify({"error": f"Failed to get claims: {str(e)}"}), 500

@app.route("/app_get_permissions")
def app_get_permissions():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401

    permission_key = request.args.get("permission_key")
    try:
        kinde_permissions = Permissions()
        
        if permission_key:
            # Get specific permission
            permission = asyncio.run(kinde_permissions.get_permission(permission_key))
            logger.info(f"Permission {permission_key} retrieved for user {user_id}: {permission}")
            return jsonify(permission)
        else:
            # Get all permissions
            permissions = asyncio.run(kinde_permissions.get_permissions())
            logger.info(f"All permissions retrieved for user {user_id}: {permissions}")
            return jsonify(permissions)
    except Exception as e:
        logger.error(f"Failed to get permissions: {str(e)}", exc_info=True)
        return jsonify({"error": f"Failed to get permissions: {str(e)}"}), 500

@app.route("/app_callback")
async def app_callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        logger.error("No authorization code provided")
        return jsonify({"error": "No authorization code provided"}), 400

    # Generate or retrieve user_id
    user_id = session.get("user_id")
    if not user_id:
        user_id = str(uuid.uuid4())
    
    try:
        # Clear any existing session data
        session.clear()
        # Store only the user_id in session
        session["user_id"] = user_id
        
        # Handle the OAuth redirect and exchange code for tokens
        result = await kinde_oauth.handle_redirect(code, user_id, state)
        logger.info(f"Redirect handled successfully: {result}")
        
        return redirect(url_for("index"))
    except Exception as e:
        logger.error(f"Callback failed: {str(e)}")
        return jsonify({"error": f"Callback failed: {str(e)}"}), 500

@app.route("/app_logout")
async def app_logout():
    user_id = session.get("user_id")
    if user_id:
        try:
            # Clear session before logout
            session.clear()
            
            # Explicitly set the post_logout_redirect_uri to match the allowed URL
            post_logout_redirect_uri = "http://localhost:5000"
            logout_url = await kinde_oauth.logout(
                user_id=user_id,
                logout_options={"post_logout_redirect_uri": post_logout_redirect_uri}
            )
            logger.info(f"Logging out user {user_id}, redirecting to: {logout_url}")
            return redirect(logout_url)
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return jsonify({"error": f"Logout failed: {str(e)}"}), 500
    logger.info("No user_id found, redirecting to index")
    return redirect("http://localhost:5000")

@app.route("/app_clear_session")
def app_clear_session():
    session.clear()
    return jsonify({"success": True, "message": "Session cleared successfully"})

@app.route("/app_refresh_token")
def app_refresh_token():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "User not authenticated"}), 401

    try:
        logger.info(f"Getting tokens for user {user_id}")
        tokens = kinde_oauth.get_tokens(user_id)
        logger.info(f"Tokens retrieved for user {user_id}: {tokens}")
        if not tokens or "refresh_token" not in tokens:
            # If no refresh token, fall back to full re-authentication
            session.clear()
            logger.warn("Full re-authentication required")
            login_url = asyncio.run(kinde_oauth.login())
            return jsonify({"login_url": login_url})

        # Use refresh token to get new access token
        new_tokens = asyncio.run(kinde_oauth.refresh_token(tokens["refresh_token"]))
        if new_tokens:
            # Update session with new tokens
            logger.info("Updating tokens")
            kinde_oauth.update_tokens(user_id, new_tokens)
            return jsonify({"success": True, "message": "Token refreshed successfully"})
        else:
            # If refresh fails, fall back to full re-authentication
            session.clear()
            logger.warn("Falling back to full re-authentication")
            login_url = asyncio.run(kinde_oauth.login())
            return jsonify({"login_url": login_url})

    except Exception as e:
        logger.error(f"Failed to refresh token: {str(e)}", exc_info=True)
        # On error, fall back to full re-authentication
        session.clear()
        login_url = asyncio.run(kinde_oauth.login())
        return jsonify({"login_url": login_url})

if __name__ == "__main__":
    app.run(debug=True)
