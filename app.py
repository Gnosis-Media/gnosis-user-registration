import os
import logging
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy_utils import database_exists, create_database
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
from functools import wraps
from secrets_manager import get_service_secrets
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from datetime import datetime, timedelta


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# CORS 
app = Flask(__name__)
CORS(app)

secrets = get_service_secrets('gnosis-user-registration')

C_PORT = int(secrets.get('PORT', 5000))
SQLALCHEMY_DATABASE_URI = (
    f"mysql+pymysql://{secrets['MYSQL_USER']}:{secrets['MYSQL_PASSWORD_USERS']}"
    f"@{secrets['MYSQL_HOST']}:{secrets['MYSQL_PORT']}/{secrets['MYSQL_DATABASE']}"
)
JWT_SECRET_KEY = secrets.get('JWT_SECRET_KEY')
API_KEY = secrets.get('API_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

app.config['SECRET_KEY'] = secrets.get('JWT_SECRET_KEY')
JWT_EXPIRATION_HOURS = 24

# Add new helper function
def generate_token(user_id, username):
    token = jwt.encode({
        'user_id': user_id,
        'username': username,
        'exp': datetime.now() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# Google OAuth registration logic
GOOGLE_CLIENT_ID = "828323748695-mtijpl2s00v32vsnfag4ubfbmjara52n.apps.googleusercontent.com"

@app.route('/test', methods=['GET'])
def test():
    return jsonify({"status": "Auth service is running"}), 200

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    logging.info("=== Received Google Auth Request ===")
    logging.info(f"Headers: {dict(request.headers)}")
    logging.info(f"Body: {request.json}")
    try:
        # Get the token from Authorization header
        token = request.json.get('credential')
        if not token:
            return jsonify({'error': 'Missing credential token'}), 401
        
        logging.info(f"Token: {token}")
        
        # Verify the Google token
        try:
            idinfo = id_token.verify_oauth2_token(
                token, 
                google_requests.Request(), 
                GOOGLE_CLIENT_ID
            )
            logging.info(f"ID Info: {idinfo}")
            
            # Get user info from the token
            email = idinfo['email']
            name = idinfo.get('name', '').replace(' ', '_').lower()

            logging.info(f"Email: {email}")
            logging.info(f"Name: {name}")
            
            # Check if user exists
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Create new user
                username = name or email.split('@')[0]
                # Ensure username is unique
                base_username = username
                counter = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1
                
                # Create user with random password
                password = generate_password_hash(str(datetime.now()))
                user = User(
                    username=username,
                    email=email,
                    password_hash=password
                )
                db.session.add(user)
                db.session.commit()
                
                logging.info(f"Created new user via Google OAuth: {email}")
            
            # Generate JWT token
            token = generate_token(user.id, user.username)
            
            logging.info(f"Token: {token}")
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username
                }
            }), 200
            
        except ValueError as e:
            logging.error(f"Token verification failed: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
            
    except Exception as e:
        logging.error(f"Google auth error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.json    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        logging.warning("Missing required fields during registration.")
        return jsonify({"error": "Missing required fields"}), 400
    
    # check if the username already exists
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        logging.warning(f"Username already exists: {data['username']}")
        return jsonify({"error": "Username already exists"}), 400
    
    # check if the email already exists
    existing_email = User.query.filter_by(email=data['email']).first()
    if existing_email:
        logging.warning(f"Email already exists: {data['email']}")
        return jsonify({"error": "Email already exists"}), 400

    # hash the password
    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    logging.debug(f"Adding new user to database: {new_user.username}")
    logging.debug(f"New user: {new_user.__dict__}")
    try:
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"User registered successfully: {data['username']}")
        return jsonify({"message": "User registered successfully"}), 201
    except IntegrityError:
        db.session.rollback()
        logging.error("Username or email already exists.")
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error during registration: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    logging.info("Fetched user list.")
    return jsonify([{"id": user.id, "username": user.username, "email": user.email} for user in users]), 200

# Modify login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        logging.warning("Missing username or password during login.")
        return jsonify({"error": "Missing username or password"}), 400
    
    logging.debug(f"Attempting to log in user: {data['username']}")
    user = User.query.filter_by(username=data['username']).first()
    
    if user:
        logging.debug(f"User found: {user.username}")
        if check_password_hash(user.password_hash, data['password']):
            token = generate_token(user.id, user.username)            
            logging.info(f"User logged in successfully: {data['username']}")
            logging.debug(f"Token: {token}")
            logging.debug(f"User: {user.id} {user.username}")
            return jsonify({
                "message": "Login successful",
                "token": token,
                "user": {
                    "id": user.id,
                    "username": user.username
                }
            }), 200
        else:
            logging.warning("Password check failed for user: %s", user.username)
    else:
        logging.warning("No user found with username: %s", data['username'])
    
    return jsonify({"error": "Invalid username or password"}), 401

# Add new validation endpoint
@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    token = request.json.get('token')
    if not token:
        logging.warning("No token provided for validation.")
        return jsonify({"error": "No token provided"}), 401
    
    logging.debug("Received token for validation: %s", token)
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        logging.info("Token validated successfully. Payload: %s", payload)
        return jsonify({
            "valid": True,
            "user": {
                "id": payload['user_id'],
                "username": payload['username']
            }
        }), 200
    except jwt.ExpiredSignatureError:
        logging.warning("Token has expired.")
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        logging.warning("Invalid token.")
        return jsonify({"error": "Invalid token"}), 401


@app.before_request
def log_request_info():
    logging.info(f"Headers: {request.headers}")
    logging.info(f"Body: {request.get_data()}")

    if request.path.startswith('/docs') or request.path.startswith('/swagger') or request.path.startswith('/api/auth/google'):
        return

    if request.headers.get('X-API-KEY') != API_KEY:
        return jsonify({"error": "Invalid API key"}), 401
    

# Use this for prod 
if __name__ == '__main__':
    with app.app_context():
        if not database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
            create_database(app.config['SQLALCHEMY_DATABASE_URI'])
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=C_PORT)