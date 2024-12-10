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
from flask_restx import Api, Resource, fields, Namespace

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# CORS 
app = Flask(__name__)
CORS(app)

# Initialize Flask-RestX
api = Api(app,
    version='1.0',
    title='Gnosis User Registration API',
    description='API for managing user registration and authentication',
    doc='/docs'
)

# Create namespaces
auth_ns = api.namespace('api/auth', description='Authentication operations')
user_ns = api.namespace('api', description='User operations')

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

# Define models for request/response
user_model = api.model('User', {
    'id': fields.Integer,
    'username': fields.String,
    'email': fields.String
})

auth_response = api.model('AuthResponse', {
    'message': fields.String,
    'token': fields.String,
    'user': fields.Nested(user_model)
})

register_request = api.model('RegisterRequest', {
    'username': fields.String(required=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True)
})

login_request = api.model('LoginRequest', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
})

google_auth_request = api.model('GoogleAuthRequest', {
    'credential': fields.String(required=True)
})

token_request = api.model('TokenRequest', {
    'token': fields.String(required=True)
})

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

@user_ns.route('/test')
class TestResource(Resource):
    def get(self):
        return {"status": "Auth service is running"}, 200

@auth_ns.route('/google')
class GoogleAuthResource(Resource):
    @api.expect(google_auth_request)
    @api.response(200, 'Success', auth_response)
    def post(self):
        logging.info("=== Received Google Auth Request ===")
        logging.info(f"Headers: {dict(request.headers)}")
        logging.info(f"Body: {request.json}")
        try:
            token = request.json.get('credential')
            if not token:
                return {'error': 'Missing credential token'}, 401
            
            logging.info(f"Token: {token}")
            
            try:
                idinfo = id_token.verify_oauth2_token(
                    token, 
                    google_requests.Request(), 
                    GOOGLE_CLIENT_ID
                )
                logging.info(f"ID Info: {idinfo}")
                
                email = idinfo['email']
                name = idinfo.get('name', '').replace(' ', '_').lower()

                logging.info(f"Email: {email}")
                logging.info(f"Name: {name}")
                
                user = User.query.filter_by(email=email).first()

                logging.info(f"User: {user}")
                
                if not user:
                    username = name or email.split('@')[0]
                    base_username = username
                    counter = 1
                    while User.query.filter_by(username=username).first():
                        username = f"{base_username}{counter}"
                        counter += 1
                    
                    password = generate_password_hash(str(datetime.now()))
                    user = User(
                        username=username,
                        email=email,
                        password_hash=password
                    )
                    db.session.add(user)
                    db.session.commit()
                    
                    logging.info(f"Created new user via Google OAuth: {email}")
                    logging.info(f"User: {user}")
                
                token = generate_token(user.id, user.username)
                
                logging.info(f"Token: {token}")
                
                return {
                    'message': 'Login successful',
                    'token': token,
                    'user': {
                        'id': user.id,
                        'username': user.username
                    }
                }, 200
                
            except ValueError as e:
                logging.error(f"Token verification failed: {str(e)}")
                return {'error': 'Invalid token'}, 401
                
        except Exception as e:
            logging.error(f"Google auth error: {str(e)}")
            return {'error': 'Authentication failed'}, 500

@user_ns.route('/register')
class RegisterResource(Resource):
    @api.expect(register_request)
    def post(self):
        data = request.json    
        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            logging.warning("Missing required fields during registration.")
            return {"error": "Missing required fields"}, 400
        
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            logging.warning(f"Username already exists: {data['username']}")
            return {"error": "Username already exists"}, 400
        
        existing_email = User.query.filter_by(email=data['email']).first()
        if existing_email:
            logging.warning(f"Email already exists: {data['email']}")
            return {"error": "Email already exists"}, 400

        hashed_password = generate_password_hash(data['password'])
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
        logging.debug(f"Adding new user to database: {new_user.username}")
        logging.debug(f"New user: {new_user.__dict__}")
        try:
            db.session.add(new_user)
            db.session.commit()
            logging.info(f"User registered successfully: {data['username']}")
            return {"message": "User registered successfully"}, 201
        except IntegrityError:
            db.session.rollback()
            logging.error("Username or email already exists.")
            return {"error": "Username or email already exists"}, 400
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during registration: {str(e)}")
            return {"error": str(e)}, 500

@user_ns.route('/users')
class UsersResource(Resource):
    @api.marshal_list_with(user_model)
    def get(self):
        users = User.query.all()
        logging.info("Fetched user list.")
        return [{"id": user.id, "username": user.username, "email": user.email} for user in users], 200

@user_ns.route('/login')
class LoginResource(Resource):
    @api.expect(login_request)
    @api.response(200, 'Success', auth_response)
    def post(self):
        data = request.json
        if not data or not data.get('username') or not data.get('password'):
            logging.warning("Missing username or password during login.")
            return {"error": "Missing username or password"}, 400
        
        logging.debug(f"Attempting to log in user: {data['username']}")
        user = User.query.filter_by(username=data['username']).first()
        
        if user:
            logging.debug(f"User found: {user.username}")
            if check_password_hash(user.password_hash, data['password']):
                token = generate_token(user.id, user.username)            
                logging.info(f"User logged in successfully: {data['username']}")
                logging.debug(f"Token: {token}")
                logging.debug(f"User: {user.id} {user.username}")
                return {
                    "message": "Login successful",
                    "token": token,
                    "user": {
                        "id": user.id,
                        "username": user.username
                    }
                }, 200
            else:
                logging.warning("Password check failed for user: %s", user.username)
        else:
            logging.warning("No user found with username: %s", data['username'])
        
        return {"error": "Invalid username or password"}, 401

@user_ns.route('/validate-token')
class ValidateTokenResource(Resource):
    @api.expect(token_request)
    def post(self):
        token = request.json.get('token')
        if not token:
            logging.warning("No token provided for validation.")
            return {"error": "No token provided"}, 401
        
        logging.debug("Received token for validation: %s", token)
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            logging.info("Token validated successfully. Payload: %s", payload)
            return {
                "valid": True,
                "user": {
                    "id": payload['user_id'],
                    "username": payload['username']
                }
            }, 200
        except jwt.ExpiredSignatureError:
            logging.warning("Token has expired.")
            return {"error": "Token has expired"}, 401
        except jwt.InvalidTokenError:
            logging.warning("Invalid token.")
            return {"error": "Invalid token"}, 401

@user_ns.route('/users/<int:user_id>/email')
class UserEmailResource(Resource):
    def get(self, user_id):
        try:
            user = User.query.get(user_id)
            
            if user:
                logging.info(f"Found email for user {user_id}: {user.email}")
                return {
                    'user_id': user.id,
                    'email': user.email
                }, 200
            else:
                logging.warning(f"No user found with ID: {user_id}")
                return {
                    'error': 'User not found',
                    'user_id': user_id
                }, 404

        except Exception as e:
            logging.error(f"Error fetching email for user {user_id}: {str(e)}")
            return {
                'error': 'Internal server error',
                'message': str(e)
            }, 500

@app.before_request
def log_request_info():
    # Exempt the /docs endpoint from logging and API key checks
    if request.path.startswith('/docs') or request.path.startswith('/swagger'):
        return

    logging.info(f"Headers: {request.headers}")
    logging.info(f"Body: {request.get_data()}")

    if request.path.startswith('/api/auth/google'):
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