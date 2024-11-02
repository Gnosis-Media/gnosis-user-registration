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

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')

# CORS 
app = Flask(__name__)
CORS(app)
C_PORT = 5007

# Use the existing database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:WmhkO3h8qxJJiPpdoYvc@users-db.c1ytbjumgtbu.us-east-1.rds.amazonaws.com:3306/user_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

app.config['SECRET_KEY'] = 'super-secret-key'  # In production, use env variable
JWT_EXPIRATION_HOURS = 24

# Add new helper function
def generate_token(user_id, username):
    token = jwt.encode({
        'user_id': user_id,
        'username': username,
        'exp': datetime.now() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return token

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

if __name__ == '__main__':
    with app.app_context():
        if not database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
            create_database(app.config['SQLALCHEMY_DATABASE_URI'])
        db.create_all()
    app.run(host='0.0.0.0', debug=True, port=C_PORT)
