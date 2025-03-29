from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, login_required, logout_user, current_user
from app.models import User
from app import db, aws_auth
import boto3
import botocore.exceptions
import json

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(aws_auth.get_sign_up_url())

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(aws_auth.get_sign_in_url())

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(aws_auth.get_sign_out_url())

@auth_bp.route('/aws-cognito-callback')
def aws_cognito_callback():
    """Handle the callback from AWS Cognito"""
    try:
        # Exchange the authorization code for tokens
        access_token = aws_auth.get_access_token(request.args)
        id_token = aws_auth.get_id_token(request.args)
        
        # Get user info from Cognito
        cognito_user_info = aws_auth.get_user_info(access_token)
        username = cognito_user_info.get('username')
        email = cognito_user_info.get('email')
        
        # Check if we know this user
        user = User.query.filter_by(aws_cognito_id=cognito_user_info.get('sub')).first()
        if not user:
            # Create the user in our database
            user = User(
                username=username,
                email=email,
                aws_cognito_id=cognito_user_info.get('sub')
            )
            db.session.add(user)
            db.session.commit()
        
        # Log the user in
        login_user(user)
        
        # Store the tokens in the session
        session['access_token'] = access_token
        session['id_token'] = id_token
        
        flash("Logged in successfully!")
        return redirect(url_for('main.dashboard'))
    except Exception as e:
        flash(f"Login failed: {str(e)}")
        return redirect(url_for('auth.login'))
