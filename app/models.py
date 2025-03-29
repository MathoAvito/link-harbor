from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    aws_cognito_id = db.Column(db.String(200), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'
