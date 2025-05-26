from app import app, db
from models import User

with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"Username: {user.username}")
        print(f"Email: {user.email}")
        print(f"Role: {user.role}")
        print(f"Active: {user.active}")
        print("---") 