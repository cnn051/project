from app import app, db
from models import User, UserRole
from werkzeug.security import generate_password_hash

# Create application context
with app.app_context():
    # Check if admin user already exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@maritime-nms.com',
            role=UserRole.ADMINISTRATOR,
            active=True
        )
        # Set password
        admin.password_hash = generate_password_hash('admin123')
        
        # Add to database
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully.")
    else:
        print("Admin user already exists.")