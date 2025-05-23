# main.py - Entry point for the application
import os
import logging
from app import app, db
import models
import routes
import auth
import api

# Configure logging
logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    # Ensure all models are imported before creating tables
    with app.app_context():
        db.create_all()
    
    # Run the application
    app.run(host="0.0.0.0", port=5000, debug=True)
