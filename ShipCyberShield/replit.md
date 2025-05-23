# Maritime Network Management System (NMS) - System Overview

## Overview

This project is a Network Management System (NMS) for maritime vessels, designed to comply with the Korean Register's "Guidance for Cyber Resilience of Ships and Systems" (KR GC-44-K). The system monitors ship systems, provides real-time data visualization, and manages security alerts.

The NMS serves as a central management platform for tracking vessel assets, monitoring security zones, collecting sensor data, managing alerts, and maintaining comprehensive security logs in accordance with maritime cybersecurity regulations.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The Maritime NMS follows a traditional web application architecture with the following components:

### Backend

- **Flask**: Web framework for handling HTTP requests, routing, and API endpoints
- **SQLAlchemy**: ORM for database interactions
- **Flask-Login**: Authentication and session management
- **Flask-Migrate**: Database migration management
- **Gunicorn**: WSGI server for production deployment

### Frontend

- **HTML/Jinja2 Templates**: Server-side rendered pages
- **Bootstrap 5**: CSS framework (dark theme)
- **Font Awesome**: Icon library
- **JavaScript**: Client-side interactivity

### Data Storage

- **Database**: SQLAlchemy ORM with SQLite as a fallback, configurable for PostgreSQL
- **Models**: Defined with SQLAlchemy for vessels, assets, security zones, users, logs, alerts, and sensor data

### Authentication & Security

- **Login System**: Flask-Login for session management
- **Password Security**: Werkzeug's password hashing
- **Access Control**: Role-based access with least privilege principles
- **CSRF Protection**: Via Flask-WTF (implied)
- **Security Logging**: Comprehensive audit logging system

## Key Components

### Models (models.py)

The system uses several key data models:

1. **User**: Authentication and role-based access control with roles (Administrator, Operator, Read-Only)
2. **Vessel**: Represents maritime vessels being monitored
3. **CBSAsset**: Computer-Based System assets on vessels (hardware/software)
4. **SecurityZone**: Network segmentation zones for vessel systems
5. **SensorData**: Telemetry data from vessel systems
6. **Alert**: Security and operational alerts with severity levels
7. **SecurityLog**: Comprehensive audit logging for system events

### API Endpoints (api.py)

RESTful API endpoints for:
- Receiving sensor data from vessels
- Data integrity verification
- Alert management
- Asset inventory updates
- Security log retrieval

### Authentication System (auth.py)

Handles user authentication with:
- Login/logout functionality
- Password management
- Session security
- Access attempt logging

### Web Interface (routes.py, templates/)

Provides UI for:
- Dashboard with system overview and alert statistics
- Asset inventory management
- Security zone visualization
- Alert monitoring and management
- Security log review
- System administration

### Utilities (utils.py)

Helper functions for:
- Role-based access control
- Data integrity verification
- Secure password management

## Data Flow

1. **Authentication Flow**:
   - Users authenticate via the login form
   - Credentials verified against User model
   - Flask-Login manages sessions
   - Security logs record login attempts

2. **Sensor Data Collection**:
   - Vessels send sensor data to the `/api/sensor_data` endpoint
   - Data integrity verification performed
   - Valid data stored in SensorData model
   - Anomalies may trigger Alerts

3. **Alert Management**:
   - Alerts generated from sensor data anomalies or security events
   - Alerts displayed on dashboard and alerts page
   - Users can acknowledge and resolve alerts
   - Alert status changes logged

4. **Asset Inventory**:
   - Administrators can add/edit vessels and assets
   - Assets assigned to security zones
   - Asset configurations and changes tracked in logs

5. **Security Logging**:
   - Security-relevant events logged to SecurityLog model
   - Logs viewable by administrators and operators
   - Logs exportable for compliance purposes

## External Dependencies

- **Flask**: Web framework
- **SQLAlchemy**: ORM for database
- **Flask-Login**: Authentication management
- **Flask-Migrate**: Database migrations
- **Gunicorn**: WSGI server
- **Bootstrap 5**: CSS framework
- **Font Awesome**: Icon library
- **D3.js**: Visualization library (referenced in JS files)

## Deployment Strategy

The application is configured for deployment on Replit with:

1. **Database**: 
   - Currently configured to use SQLite by default
   - Configurable for PostgreSQL via DATABASE_URL environment variable

2. **Environment**:
   - Python 3.11 runtime
   - Dependencies managed via pyproject.toml
   - PostgreSQL support included in Nix configuration

3. **Production Server**:
   - Gunicorn as the WSGI server
   - Configured to listen on port 5000
   - Auto-scaling deployment target

4. **Development Workflow**:
   - Replit workflow configured for running the application
   - Flask debug mode enabled in development

5. **Security Considerations**:
   - Session secret configurable via SESSION_SECRET environment variable
   - ProxyFix middleware for handling forwarded headers
   - Database connection pool settings for stability

## Implementation Guide

When implementing new features or making changes:

1. **Authentication & Authorization**:
   - Use the `@login_required` decorator for protected routes
   - Use the `@role_required` decorator to enforce role-based access
   - Follow the least privilege principle

2. **Database Changes**:
   - Use Flask-Migrate for schema changes
   - Follow the existing model structure
   - Maintain relationships between entities

3. **Security Features**:
   - Log security-relevant events using the SecurityLog model
   - Validate all user inputs
   - Verify data integrity where applicable
   - Follow secure coding practices

4. **UI Development**:
   - Extend existing templates
   - Use Bootstrap 5 dark theme components
   - Follow responsive design principles

5. **API Development**:
   - Follow the RESTful pattern established
   - Implement proper validation and error handling
   - Include appropriate security headers
   - Log API access and errors