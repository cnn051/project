# Implementation Phase

## Purpose

The Implementation phase translates the security design into secure, functional code. This document outlines the secure coding practices, standards, tools, and review processes used during the implementation of the Maritime Network Management System (NMS).

## Secure Coding Practices

### Coding Standards

The Maritime NMS development follows these language-specific secure coding standards:

1. **Python (Backend)**
   - PEP 8 style guide for code readability
   - OWASP Python Security Best Practices
   - Flask Security Best Practices
   - SQLAlchemy Security Guidelines

2. **JavaScript (Frontend)**
   - OWASP JavaScript Security Best Practices
   - ES6+ Modern JavaScript guidelines
   - Content Security Policy (CSP) compliance

3. **HTML/CSS (Frontend)**
   - OWASP HTML5 Security Cheat Sheet
   - W3C HTML5 and CSS3 standards
   - Responsive design principles

### Common Security Vulnerabilities Prevention

The following measures are implemented to prevent common security vulnerabilities:

1. **Injection Prevention**
   - All database queries use SQLAlchemy ORM with parameterized queries
   - User input is always validated and sanitized
   - Dynamic queries are avoided where possible

2. **Authentication & Session Management**
   - Flask-Login for secure session management
   - Secure password hashing with Werkzeug
   - CSRF protection with Flask-WTF
   - Session fixation protection
   - Session timeout implementation

3. **Cross-Site Scripting (XSS) Prevention**
   - Template auto-escaping with Jinja2
   - Context-appropriate output encoding
   - Content Security Policy implementation
   - HTML Sanitization for user-generated content

4. **Cross-Site Request Forgery (CSRF) Prevention**
   - Anti-CSRF tokens for all state-changing operations
   - SameSite cookie attributes
   - Origin and Referer header validation

5. **Security Misconfiguration Prevention**
   - Environment-specific configuration
   - Secure default settings
   - Minimal exposure of configuration details
   - Regular configuration review

6. **Sensitive Data Exposure Prevention**
   - TLS for all communications
   - Environment variables for secrets
   - No hardcoded credentials
   - Sensitive data masking in logs

## Security Libraries and Frameworks

The Maritime NMS implementation uses the following security-focused libraries and frameworks:

1. **Python/Flask Backend**
   - Flask-Login: Authentication management
   - Flask-WTF: CSRF protection
   - Werkzeug: Secure password hashing
   - PyJWT: JSON Web Token implementation
   - SQLAlchemy: ORM for database operations
   - python-dotenv: Environment variable management

2. **Frontend**
   - Bootstrap 5: UI framework with secure defaults
   - D3.js: Visualization library
   - Chart.js: Data visualization
   - CSRF protection integration

3. **Security Testing**
   - Pytest: Unit and integration testing
   - Coverage: Code coverage measurement
   - Bandit: Static security analysis for Python
   - ESLint: JavaScript linting with security rules
   - OWASP ZAP: Dynamic application security testing

## Private Key Control (KR GC-44-K, 3.502.1)

In accordance with KR GC-44-K, 3.502.1, the following controls are implemented for private key management:

1. **Key Generation**
   - Strong cryptographic algorithms
   - Secure random number generators
   - Appropriate key lengths (RSA: 2048+, ECC: 256+)

2. **Key Storage**
   - Environment variables for development
   - Secure key storage in production
   - Protection against unauthorized access

3. **Key Usage**
   - Minimized access to private keys
   - Principle of least privilege
   - Logging of key usage

4. **Key Rotation**
   - Regular key rotation schedule
   - Secure key revocation procedures
   - Backward compatibility handling

## Code Review Process

All code is subject to security review before integration:

1. **Peer Review**
   - Developer peer reviews
   - Security-focused code review checklist
   - Documentation of findings and resolutions

2. **Security Review**
   - Dedicated security review for critical components
   - Review by security specialist
   - Threat modeling validation

3. **Automated Analysis**
   - Static code analysis with security plugins
   - Dependency analysis for vulnerabilities
   - Security linting integration

## Coding Example: Secure Implementation

### Example 1: Secure Authentication Implementation

```python
@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with security controls"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Basic validation to prevent empty submissions
        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        # Look up user - using ORM to prevent injection
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            # Log failed login attempt with minimal information
            logging.warning(f"Failed login attempt for username: {username} from IP: {request.remote_addr}")
            
            # Create security log entry
            log = SecurityLog(
                event_type=EventType.ACCESS_CONTROL,
                ip_address=request.remote_addr,
                description=f"Failed login attempt for username: {username}"
            )
            db.session.add(log)
            db.session.commit()
            
            # Generic error message to prevent user enumeration
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        # Check if user is active
        if not user.is_active:
            flash('This account has been deactivated', 'danger')
            return render_template('login.html')
        
        # Login successful
        login_user(user)
        
        # Update last login time
        user.last_login = datetime.utcnow()
        
        # Create security log entry for successful login
        log = SecurityLog(
            event_type=EventType.ACCESS_CONTROL,
            user_id=user.id,
            ip_address=request.remote_addr,
            description=f"Successful login: {user.username}"
        )
        db.session.add(log)
        db.session.commit()
        
        # Redirect to next page or dashboard with safe URL validation
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('dashboard')
        
        return redirect(next_page)
    
    return render_template('login.html')
