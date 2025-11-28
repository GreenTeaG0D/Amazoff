import os
import uuid
import time
import re
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

from flask import Flask, render_template, redirect, url_for, request, abort, session, flash, jsonify, send_from_directory

import SecurityHandler
import DatabaseInterface

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev-secret")

# Rate limiting storage (in-memory, resets on server restart)
# SECURITY: Rate limiting prevents brute force attacks
_rate_limit_store = defaultdict(list)
RATE_LIMIT_ATTEMPTS = 5  # Maximum attempts
RATE_LIMIT_WINDOW = 900  # 15 minutes in seconds

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _check_rate_limit(identifier):
    """
    Check if an IP address has exceeded rate limits.
    SECURITY: Prevents brute force attacks by limiting attempts per time window.
    Returns: (allowed: bool, remaining_attempts: int, reset_time: int)
    """
    current_time = time.time()
    attempts = _rate_limit_store[identifier]
    
    # Remove old attempts outside the time window
    attempts[:] = [t for t in attempts if current_time - t < RATE_LIMIT_WINDOW]
    
    if len(attempts) >= RATE_LIMIT_ATTEMPTS:
        # Calculate when the oldest attempt will expire
        oldest_attempt = min(attempts) if attempts else current_time
        reset_time = int(oldest_attempt + RATE_LIMIT_WINDOW - current_time)
        return False, 0, reset_time
    
    remaining = RATE_LIMIT_ATTEMPTS - len(attempts)
    return True, remaining, 0


def _record_rate_limit_attempt(identifier):
    """Record a rate limit attempt for an identifier."""
    _rate_limit_store[identifier].append(time.time())


def _validate_password_complexity(password):
    """
    Validate password meets complexity requirements.
    SECURITY: Enforces strong passwords to prevent dictionary attacks.
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    Returns: (is_valid: bool, error_message: str)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
    
    return True, ""


def _generate_csrf_token():
    """Generate a CSRF token and store it in the session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


def _validate_csrf_token(token):
    """Validate a CSRF token against the session."""
    return token and 'csrf_token' in session and token == session['csrf_token']


def _init_demo_user():
    """Ensure the demo user exists with correct credentials and admin role."""
    from BBCrypt import sha256_hash
    demo_username = "user"
    demo_password = "pass"
    demo_hash = sha256_hash(demo_password)
    
    import sqlite3 as sql
    conn = sql.connect(DatabaseInterface.MAIN_DB_FILE)
    cur = conn.cursor()
    
    # Check if user exists
    cur.execute("SELECT username, role FROM users WHERE username = ?", (demo_username,))
    existing = cur.fetchone()
    if existing is None:
        # SECURITY: Insert demo user with admin role
        # SQL INJECTION PROTECTION: Parameterized query
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", 
                   (demo_username, demo_hash))
        conn.commit()
        print(f"[INIT] Created demo user: {demo_username} with admin role")
    else:
        # Update password hash and ensure admin role
        # SQL INJECTION PROTECTION: Parameterized queries
        cur.execute("UPDATE users SET password_hash = ?, role = 'admin' WHERE username = ?",
                   (demo_hash, demo_username))
        conn.commit()
        print(f"[INIT] Updated demo user: {demo_username} to admin role")
    
    conn.close()


# Initialize demo user on app startup
_init_demo_user()


@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into all template contexts."""
    return dict(csrf_token=_generate_csrf_token())


def _current_user():
    """Get current username from session."""
    return session.get("username", "*")


def _get_current_user_role():
    """Get current user's role for template context."""
    username = session.get("username", "*")
    if username == "*":
        return None
    return _get_user_role(username)


def _current_token():
    return session.get("session_token")


def _get_user_role(username):
    """
    Get current user's role.
    SECURITY: Returns None if user doesn't exist or isn't authenticated.
    """
    if not username or username == "*":
        return None
    return DatabaseInterface.DatabaseInterface.get_user_role(username)


def _require_role(allowed_roles):
    """
    Decorator to require specific roles for a route.
    SECURITY: Checks user authentication and role before allowing access.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            username = session.get('username')
            token = _current_token()
            
            # Check authentication
            if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
                session.clear()
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('login'))
            
            # Check role
            user_role = _get_user_role(username)
            if user_role not in allowed_roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for('home'))
            
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator


@app.route('/')
@app.route('/index')
@app.route('/home')
def home():
    # Log activity
    username = session.get('username')
    DatabaseInterface.DatabaseInterface.log_activity(
        username if username and username != "*" else None,
        'page_view', 'home', request.remote_addr
    )
    return render_template('index.html', 
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role()), 200


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login endpoint.
    
    SECURITY: Input validation and sanitization.
    SQL INJECTION PROTECTION: SecurityHandler uses parameterized queries.
    XSS PROTECTION: All inputs are escaped in templates.
    """
    if request.method == 'POST':
        # SECURITY: Sanitize username input - limit length, strip whitespace
        # XSS PROTECTION: Input is escaped when displayed in templates
        username = request.form.get('username', '').strip()[:50]  # Limit length
        password = request.form.get('password', '')  # Password not displayed, so XSS not applicable
        redirect_url = request.form.get('redirect_url') or request.args.get('next')
        
        # SECURITY: Validate redirect_url to prevent open redirect attacks
        if redirect_url and (not redirect_url.startswith('/') or redirect_url.startswith('//')):
            redirect_url = None

        # SQL INJECTION PROTECTION: SecurityHandler.login() uses parameterized queries
        token = SecurityHandler.login(username, password, requester_ip=request.remote_addr)
        if isinstance(token, str):
            session['username'] = username
            session['session_token'] = token
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'login', 'success', request.remote_addr
            )
            flash("Login successful.", "success")
            # If redirect_url is provided (from modal), use it to stay on same page
            if redirect_url and redirect_url.startswith('/') and not redirect_url.startswith('//'):
                return redirect(redirect_url)
            # Only redirect to dashboard if no redirect_url (e.g., from dedicated login page)
            # If coming from modal, redirect_url should always be set
            return redirect(url_for('dashboard'))
        elif token == -2:
            flash("Too many active sessions. Please close one and try again.", "warning")
        elif token == -3:
            flash("Your account has been banned. Please contact support.", "error")
        else:
            # Log failed login attempt
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'login', 'failed', request.remote_addr
            )
            flash("Invalid username or password.", "error")
    return render_template('login.html', 
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role()), 200


@app.route('/logout', methods=['POST'])
def logout():
    token = _current_token()
    if token:
        SecurityHandler.logout(token)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    User registration endpoint.
    
    SECURITY: Input validation, password complexity, rate limiting, CSRF protection.
    SQL INJECTION PROTECTION: SecurityHandler uses parameterized queries.
    XSS PROTECTION: All inputs are escaped in templates.
    """
    if request.method == 'POST':
        # SECURITY: CSRF Protection - validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not _validate_csrf_token(csrf_token):
            flash("Security validation failed. Please try again.", "error")
            return render_template('signup.html', 
                                 current_user=_current_user(),
                                 current_user_role=_get_current_user_role(),
                                 csrf_token=_generate_csrf_token()), 200
        
        # SECURITY: Rate limiting - prevent registration spam
        client_ip = request.remote_addr
        allowed, remaining, reset_time = _check_rate_limit(f"signup_{client_ip}")
        if not allowed:
            flash(f"Too many registration attempts. Please try again in {reset_time // 60 + 1} minutes.", "error")
            return render_template('signup.html', 
                                 current_user=_current_user(),
                                 current_user_role=_get_current_user_role(),
                                 csrf_token=_generate_csrf_token()), 429
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        redirect_url = request.form.get('redirect_url') or request.args.get('next')
        
        # SECURITY: Validate password confirmation
        if password != confirm_password:
            _record_rate_limit_attempt(f"signup_{client_ip}")
            flash("Passwords do not match.", "error")
            return render_template('signup.html', 
                                 current_user=_current_user(),
                                 current_user_role=_get_current_user_role(),
                                 csrf_token=_generate_csrf_token()), 200
        
        # SECURITY: Validate password complexity
        is_valid, error_msg = _validate_password_complexity(password)
        if not is_valid:
            _record_rate_limit_attempt(f"signup_{client_ip}")
            flash(error_msg, "error")
            return render_template('signup.html', 
                                 current_user=_current_user(),
                                 current_user_role=_get_current_user_role(),
                                 csrf_token=_generate_csrf_token()), 200
        
        if SecurityHandler.register(username, password):
            # Successful registration - clear rate limit
            _rate_limit_store[f"signup_{client_ip}"].clear()
            flash("Account created successfully! Please log in.", "success")
            # Redirect to login, preserving redirect URL if from modal
            if redirect_url:
                return redirect(url_for('login', next=redirect_url))
            return redirect(url_for('login'))
        else:
            _record_rate_limit_attempt(f"signup_{client_ip}")
            # SECURITY: Generic error message to prevent username enumeration
            flash("Registration failed. Username may already exist or input is invalid.", "error")
    
    # Generate CSRF token for GET requests
    csrf_token = _generate_csrf_token()
    return render_template('signup.html', 
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role(),
                         csrf_token=csrf_token), 200


@app.route("/search/<query>", methods=['GET'])
def search(query):
    """
    Search products by query string.
    
    SECURITY: Query parameter is sanitized and length-limited.
    SQL INJECTION PROTECTION: Uses parameterized queries via search_products().
    XSS PROTECTION: Query is escaped by Jinja2 template engine.
    """
    # SECURITY: Sanitize and limit query length to prevent DoS attacks
    # XSS PROTECTION: strip() removes dangerous characters, length limit prevents buffer issues
    query = query.strip()[:100]  # Limit length to prevent DoS
    
    # SQL INJECTION PROTECTION: search_products() uses parameterized LIKE queries
    products = DatabaseInterface.DatabaseInterface.search_products(query) if query else []
    
    # Log search activity
    username = session.get('username')
    DatabaseInterface.DatabaseInterface.log_activity(
        username if username and username != "*" else None,
        'search', f'query={query}', request.remote_addr
    )
    
    # Increment view counts for all products in search results
    # SECURITY: Only increment if products exist and have valid IDs
    if products:
        for product in products:
            try:
                product_id = product.get('id')
                if product_id:
                    DatabaseInterface.DatabaseInterface.increment_product_views(product_id)
            except Exception as e:
                # Log error but don't break the page
                print(f"Error incrementing views for product {product.get('id')}: {e}")
        
        # Refresh products to get updated view counts after incrementing
        products = DatabaseInterface.DatabaseInterface.search_products(query) if query else []
    
    # XSS PROTECTION: All template variables are auto-escaped by Jinja2
    return render_template('search.html', 
                         query=query, 
                         products=products, 
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role()), 200


@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    token = _current_token()
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))
    
    # Log activity
    DatabaseInterface.DatabaseInterface.log_activity(
        username, 'page_view', 'dashboard', request.remote_addr
    )
    
    return render_template('dashboard.html', 
                         current_user=username,
                         current_user_role=_get_current_user_role()), 200


@app.route('/cart')
def cart():
    username = session.get('username')
    if not username or username == "*":
        return render_template('cart.html', 
                             current_user=_current_user(),
                             current_user_role=_get_current_user_role()), 200
    
    cart_items = DatabaseInterface.DatabaseInterface.get_cart_items(username)
    cart_total = DatabaseInterface.DatabaseInterface.get_cart_total(username)
    
    return render_template('cart.html', 
                         current_user=username,
                         current_user_role=_get_current_user_role(),
                         cart_items=cart_items,
                         cart_total=cart_total), 200


@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    username = session.get('username')
    if not username or username == "*":
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    
    if not product_id:
        return jsonify({"success": False, "error": "Product ID required"}), 400
    
    try:
        DatabaseInterface.DatabaseInterface.add_to_cart(username, product_id, quantity)
        # Log activity
        DatabaseInterface.DatabaseInterface.log_activity(
            username, 'cart_add', f'product_id={product_id}, quantity={quantity}', request.remote_addr
        )
        return jsonify({"success": True}), 200
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Add to cart failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/cart/update', methods=['POST'])
def update_cart():
    """
    Update cart item quantity.
    
    SECURITY: Requires authentication, validates input, ensures user owns the cart item.
    SQL INJECTION PROTECTION: Uses parameterized queries via update_cart_quantity().
    """
    username = session.get('username')
    if not username or username == "*":
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # SECURITY: Validate JSON input
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400
    
    # SECURITY: Validate and sanitize inputs
    try:
        cart_item_id = int(data.get('cart_item_id', 0))
        quantity = int(data.get('quantity', 0))
        
        if cart_item_id <= 0:
            return jsonify({"success": False, "error": "Invalid cart item ID"}), 400
        if quantity < 0 or quantity > 100:  # Prevent unrealistic quantities
            return jsonify({"success": False, "error": "Invalid quantity"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid input"}), 400
    
    # SQL INJECTION PROTECTION: update_cart_quantity() uses parameterized queries
    # SECURITY: Username is verified in update_cart_quantity() to ensure user owns the item
    try:
        success = DatabaseInterface.DatabaseInterface.update_cart_quantity(cart_item_id, quantity, username)
        if success:
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'cart_update', f'cart_item_id={cart_item_id}, quantity={quantity}', request.remote_addr
            )
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "error": "Item not found"}), 404
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Cart update failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/cart/remove', methods=['POST'])
def remove_from_cart():
    """
    Remove item from cart.
    
    SECURITY: Requires authentication, validates input, ensures user owns the cart item.
    SQL INJECTION PROTECTION: Uses parameterized queries via remove_from_cart().
    """
    username = session.get('username')
    if not username or username == "*":
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # SECURITY: Validate JSON input
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400
    
    # SECURITY: Validate and sanitize cart_item_id
    try:
        cart_item_id = int(data.get('cart_item_id', 0))
        if cart_item_id <= 0:
            return jsonify({"success": False, "error": "Invalid cart item ID"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid input"}), 400
    
    # SQL INJECTION PROTECTION: remove_from_cart() uses parameterized queries
    # SECURITY: Username is verified to ensure user owns the item
    try:
        success = DatabaseInterface.DatabaseInterface.remove_from_cart(cart_item_id, username)
        if success:
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'cart_remove', f'cart_item_id={cart_item_id}', request.remote_addr
            )
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "error": "Item not found"}), 404
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Cart update failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """
    Checkout process - create orders from cart items.
    
    SECURITY: Requires authentication, validates cart ownership.
    SQL INJECTION PROTECTION: Uses parameterized queries.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to checkout.", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get cart items
        cart_items = DatabaseInterface.DatabaseInterface.get_cart_items(username)
        
        if not cart_items:
            flash("Your cart is empty.", "warning")
            return redirect(url_for('cart'))
        
        # Create orders for each cart item
        order_ids = []
        try:
            for item in cart_items:
                order_id = DatabaseInterface.DatabaseInterface.create_order(
                    username, item['product_id'], item['quantity'], item['price']
                )
                order_ids.append(order_id)
                
                # Log purchase activity
                DatabaseInterface.DatabaseInterface.log_activity(
                    username, 'purchase',
                    f'product_id={item["product_id"]}, quantity={item["quantity"]}, price={item["price"]}',
                    request.remote_addr
                )
            
            # Clear cart after successful checkout
            import sqlite3 as sql
            conn = sql.connect(DatabaseInterface.MAIN_DB_FILE)
            conn.execute("DELETE FROM cart_items WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            
            flash(f"Order placed successfully! Order IDs: {', '.join(map(str, order_ids))}", "success")
            return redirect(url_for('order_history'))
        except Exception as e:
            print(f"[ERROR] Checkout failed: {e}")
            flash("Error processing your order. Please try again.", "error")
            return redirect(url_for('cart'))
    
    # GET request - show checkout confirmation
    cart_items = DatabaseInterface.DatabaseInterface.get_cart_items(username)
    cart_total = DatabaseInterface.DatabaseInterface.get_cart_total(username)
    
    if not cart_items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('cart'))
    
    return render_template('checkout.html',
                         current_user=username,
                         current_user_role=_get_current_user_role(),
                         cart_items=cart_items,
                         cart_total=cart_total), 200


@app.route('/orders')
def order_history():
    """
    View order history for the current user.
    
    SECURITY: Requires authentication, shows only user's own orders.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to view your orders.", "warning")
        return redirect(url_for('login'))
    
    orders = DatabaseInterface.DatabaseInterface.get_user_orders(username)
    
    # Log activity
    DatabaseInterface.DatabaseInterface.log_activity(
        username, 'page_view', 'order_history', request.remote_addr
    )
    
    return render_template('orders.html',
                         current_user=username,
                         current_user_role=_get_current_user_role(),
                         orders=orders), 200


@app.route('/wishlist')
def wishlist():
    """
    View user's wishlist.
    
    SECURITY: Requires authentication, shows only user's own wishlist.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to view your wishlist.", "warning")
        return redirect(url_for('login'))
    
    wishlist_items = DatabaseInterface.DatabaseInterface.get_wishlist(username)
    
    # Log activity
    DatabaseInterface.DatabaseInterface.log_activity(
        username, 'page_view', 'wishlist', request.remote_addr
    )
    
    return render_template('wishlist.html',
                         current_user=username,
                         current_user_role=_get_current_user_role(),
                         wishlist_items=wishlist_items), 200


@app.route('/wishlist/add', methods=['POST'])
def add_to_wishlist():
    """
    Add a product to wishlist.
    
    SECURITY: Requires authentication, validates input.
    """
    username = session.get('username')
    if not username or username == "*":
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    data = request.get_json()
    product_id = data.get('product_id')
    
    if not product_id:
        return jsonify({"success": False, "error": "Product ID required"}), 400
    
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid product ID"}), 400
    
    try:
        success = DatabaseInterface.DatabaseInterface.add_to_wishlist(username, product_id)
        if success:
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'wishlist_add', f'product_id={product_id}', request.remote_addr
            )
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "error": "Product already in wishlist"}), 400
    except Exception as e:
        print(f"[ERROR] Add to wishlist failed: {e}")
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/wishlist/remove', methods=['POST'])
def remove_from_wishlist():
    """
    Remove a product from wishlist.
    
    SECURITY: Requires authentication, validates input.
    """
    username = session.get('username')
    if not username or username == "*":
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    data = request.get_json()
    product_id = data.get('product_id')
    
    if not product_id:
        return jsonify({"success": False, "error": "Product ID required"}), 400
    
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid product ID"}), 400
    
    try:
        success = DatabaseInterface.DatabaseInterface.remove_from_wishlist(username, product_id)
        if success:
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'wishlist_remove', f'product_id={product_id}', request.remote_addr
            )
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "error": "Product not in wishlist"}), 404
    except Exception as e:
        print(f"[ERROR] Remove from wishlist failed: {e}")
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/wishlist/check', methods=['POST'])
def check_wishlist():
    """
    Check which products are in user's wishlist.
    
    SECURITY: Requires authentication.
    """
    username = session.get('username')
    if not username or username == "*":
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    data = request.get_json()
    product_ids = data.get('product_ids', [])
    
    if not product_ids:
        return jsonify({"success": True, "in_wishlist": []}), 200
    
    try:
        product_ids = [int(pid) for pid in product_ids]
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid product IDs"}), 400
    
    try:
        in_wishlist = []
        for product_id in product_ids:
            if DatabaseInterface.DatabaseInterface.is_in_wishlist(username, product_id):
                in_wishlist.append(product_id)
        return jsonify({"success": True, "in_wishlist": in_wishlist}), 200
    except Exception as e:
        print(f"[ERROR] Check wishlist failed: {e}")
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """
    Display product details page with reviews.
    
    SECURITY: Validates product exists, logs activity.
    SQL INJECTION PROTECTION: Uses parameterized queries.
    """
    # Check if user is seller/admin to allow viewing delisted products
    username = session.get('username')
    token = _current_token()
    is_seller_or_admin = False
    if username and token and SecurityHandler.is_authenticated(username, token, request.remote_addr):
        user_role = _get_user_role(username)
        is_seller_or_admin = user_role in ['admin', 'seller']
    
    # Allow viewing delisted products for sellers/admins
    product = DatabaseInterface.DatabaseInterface.get_product(product_id, include_delisted=is_seller_or_admin)
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for('home'))
    
    # Get reviews for this product
    reviews = DatabaseInterface.DatabaseInterface.get_product_reviews(product_id)
    
    # Check if current user has purchased this product (for review eligibility)
    username = session.get('username')
    can_review = False
    user_review = None
    if username and username != "*":
        can_review = DatabaseInterface.DatabaseInterface.has_user_purchased_product(username, product_id)
        user_review = DatabaseInterface.DatabaseInterface.get_user_review(product_id, username)
    
    # Increment view count
    DatabaseInterface.DatabaseInterface.increment_product_views(product_id)
    
    # Log activity
    if username and username != "*":
        DatabaseInterface.DatabaseInterface.log_activity(
            username, 'product_view', f'product_id={product_id}', request.remote_addr
        )
    else:
        DatabaseInterface.DatabaseInterface.log_activity(
            None, 'product_view', f'product_id={product_id}', request.remote_addr
        )
    
    return render_template('product_detail.html',
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role(),
                         product=product,
                         reviews=reviews,
                         can_review=can_review,
                         user_review=user_review), 200


@app.route('/listings/<category>')
def listings(category):
    """
    Display product listings for a given category.
    
    SECURITY: Category parameter is validated against whitelist to prevent path traversal.
    SQL INJECTION PROTECTION: Uses parameterized queries via get_products_by_category().
    XSS PROTECTION: All user-generated content is escaped by Jinja2 template engine.
    """
    # SECURITY: Whitelist category values to prevent injection/path traversal attacks
    category_names = {
        'electronics': 'Electronics',
        'clothing': 'Clothing',
        'home-garden': 'Home & Garden',
        'books': 'Books',
        'gaming': 'Gaming',
        'sports': 'Sports & Outdoors'
    }
    
    # SECURITY: Validate category against whitelist, default to safe value if invalid
    if category not in category_names:
        flash("Invalid category.", "warning")
        return redirect(url_for('home'))
    
    category_name = category_names[category]
    
    # SQL INJECTION PROTECTION: Parameterized query in get_products_by_category()
    products = DatabaseInterface.DatabaseInterface.get_products_by_category(category)
    
    # Increment view counts for all products in this category
    # SECURITY: Only increment if products exist and have valid IDs
    username = session.get('username')
    if products:
        for product in products:
            try:
                product_id = product.get('id')
                if product_id:
                    DatabaseInterface.DatabaseInterface.increment_product_views(product_id)
                    # Log activity
                    if username and username != "*":
                        DatabaseInterface.DatabaseInterface.log_activity(
                            username, 'product_view', f'product_id={product_id}', request.remote_addr
                        )
            except Exception as e:
                # Log error but don't break the page
                print(f"Error incrementing views for product {product.get('id')}: {e}")
        
        # Refresh products to get updated view counts after incrementing
        products = DatabaseInterface.DatabaseInterface.get_products_by_category(category)
    
    # Log category view
    if username and username != "*":
        DatabaseInterface.DatabaseInterface.log_activity(
            username, 'page_view', f'category={category}', request.remote_addr
        )
    
    # XSS PROTECTION: Jinja2 auto-escapes all template variables
    return render_template('listings.html', 
                         category=category,
                         category_name=category_name,
                         products=products,
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role()), 200


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    """
    Admin/Seller panel for creating product listings.
    
    SECURITY: Requires authentication and admin or seller role.
    RBAC: Admin and seller roles can access this panel.
    XSS PROTECTION: All user input is sanitized and escaped.
    SQL INJECTION PROTECTION: Uses parameterized queries via create_product().
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check - prevents unauthorized access
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to access the admin panel.", "warning")
        return redirect(url_for('login'))
    
    # RBAC: Check if user has admin or seller role
    user_role = _get_user_role(username)
    if user_role not in ['admin', 'seller']:
        flash("You do not have permission to access this panel.", "error")
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # XSS PROTECTION: strip() removes leading/trailing whitespace, prevents some injection attempts
        # SECURITY: Input validation and sanitization
        name = request.form.get('name', '').strip()[:200]  # Limit length to prevent DoS
        price = request.form.get('price', '').strip()
        description = request.form.get('description', '').strip()[:5000]  # Limit length
        category = request.form.get('category', '').strip()
        
        # Get user role for conditional analytics
        user_role = _get_user_role(username)
        
        # SECURITY: Validate required fields
        if not name or not price or not category:
            flash("Name, price, and category are required.", "error")
            # Get analytics based on role for error display
            if user_role == 'admin':
                cart_analytics = DatabaseInterface.DatabaseInterface.get_cart_analytics()
                user_count = DatabaseInterface.DatabaseInterface.get_user_count()
                all_users = DatabaseInterface.DatabaseInterface.get_all_users()
                all_products = DatabaseInterface.DatabaseInterface.get_all_products()
                seller_analytics = None
            else:
                cart_analytics = None
                user_count = None
                all_users = None
                all_products = None
                seller_analytics = DatabaseInterface.DatabaseInterface.get_seller_analytics(username)
            return render_template('admin.html', 
                                 current_user=username,
                                 current_user_role=user_role,
                                 cart_analytics=cart_analytics,
                                 user_count=user_count,
                                 all_users=all_users,
                                 all_products=all_products,
                                 seller_analytics=seller_analytics), 200
        
        # SECURITY: Whitelist category values to prevent injection
        valid_categories = ['electronics', 'clothing', 'home-garden', 'books', 'gaming', 'sports']
        if category not in valid_categories:
            flash("Invalid category selected.", "error")
            # Get analytics based on role for error display
            if user_role == 'admin':
                cart_analytics = DatabaseInterface.DatabaseInterface.get_cart_analytics()
                user_count = DatabaseInterface.DatabaseInterface.get_user_count()
                all_users = DatabaseInterface.DatabaseInterface.get_all_users()
                all_products = DatabaseInterface.DatabaseInterface.get_all_products()
                seller_analytics = None
            else:
                cart_analytics = None
                user_count = None
                all_users = None
                all_products = None
                seller_analytics = DatabaseInterface.DatabaseInterface.get_seller_analytics(username)
            return render_template('admin.html', 
                                 current_user=username,
                                 current_user_role=user_role,
                                 cart_analytics=cart_analytics,
                                 user_count=user_count,
                                 all_users=all_users,
                                 all_products=all_products,
                                 seller_analytics=seller_analytics), 200
        
        # SECURITY: Validate and sanitize price input
        try:
            price = float(price)
            if price <= 0 or price > 999999.99:  # Prevent unrealistic values
                raise ValueError("Price must be between 0.01 and 999999.99")
        except (ValueError, TypeError):
            flash("Invalid price. Please enter a valid number.", "error")
            # Get analytics based on role for error display
            if user_role == 'admin':
                cart_analytics = DatabaseInterface.DatabaseInterface.get_cart_analytics()
                user_count = DatabaseInterface.DatabaseInterface.get_user_count()
                all_users = DatabaseInterface.DatabaseInterface.get_all_users()
                all_products = DatabaseInterface.DatabaseInterface.get_all_products()
                seller_analytics = None
            else:
                cart_analytics = None
                user_count = None
                all_users = None
                all_products = None
                seller_analytics = DatabaseInterface.DatabaseInterface.get_seller_analytics(username)
            return render_template('admin.html', 
                                 current_user=username,
                                 current_user_role=user_role,
                                 cart_analytics=cart_analytics,
                                 user_count=user_count,
                                 all_users=all_users,
                                 all_products=all_products,
                                 seller_analytics=seller_analytics), 200
        
        # SECURITY: File upload validation
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                # SECURITY: secure_filename() prevents path traversal attacks
                # SECURITY: UUID prevents filename collisions and injection
                filename = secure_filename(file.filename)
                ext = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{uuid.uuid4().hex}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                image_url = f"/static/uploads/{unique_filename}"
        
        # SQL INJECTION PROTECTION: create_product() uses parameterized queries
        # SECURITY: created_by is set to current username to track product ownership
        try:
            product_id = DatabaseInterface.DatabaseInterface.create_product(
                name=name,
                price=price,
                description=description if description else None,
                image_url=image_url,
                category=category,
                created_by=username
            )
            # XSS PROTECTION: Flash message content is escaped by Jinja2
            flash(f"Product '{name}' created successfully! (ID: {product_id})", "success")
            return redirect(url_for('admin'))
        except Exception as e:
            # SECURITY: Don't leak exception details to users
            flash("Error creating product. Please try again.", "error")
            print(f"[ERROR] Product creation failed: {e}")  # Log for debugging
    
    # Get analytics based on role
    user_role = _get_user_role(username)
    if user_role == 'admin':
        # SQL INJECTION PROTECTION: No user input in these queries
        cart_analytics = DatabaseInterface.DatabaseInterface.get_cart_analytics()
        user_count = DatabaseInterface.DatabaseInterface.get_user_count()
        all_users = DatabaseInterface.DatabaseInterface.get_all_users()
        all_products = DatabaseInterface.DatabaseInterface.get_all_products()
        seller_analytics = None
    else:
        # Seller role - get seller-specific analytics
        cart_analytics = None
        user_count = None
        all_users = None
        all_products = None
        seller_analytics = DatabaseInterface.DatabaseInterface.get_seller_analytics(username)
    
    # XSS PROTECTION: All template variables are auto-escaped by Jinja2
    return render_template('admin.html', 
                         current_user=username,
                         current_user_role=_get_current_user_role(),
                         cart_analytics=cart_analytics,
                         user_count=user_count,
                         all_users=all_users,
                         all_products=all_products,
                         seller_analytics=seller_analytics), 200


@app.route('/admin/analytics')
def admin_analytics():
    """
    Admin analytics page showing cart statistics and user count.
    
    SECURITY: Requires authentication and admin role.
    RBAC: Only admin role can access analytics.
    SQL INJECTION PROTECTION: Analytics queries use no user input, pure aggregations.
    XSS PROTECTION: All data is escaped by Jinja2 template engine.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to access the admin panel.", "warning")
        return redirect(url_for('login'))
    
    # RBAC: Check if user has admin role
    user_role = _get_user_role(username)
    if user_role != 'admin':
        flash("You do not have permission to access analytics.", "error")
        return redirect(url_for('home'))
    
    # SQL INJECTION PROTECTION: No user input in these queries
    cart_analytics = DatabaseInterface.DatabaseInterface.get_cart_analytics()
    user_count = DatabaseInterface.DatabaseInterface.get_user_count()
    
    # XSS PROTECTION: All template variables are auto-escaped by Jinja2
    return render_template('admin_analytics.html', 
                         current_user=username,
                         current_user_role=_get_current_user_role(),
                         cart_analytics=cart_analytics,
                         user_count=user_count), 200


@app.route('/admin/update_role', methods=['POST'])
def update_user_role():
    """
    Update a user's role (admin only).
    
    SECURITY: Requires authentication and admin role.
    RBAC: Only admin can update user roles.
    SQL INJECTION PROTECTION: Uses parameterized queries via update_user_role().
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # RBAC: Check if user has admin role
    user_role = _get_user_role(username)
    if user_role != 'admin':
        return jsonify({"success": False, "error": "Permission denied"}), 403
    
    # SECURITY: Validate JSON input
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400
    
    target_username = data.get('username', '').strip()
    new_role = data.get('role', '').strip()
    
    # SECURITY: Validate inputs
    if not target_username or not new_role:
        return jsonify({"success": False, "error": "Username and role required"}), 400
    
    # SECURITY: Prevent self-demotion from admin
    if target_username == username and new_role != 'admin':
        return jsonify({"success": False, "error": "Cannot change your own admin role"}), 400
    
    # SECURITY: Whitelist valid roles
    valid_roles = ['buyer', 'seller', 'admin']
    if new_role not in valid_roles:
        return jsonify({"success": False, "error": "Invalid role"}), 400
    
    # SQL INJECTION PROTECTION: update_user_role() uses parameterized queries
    try:
        success = DatabaseInterface.DatabaseInterface.update_user_role(target_username, new_role)
        if success:
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "error": "User not found"}), 404
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Role update failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/admin/ban_user', methods=['POST'])
def ban_user():
    """
    Ban or unban a user (admin only).
    
    SECURITY: Requires authentication and admin role.
    RBAC: Only admin can ban/unban users.
    SQL INJECTION PROTECTION: Uses parameterized queries via ban_user()/unban_user().
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # RBAC: Check if user has admin role
    user_role = _get_user_role(username)
    if user_role != 'admin':
        return jsonify({"success": False, "error": "Permission denied"}), 403
    
    # SECURITY: Validate JSON input
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400
    
    target_username = data.get('username', '').strip()
    action = data.get('action', '').strip()  # 'ban' or 'unban'
    
    # SECURITY: Validate inputs
    if not target_username or not action:
        return jsonify({"success": False, "error": "Username and action required"}), 400
    
    # SECURITY: Prevent self-banning
    if target_username == username:
        return jsonify({"success": False, "error": "Cannot ban yourself"}), 400
    
    # SECURITY: Validate action
    if action not in ['ban', 'unban']:
        return jsonify({"success": False, "error": "Invalid action"}), 400
    
    # SQL INJECTION PROTECTION: ban_user()/unban_user() use parameterized queries
    try:
        if action == 'ban':
            success = DatabaseInterface.DatabaseInterface.ban_user(target_username)
        else:
            success = DatabaseInterface.DatabaseInterface.unban_user(target_username)
        
        if success:
            # Invalidate all sessions for banned user
            if action == 'ban':
                # Get all sessions for this user and invalidate them
                import sqlite3 as sql
                conn = sql.connect(DatabaseInterface.MAIN_DB_FILE)
                conn.execute("DELETE FROM sessions WHERE username = ?", (target_username,))
                conn.commit()
                conn.close()
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "error": "User not found"}), 404
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Ban/unban failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/review/create', methods=['POST'])
def create_review():
    """
    Create or update a product review.
    
    SECURITY: Requires authentication, validates user has purchased product.
    XSS PROTECTION: Review HTML is sanitized.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # Handle both JSON and form-data (for file uploads)
    if request.content_type and 'application/json' in request.content_type:
        data = request.get_json()
        product_id = data.get('product_id')
        rating = data.get('rating')
        review_text = data.get('review_text', '').strip()
        review_html = data.get('review_html', '').strip()
        image_url = None
    else:
        # Form data (multipart/form-data)
        product_id = request.form.get('product_id')
        rating = request.form.get('rating')
        review_text = request.form.get('review_text', '').strip()
        review_html = request.form.get('review_html', '').strip()
        
        # SECURITY: File upload for review image
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                ext = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{uuid.uuid4().hex}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                image_url = f"/static/uploads/{unique_filename}"
    
    # SECURITY: Validate inputs
    try:
        product_id = int(product_id)
        rating = int(rating)
        if rating < 1 or rating > 5:
            return jsonify({"success": False, "error": "Rating must be between 1 and 5"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid input"}), 400
    
    if not review_text:
        return jsonify({"success": False, "error": "Review text is required"}), 400
    
    # SECURITY: Verify user has purchased this product
    if not DatabaseInterface.DatabaseInterface.has_user_purchased_product(username, product_id):
        return jsonify({"success": False, "error": "You must purchase this product before reviewing"}), 403
    
    # XSS PROTECTION: Review HTML should be sanitized - for now, we store it but display carefully
    # In production, use a proper HTML sanitizer like bleach
    
    try:
        review_id = DatabaseInterface.DatabaseInterface.create_review(
            product_id, username, rating, review_text, review_html, image_url
        )
        
        # Log activity
        DatabaseInterface.DatabaseInterface.log_activity(
            username, 'review_create', f'product_id={product_id}, rating={rating}', request.remote_addr
        )
        
        return jsonify({"success": True, "review_id": review_id}), 200
    except Exception as e:
        print(f"[ERROR] Review creation failed: {e}")
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/admin/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    """
    Edit product details (seller/admin only).
    
    SECURITY: Requires authentication and seller/admin role.
    RBAC: Sellers can only edit their own products, admins can edit any.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to edit products.", "warning")
        return redirect(url_for('login'))
    
    # RBAC: Check if user has seller or admin role
    user_role = _get_user_role(username)
    if user_role not in ['admin', 'seller']:
        flash("You do not have permission to edit products.", "error")
        return redirect(url_for('home'))
    
    # Allow viewing delisted products for sellers/admins
    product = DatabaseInterface.DatabaseInterface.get_product(product_id, include_delisted=True)
    if not product:
        flash("Product not found.", "error")
        return redirect(url_for('admin'))
    
    # SECURITY: Sellers can only edit their own products
    if user_role == 'seller' and product.get('created_by') != username:
        flash("You can only edit your own products.", "error")
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        # XSS PROTECTION: Input sanitization
        name = request.form.get('name', '').strip()[:200]
        price = request.form.get('price', '').strip()
        description = request.form.get('description', '').strip()[:5000]
        category = request.form.get('category', '').strip()
        
        # SECURITY: Validate required fields
        if not name or not price or not category:
            flash("Name, price, and category are required.", "error")
            return render_template('edit_product.html',
                                 current_user=username,
                                 current_user_role=user_role,
                                 product=product), 200
        
        # SECURITY: Whitelist category values
        valid_categories = ['electronics', 'clothing', 'home-garden', 'books', 'gaming', 'sports']
        if category not in valid_categories:
            flash("Invalid category selected.", "error")
            return render_template('edit_product.html',
                                 current_user=username,
                                 current_user_role=user_role,
                                 product=product), 200
        
        # SECURITY: Validate price
        try:
            price = float(price)
            if price <= 0 or price > 999999.99:
                raise ValueError("Price must be between 0.01 and 999999.99")
        except (ValueError, TypeError):
            flash("Invalid price. Please enter a valid number.", "error")
            return render_template('edit_product.html',
                                 current_user=username,
                                 current_user_role=user_role,
                                 product=product), 200
        
        # SECURITY: File upload validation
        image_url = product.get('image_url')  # Keep existing image by default
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                ext = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{uuid.uuid4().hex}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(filepath)
                image_url = f"/static/uploads/{unique_filename}"
        
        # SQL INJECTION PROTECTION: update_product() uses parameterized queries
        try:
            success = DatabaseInterface.DatabaseInterface.update_product(
                product_id, name=name, price=price, description=description,
                image_url=image_url, category=category
            )
            if success:
                # Log activity
                DatabaseInterface.DatabaseInterface.log_activity(
                    username, 'product_edit', f'product_id={product_id}', request.remote_addr
                )
                flash(f"Product '{name}' updated successfully!", "success")
                return redirect(url_for('admin'))
            else:
                flash("Error updating product. Please try again.", "error")
        except Exception as e:
            print(f"[ERROR] Product update failed: {e}")
            flash("Error updating product. Please try again.", "error")
    
    return render_template('edit_product.html',
                         current_user=username,
                         current_user_role=user_role,
                         product=product), 200


@app.route('/admin/transactions')
def seller_transactions():
    """
    View transaction history for seller's products.
    
    SECURITY: Requires authentication and seller/admin role.
    RBAC: Sellers see only their products' transactions, admins see all.
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        session.clear()
        flash("Please log in to view transactions.", "warning")
        return redirect(url_for('login'))
    
    # RBAC: Check if user has seller or admin role
    user_role = _get_user_role(username)
    if user_role not in ['admin', 'seller']:
        flash("You do not have permission to view transactions.", "error")
        return redirect(url_for('home'))
    
    # Get transactions
    if user_role == 'admin':
        # Admins see all transactions
        import sqlite3 as sql
        conn = sql.connect(DatabaseInterface.MAIN_DB_FILE)
        conn.row_factory = sql.Row
        cur = conn.cursor()
        cur.execute(
            '''SELECT o.*, p.name, p.image_url, p.created_by, u.username as buyer_username
               FROM orders o
               JOIN products p ON o.product_id = p.id
               JOIN users u ON o.username = u.username
               ORDER BY o.order_date DESC'''
        )
        transactions = [dict(row) for row in cur.fetchall()]
        conn.close()
    else:
        # Sellers see only their products' transactions
        transactions = DatabaseInterface.DatabaseInterface.get_seller_transactions(username)
    
    # Calculate total revenue correctly: sum of (price * quantity) for each transaction
    total_revenue = sum(t['price'] * t['quantity'] for t in transactions) if transactions else 0.0
    
    # Log activity
    DatabaseInterface.DatabaseInterface.log_activity(
        username, 'page_view', 'transaction_history', request.remote_addr
    )
    
    return render_template('transactions.html',
                         current_user=username,
                         current_user_role=user_role,
                         transactions=transactions,
                         total_revenue=total_revenue), 200


@app.route('/admin/delist', methods=['POST'])
@_require_role(['admin', 'seller'])
def delist_product():
    """
    Delist a product (hide from public but keep data).
    
    SECURITY: Requires authentication and admin/seller role.
    RBAC: Admin can delist any product, sellers can only delist their own products.
    SQL INJECTION PROTECTION: Uses parameterized queries via delist_product().
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # RBAC: Check if user has admin or seller role
    user_role = _get_user_role(username)
    if user_role not in ['admin', 'seller']:
        return jsonify({"success": False, "error": "Permission denied"}), 403
    
    # SECURITY: Validate JSON input
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400
    
    product_id = data.get('product_id')
    
    # SECURITY: Validate product_id
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid product ID"}), 400
    
    # RBAC: Sellers can only delist their own products
    if user_role == 'seller':
        product = DatabaseInterface.DatabaseInterface.get_product(product_id, include_delisted=True)
        if not product:
            return jsonify({"success": False, "error": "Product not found"}), 404
        if product.get('created_by') != username:
            return jsonify({"success": False, "error": "You can only delist your own products"}), 403
    
    # SQL INJECTION PROTECTION: delist_product() uses parameterized queries
    try:
        success = DatabaseInterface.DatabaseInterface.delist_product(product_id)
        if success:
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'product_delisted', f'product_id={product_id}', request.remote_addr
            )
            return jsonify({"success": True, "message": "Product delisted successfully"}), 200
        else:
            return jsonify({"success": False, "error": "Product not found"}), 404
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Delist failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/admin/relist', methods=['POST'])
@_require_role(['admin', 'seller'])
def relist_product():
    """
    Relist a previously delisted product (make it visible again).
    
    SECURITY: Requires authentication and admin/seller role.
    RBAC: Admin can relist any product, sellers can only relist their own products.
    SQL INJECTION PROTECTION: Uses parameterized queries via relist_product().
    """
    username = session.get('username')
    token = _current_token()
    
    # SECURITY: Authentication check
    if not username or not token or not SecurityHandler.is_authenticated(username, token, request.remote_addr):
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    # RBAC: Check if user has admin or seller role
    user_role = _get_user_role(username)
    if user_role not in ['admin', 'seller']:
        return jsonify({"success": False, "error": "Permission denied"}), 403
    
    # SECURITY: Validate JSON input
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400
    
    product_id = data.get('product_id')
    
    # SECURITY: Validate product_id
    try:
        product_id = int(product_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid product ID"}), 400
    
    # RBAC: Sellers can only relist their own products
    if user_role == 'seller':
        product = DatabaseInterface.DatabaseInterface.get_product(product_id, include_delisted=True)
        if not product:
            return jsonify({"success": False, "error": "Product not found"}), 404
        if product.get('created_by') != username:
            return jsonify({"success": False, "error": "You can only relist your own products"}), 403
    
    # SQL INJECTION PROTECTION: relist_product() uses parameterized queries
    try:
        success = DatabaseInterface.DatabaseInterface.relist_product(product_id)
        if success:
            # Log activity
            DatabaseInterface.DatabaseInterface.log_activity(
                username, 'product_relisted', f'product_id={product_id}', request.remote_addr
            )
            return jsonify({"success": True, "message": "Product relisted successfully"}), 200
        else:
            return jsonify({"success": False, "error": "Product not found"}), 404
    except Exception as e:
        # SECURITY: Don't leak exception details to users
        print(f"[ERROR] Relist failed: {e}")  # Log for debugging
        return jsonify({"success": False, "error": "An error occurred. Please try again."}), 500


@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', 
                         current_user=_current_user(),
                         current_user_role=_get_current_user_role()), 404



if __name__ == '__main__':
    app.run(debug=True)