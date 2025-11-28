"""
Authentication helpers that plug into DatabaseInterface + BBCrypt:
- login(username, password, requester_ip=None) → session token or error code
- logout(token) → invalidate session
- is_authenticated(username, token, requester_ip) → bool and token refresh
- hash_password / verify_password wrap BBCrypt primitives
"""

import secrets as random  # secrets provides cryptographically secure tokens
import sqlite3 as sql

from BBCrypt import sha256_hash, sha256_validate
import DatabaseInterface as DBI


def _log(event, **details):
    """Lightweight structured logging hook."""
    entries = ", ".join(f"{k}={v}" for k, v in details.items())
    print(f"[SECURITY] {event}: {entries}")


def _fetch_user(username):
    """Retrieve a user record from the main database."""
    with sql.connect(DBI.MAIN_DB_FILE) as conn:
        conn.row_factory = sql.Row
        cur = conn.cursor()
        # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
        cur.execute("SELECT username, password_hash, banned FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None


def login(username, password, requester_ip=None):
    """
    Attempt to authenticate a user and create a session.

    Returns:
        token (str): when successful
        -1 on bad username/password
        -2 when user exceeded active session quota
        -3 when user is banned
    """
    user = _fetch_user(username)
    if not user:
        _log("login_failed_no_user", username=username, ip=requester_ip)
        return -1

    # SECURITY: Check if user is banned before allowing login
    if user.get("banned", 0):
        _log("login_failed_banned", username=username, ip=requester_ip)
        return -3

    if not verify_password(user["password_hash"], password):
        _log("login_failed_bad_password", username=username, ip=requester_ip)
        return -1

    for _ in range(3):  # retry a couple times on random token collisions
        token = random.token_bytes(16).hex()
        result = DBI.DatabaseInterface.create_session(username, token, requester_ip)
        if result == "success":
            _log("login_success", username=username, token=token, ip=requester_ip)
            return token
        if result == "collision":
            _log("login_collision_retry", username=username)
            continue
        if result == "too many sessions":
            _log("login_failed_session_limit", username=username)
            return -2
        _log("login_unexpected_result", username=username, result=result)
        break

    return -1


def logout(token):
    """Invalidate the provided session token."""
    try:
        DBI.DatabaseInterface.invalidate_session(token)
        _log("logout_success", token=token)
        return True
    except Exception as exc:
        _log("logout_failure", token=token, error=exc)
        return False


def is_authenticated(username, token, requester_ip):
    """
    Confirm that the session token is valid, belongs to the user/IP, and is fresh.
    Refreshes the session's last_active timestamp on success.
    SECURITY: Also checks if user is banned and invalidates session if banned.
    """
    try:
        session = DBI.DatabaseInterface.get_session(username, token, requester_ip)
        if session and not DBI.DatabaseInterface.is_session_expired(session):
            # SECURITY: Check if user is banned - invalidate session if banned
            user = _fetch_user(username)
            if user and user.get("banned", 0):
                logout(token)
                _log("auth_failed_banned", username=username, token=token)
                return False
            
            DBI.DatabaseInterface.update_last_active(session)
            _log("auth_success", username=username, token=token)
            return True
        logout(token)
        _log("auth_failed", username=username, token=token)
        return False
    except Exception as exc:
        _log("auth_error", username=username, token=token, error=exc)
        return False


def hash_password(password):
    """Hash the password via BBCrypt's SHA-256 helper."""
    return sha256_hash(password)


def verify_password(stored_hash, password):
    """Compare the provided password with the stored hash."""
    if stored_hash is None:
        return False
    return sha256_validate(password, stored_hash)


def register(username, password):
    """
    Register a new user account.
    
    Returns:
        True if registration successful
        False if username already exists or invalid input
    """
    if not username or not password:
        _log("register_failed_invalid_input", username=username)
        return False
    
    if len(username) < 3 or len(username) > 50:
        _log("register_failed_username_length", username=username)
        return False
    
    # SECURITY: Password complexity validation is now handled in main.py
    # This function only checks minimum length for backward compatibility
    if len(password) < 8:
        _log("register_failed_password_length", username=username)
        return False
    
    # Check if username already exists
    existing = _fetch_user(username)
    if existing:
        _log("register_failed_username_exists", username=username)
        return False
    
    # Hash password and insert user
    password_hash = hash_password(password)
    try:
        with sql.connect(DBI.MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SECURITY: New users are created as 'buyer' role by default
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'buyer')", (username, password_hash))
            conn.commit()
        _log("register_success", username=username)
        return True
    except sql.IntegrityError:
        _log("register_failed_integrity", username=username)
        return False
    except Exception as exc:
        _log("register_error", username=username, error=exc)
        return False