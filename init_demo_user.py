"""
Initialize the demo user account.
Run this script to ensure the demo user (username: user, password: pass) exists.
"""
import DatabaseInterface
from BBCrypt import sha256_hash

def init_demo_user():
    """Create or update the demo user account."""
    demo_username = "user"
    demo_password = "pass"
    demo_hash = sha256_hash(demo_password)
    
    import sqlite3 as sql
    conn = sql.connect(DatabaseInterface.MAIN_DB_FILE)
    cur = conn.cursor()
    
    # Check if user exists
    cur.execute("SELECT username FROM users WHERE username = ?", (demo_username,))
    if cur.fetchone() is None:
        # Insert demo user
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                   (demo_username, demo_hash))
        conn.commit()
        print(f"✓ Created demo user: {demo_username}")
    else:
        # Update password hash
        cur.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                   (demo_hash, demo_username))
        conn.commit()
        print(f"✓ Updated demo user: {demo_username}")
    
    conn.close()
    print(f"Demo credentials: username='{demo_username}', password='{demo_password}'")

if __name__ == "__main__":
    init_demo_user()

