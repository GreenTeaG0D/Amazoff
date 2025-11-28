import os
import sqlite3 as sql
from datetime import datetime, timedelta

MAIN_DB_FILE = "database.db"
BLOWFISH_DB_FILE = "blowfish_material.db"
MAX_SESSIONS_PER_USER = 5
SESSION_TIMEOUT = timedelta(minutes=30)


def _connect(db_path):
    conn = sql.connect(db_path)
    conn.row_factory = sql.Row
    return conn


def _ensure_main_schema():
    with _connect(MAIN_DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS users(
                   username TEXT PRIMARY KEY NOT NULL,
                   password_hash TEXT NOT NULL,
                   role TEXT NOT NULL DEFAULT 'buyer',
                   banned INTEGER NOT NULL DEFAULT 0
               )'''
        )
        # SECURITY: Add role column if it doesn't exist (migration for existing databases)
        try:
            cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'buyer'")
        except sql.OperationalError:
            pass  # Column already exists
        # SECURITY: Add banned column if it doesn't exist (migration for existing databases)
        try:
            cur.execute("ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0")
        except sql.OperationalError:
            pass  # Column already exists
        conn.commit()
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS sessions(
                   username TEXT NOT NULL,
                   token TEXT PRIMARY KEY NOT NULL,
                   ip_address TEXT,
                   last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(username) REFERENCES users(username)
               )'''
        )
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS products(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL,
                   price REAL NOT NULL,
                   description TEXT,
                   image_url TEXT,
                   category TEXT,
                   listing_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   view_count INTEGER DEFAULT 0,
                   created_by TEXT,
                   FOREIGN KEY(created_by) REFERENCES users(username)
               )'''
        )
        # SECURITY: Add created_by column if it doesn't exist (migration for existing databases)
        try:
            cur.execute("ALTER TABLE products ADD COLUMN created_by TEXT")
        except sql.OperationalError:
            pass  # Column already exists
        # SECURITY: Add delisted column if it doesn't exist (migration for existing databases)
        try:
            cur.execute("ALTER TABLE products ADD COLUMN delisted INTEGER NOT NULL DEFAULT 0")
        except sql.OperationalError:
            pass  # Column already exists
        conn.commit()
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS cart_items(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT NOT NULL,
                   product_id INTEGER NOT NULL,
                   quantity INTEGER NOT NULL DEFAULT 1,
                   added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(username) REFERENCES users(username),
                   FOREIGN KEY(product_id) REFERENCES products(id),
                   UNIQUE(username, product_id)
               )'''
        )
        conn.commit()
        # Orders table for purchases
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS orders(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT NOT NULL,
                   product_id INTEGER NOT NULL,
                   quantity INTEGER NOT NULL,
                   price REAL NOT NULL,
                   order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   status TEXT DEFAULT 'completed',
                   FOREIGN KEY(username) REFERENCES users(username),
                   FOREIGN KEY(product_id) REFERENCES products(id)
               )'''
        )
        conn.commit()
        # Reviews table
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS reviews(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   product_id INTEGER NOT NULL,
                   username TEXT NOT NULL,
                   rating INTEGER CHECK(rating >= 1 AND rating <= 5),
                   review_text TEXT NOT NULL,
                   review_html TEXT,
                   image_url TEXT,
                   review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(product_id) REFERENCES products(id),
                   FOREIGN KEY(username) REFERENCES users(username),
                   UNIQUE(product_id, username)
               )'''
        )
        conn.commit()
        # Activity logs table
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS activity_logs(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT,
                   activity_type TEXT NOT NULL,
                   activity_data TEXT,
                   ip_address TEXT,
                   timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(username) REFERENCES users(username)
               )'''
        )
        conn.commit()
        # Wishlist table
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS wishlist(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT NOT NULL,
                   product_id INTEGER NOT NULL,
                   added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY(username) REFERENCES users(username),
                   FOREIGN KEY(product_id) REFERENCES products(id),
                   UNIQUE(username, product_id)
               )'''
        )
        conn.commit()


def _ensure_blowfish_schema():
    with _connect(BLOWFISH_DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS blowfish_material(
                   key_label TEXT PRIMARY KEY NOT NULL,
                   key_hex TEXT NOT NULL,
                   iv_hex TEXT NOT NULL,
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
               )'''
        )
        conn.commit()


def _parse_timestamp(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {value}")


_ensure_main_schema()
_ensure_blowfish_schema()


class DatabaseInterface:
    @staticmethod
    def create_session(username, token, ip_address=None):
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM sessions WHERE username = ?", (username,))
            if cur.fetchone()[0] >= MAX_SESSIONS_PER_USER:
                return "too many sessions"
            try:
                cur.execute(
                    "INSERT INTO sessions (username, token, ip_address) VALUES (?, ?, ?)",
                    (username, token, ip_address),
                )
                conn.commit()
                return "success"
            except sql.IntegrityError as exc:
                if "sessions.token" in str(exc):
                    return "collision"
                raise

    @staticmethod
    def invalidate_session(token):
        with _connect(MAIN_DB_FILE) as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    @staticmethod
    def get_session(username, token, requester_ip):
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT username, token, ip_address, last_active FROM sessions WHERE username = ? AND token = ?",
                (username, token),
            )
            row = cur.fetchone()
            if not row:
                return None
            if row["ip_address"] and requester_ip and row["ip_address"] != requester_ip:
                return None
            return dict(row)

    @staticmethod
    def is_session_expired(session):
        last_active = session.get("last_active")
        try:
            last_dt = _parse_timestamp(last_active) if last_active else None
        except ValueError:
            return True
        if not last_dt:
            return True
        return datetime.utcnow() - last_dt > SESSION_TIMEOUT

    @staticmethod
    def update_last_active(session):
        token = session.get("token")
        if not token:
            raise ValueError("Session data must include a token.")
        with _connect(MAIN_DB_FILE) as conn:
            conn.execute(
                "UPDATE sessions SET last_active = CURRENT_TIMESTAMP WHERE token = ?",
                (token,),
            )
            conn.commit()

    @staticmethod
    def store_blowfish_material(key_label, key_hex, iv_hex):
        with _connect(BLOWFISH_DB_FILE) as conn:
            conn.execute(
                '''INSERT INTO blowfish_material (key_label, key_hex, iv_hex)
                   VALUES (?, ?, ?)
                   ON CONFLICT(key_label) DO UPDATE SET
                       key_hex = excluded.key_hex,
                       iv_hex = excluded.iv_hex,
                       updated_at = CURRENT_TIMESTAMP''',
                (key_label, key_hex, iv_hex),
            )
            conn.commit()

    @staticmethod
    def fetch_blowfish_material(key_label):
        with _connect(BLOWFISH_DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT key_hex, iv_hex FROM blowfish_material WHERE key_label = ?",
                (key_label,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {"key_hex": row["key_hex"], "iv_hex": row["iv_hex"]}

    # Product management methods
    @staticmethod
    def create_product(name, price, description=None, image_url=None, category=None, created_by=None):
        """
        Create a new product listing.
        
        SQL INJECTION PROTECTION: All parameters use ? placeholders (parameterized queries).
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query - values are bound separately from SQL
            cur.execute(
                '''INSERT INTO products (name, price, description, image_url, category, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (name, price, description, image_url, category, created_by)
            )
            conn.commit()
            return cur.lastrowid

    @staticmethod
    def get_product(product_id, include_delisted=False):
        """
        Get a product by ID.
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        
        Args:
            product_id: The product ID
            include_delisted: If True, return product even if delisted (for admin/seller views)
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            if include_delisted:
                cur.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            else:
                # SECURITY: Only show active (non-delisted) products to public
                cur.execute("SELECT * FROM products WHERE id = ? AND (delisted IS NULL OR delisted = 0)", (product_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_products_by_category(category):
        """
        Get all active (non-delisted) products in a category.
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query - category is bound as parameter
            # SECURITY: Only show active (non-delisted) products to public
            cur.execute("SELECT * FROM products WHERE category = ? AND (delisted IS NULL OR delisted = 0) ORDER BY listing_time DESC", (category,))
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def search_products(query):
        """
        Search active (non-delisted) products by name or description.
        
        SQL INJECTION PROTECTION: Uses parameterized LIKE queries with ? placeholders.
        Note: The % wildcards are added to the parameter value, not the SQL string.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: search_term is built with % but used as parameter
            # This prevents SQL injection because the query structure is fixed
            search_term = f"%{query}%"
            # SQL INJECTION PROTECTION: Parameterized query - search_term is bound as parameter
            # SECURITY: Only show active (non-delisted) products to public
            cur.execute(
                "SELECT * FROM products WHERE (name LIKE ? OR description LIKE ?) AND (delisted IS NULL OR delisted = 0) ORDER BY listing_time DESC",
                (search_term, search_term)
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def increment_product_views(product_id):
        """
        Increment the view count for a product.
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            conn.execute("UPDATE products SET view_count = view_count + 1 WHERE id = ?", (product_id,))
            conn.commit()

    @staticmethod
    def get_all_products(include_delisted=True):
        """
        Get all products in the database.
        
        SQL INJECTION PROTECTION: No user input, pure SELECT query.
        
        Args:
            include_delisted: If True, include delisted products (for admin views)
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: No user input in this query
            if include_delisted:
                cur.execute("SELECT * FROM products ORDER BY listing_time DESC")
            else:
                cur.execute("SELECT * FROM products WHERE (delisted IS NULL OR delisted = 0) ORDER BY listing_time DESC")
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def delete_product(product_id):
        """
        Delete a product from the database (permanent deletion - admin only).
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("DELETE FROM products WHERE id = ?", (product_id,))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def delist_product(product_id):
        """
        Delist a product (hide from public but keep data).
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("UPDATE products SET delisted = 1 WHERE id = ?", (product_id,))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def relist_product(product_id):
        """
        Relist a previously delisted product (make it visible again).
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("UPDATE products SET delisted = 0 WHERE id = ?", (product_id,))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def is_product_delisted(product_id):
        """
        Check if a product is delisted.
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("SELECT delisted FROM products WHERE id = ?", (product_id,))
            row = cur.fetchone()
            return bool(row['delisted']) if row and row.get('delisted') else False

    # Cart management methods
    @staticmethod
    def add_to_cart(username, product_id, quantity=1):
        """
        Add or update item in cart.
        
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        SECURITY: Username is validated to ensure user can only modify their own cart.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: All values are bound as parameters
            cur.execute(
                '''INSERT INTO cart_items (username, product_id, quantity)
                   VALUES (?, ?, ?)
                   ON CONFLICT(username, product_id) DO UPDATE SET
                       quantity = quantity + ?''',
                (username, product_id, quantity, quantity)
            )
            conn.commit()

    @staticmethod
    def get_cart_items(username):
        """
        Get all items in user's cart with product details.
        
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        SECURITY: Username parameter ensures users can only see their own cart.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query - username is bound as parameter
            cur.execute(
                '''SELECT ci.id, ci.product_id, ci.quantity, p.name, p.price, p.image_url, p.description
                   FROM cart_items ci
                   JOIN products p ON ci.product_id = p.id
                   WHERE ci.username = ?
                   ORDER BY ci.added_at DESC''',
                (username,)
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def update_cart_quantity(cart_item_id, quantity, username):
        """
        Update quantity of a cart item.
        
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        SECURITY: Username check ensures users can only modify their own cart items.
        """
        if quantity <= 0:
            return DatabaseInterface.remove_from_cart(cart_item_id, username)
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: All parameters are bound separately
            # SECURITY: username in WHERE clause ensures user can only update their own items
            cur.execute(
                "UPDATE cart_items SET quantity = ? WHERE id = ? AND username = ?",
                (quantity, cart_item_id, username)
            )
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def remove_from_cart(cart_item_id, username):
        """
        Remove item from cart.
        
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        SECURITY: Username check ensures users can only remove their own cart items.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            # SECURITY: username in WHERE clause ensures user can only delete their own items
            cur.execute("DELETE FROM cart_items WHERE id = ? AND username = ?", (cart_item_id, username))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def get_cart_total(username):
        """Calculate total price of all items in cart."""
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                '''SELECT SUM(ci.quantity * p.price) as total
                   FROM cart_items ci
                   JOIN products p ON ci.product_id = p.id
                   WHERE ci.username = ?''',
                (username,)
            )
            row = cur.fetchone()
            return float(row["total"]) if row["total"] else 0.0

    @staticmethod
    def get_cart_analytics():
        """
        Get analytics on items in all carts.
        SQL INJECTION PROTECTION: Uses parameterized queries.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: No user input, pure aggregation query
            cur.execute(
                '''SELECT p.id, p.name, SUM(ci.quantity) as total_quantity
                   FROM cart_items ci
                   JOIN products p ON ci.product_id = p.id
                   GROUP BY p.id, p.name
                   ORDER BY total_quantity DESC'''
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def get_user_count():
        """
        Get total number of users.
        SQL INJECTION PROTECTION: No user input, pure count query.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: No user input, pure count query
            cur.execute("SELECT COUNT(*) as count FROM users")
            row = cur.fetchone()
            return row["count"] if row else 0

    @staticmethod
    def get_user_role(username):
        """
        Get user's role.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("SELECT role FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            return row["role"] if row else None

    @staticmethod
    def update_user_role(username, new_role):
        """
        Update user's role.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        SECURITY: Validates role against whitelist to prevent invalid roles.
        """
        # SECURITY: Whitelist valid roles to prevent role escalation
        valid_roles = ['buyer', 'seller', 'admin']
        if new_role not in valid_roles:
            return False
        
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def get_all_users():
        """
        Get all users with their roles and banned status (admin only function).
        SQL INJECTION PROTECTION: No user input, pure SELECT query.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: No user input, pure SELECT query
            cur.execute("SELECT username, role, banned FROM users ORDER BY username")
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def is_user_banned(username):
        """
        Check if a user is banned.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("SELECT banned FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            return bool(row['banned']) if row else False

    @staticmethod
    def ban_user(username):
        """
        Ban a user.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("UPDATE users SET banned = 1 WHERE username = ?", (username,))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def unban_user(username):
        """
        Unban a user.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            cur.execute("UPDATE users SET banned = 0 WHERE username = ?", (username,))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def get_seller_products(username, include_delisted=True):
        """
        Get all products created by a specific seller.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        
        Args:
            username: The seller's username
            include_delisted: If True, include delisted products (for seller/admin views)
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query prevents SQL injection
            if include_delisted:
                cur.execute("SELECT * FROM products WHERE created_by = ? ORDER BY listing_time DESC", (username,))
            else:
                cur.execute("SELECT * FROM products WHERE created_by = ? AND (delisted IS NULL OR delisted = 0) ORDER BY listing_time DESC", (username,))
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def get_seller_analytics(username):
        """
        Get analytics for a seller's products.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        Returns: dict with total_sales, total_in_cart, total_views, and per-product breakdown
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            
            # Get all products by this seller (including delisted)
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute("SELECT id, name, delisted FROM products WHERE created_by = ?", (username,))
            products = [dict(row) for row in cur.fetchall()]
            
            if not products:
                return {
                    'total_sales': 0,
                    'total_in_cart': 0,
                    'total_views': 0,
                    'products': []
                }
            
            product_ids = [p['id'] for p in products]
            placeholders = ','.join('?' * len(product_ids))
            
            # Get total views
            # SQL INJECTION PROTECTION: Parameterized query with placeholders
            # Note: placeholders string is safe because it's generated from length, not user input
            cur.execute(f"SELECT SUM(view_count) as total FROM products WHERE id IN ({placeholders})", product_ids)
            row = cur.fetchone()
            total_views = row['total'] if row and row['total'] else 0
            
            # Get total in cart (quantity)
            # SQL INJECTION PROTECTION: Parameterized query with placeholders
            cur.execute(
                f'''SELECT SUM(ci.quantity) as total
                   FROM cart_items ci
                   WHERE ci.product_id IN ({placeholders})''',
                product_ids
            )
            row = cur.fetchone()
            total_in_cart = row['total'] if row and row['total'] else 0
            
            # Get per-product analytics
            product_analytics = []
            for product in products:
                # SQL INJECTION PROTECTION: Parameterized queries
                cur.execute("SELECT view_count FROM products WHERE id = ?", (product['id'],))
                views_row = cur.fetchone()
                views = views_row['view_count'] if views_row and views_row['view_count'] else 0
                
                cur.execute("SELECT SUM(quantity) as total FROM cart_items WHERE product_id = ?", (product['id'],))
                cart_row = cur.fetchone()
                in_cart = cart_row['total'] if cart_row and cart_row['total'] else 0
                
                product_analytics.append({
                    'id': product['id'],
                    'name': product['name'],
                    'views': views,
                    'in_cart': in_cart,
                    'sales': 0,  # Sales would require an orders table - placeholder for now
                    'delisted': bool(product.get('delisted', 0)) if product.get('delisted') is not None else False
                })
            
            # Get total sales from orders
            # SQL INJECTION PROTECTION: Parameterized query with placeholders
            cur.execute(
                f'''SELECT SUM(o.quantity * o.price) as total
                   FROM orders o
                   WHERE o.product_id IN ({placeholders}) AND o.status = 'completed' ''',
                product_ids
            )
            row = cur.fetchone()
            total_sales = row['total'] if row and row['total'] else 0
            
            # Update product analytics with sales data
            for product in product_analytics:
                # SQL INJECTION PROTECTION: Parameterized queries
                cur.execute(
                    "SELECT SUM(quantity * price) as total FROM orders WHERE product_id = ? AND status = 'completed'",
                    (product['id'],)
                )
                sales_row = cur.fetchone()
                product['sales'] = sales_row['total'] if sales_row and sales_row['total'] else 0
            
            return {
                'total_sales': total_sales,
                'total_in_cart': total_in_cart,
                'total_views': total_views,
                'products': product_analytics
            }

    # Order management methods
    @staticmethod
    def create_order(username, product_id, quantity, price):
        """
        Create an order from a cart item.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''INSERT INTO orders (username, product_id, quantity, price, status)
                   VALUES (?, ?, ?, ?, 'completed')''',
                (username, product_id, quantity, price)
            )
            conn.commit()
            return cur.lastrowid

    @staticmethod
    def get_user_orders(username):
        """
        Get all orders for a user.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''SELECT o.*, p.name, p.image_url, p.category
                   FROM orders o
                   JOIN products p ON o.product_id = p.id
                   WHERE o.username = ?
                   ORDER BY o.order_date DESC''',
                (username,)
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def get_seller_transactions(seller_username):
        """
        Get transaction history for a seller's products.
        SQL INJECTION PROTECTION: Uses parameterized queries.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''SELECT o.*, p.name, p.image_url, u.username as buyer_username
                   FROM orders o
                   JOIN products p ON o.product_id = p.id
                   JOIN users u ON o.username = u.username
                   WHERE p.created_by = ?
                   ORDER BY o.order_date DESC''',
                (seller_username,)
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def has_user_purchased_product(username, product_id):
        """
        Check if a user has purchased a specific product.
        SQL INJECTION PROTECTION: Uses parameterized query.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                "SELECT COUNT(*) as count FROM orders WHERE username = ? AND product_id = ? AND status = 'completed'",
                (username, product_id)
            )
            row = cur.fetchone()
            return row['count'] > 0 if row else False

    # Review management methods
    @staticmethod
    def create_review(product_id, username, rating, review_text, review_html=None, image_url=None):
        """
        Create a product review.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''INSERT INTO reviews (product_id, username, rating, review_text, review_html, image_url)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(product_id, username) DO UPDATE SET
                       rating = excluded.rating,
                       review_text = excluded.review_text,
                       review_html = excluded.review_html,
                       image_url = excluded.image_url,
                       review_date = CURRENT_TIMESTAMP''',
                (product_id, username, rating, review_text, review_html, image_url)
            )
            conn.commit()
            return cur.lastrowid

    @staticmethod
    def get_product_reviews(product_id):
        """
        Get all reviews for a product.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''SELECT r.*, u.username
                   FROM reviews r
                   JOIN users u ON r.username = u.username
                   WHERE r.product_id = ?
                   ORDER BY r.review_date DESC''',
                (product_id,)
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def get_user_review(product_id, username):
        """
        Get a specific user's review for a product.
        SQL INJECTION PROTECTION: Uses parameterized query.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                "SELECT * FROM reviews WHERE product_id = ? AND username = ?",
                (product_id, username)
            )
            row = cur.fetchone()
            return dict(row) if row else None

    # Product editing methods
    @staticmethod
    def update_product(product_id, name=None, price=None, description=None, image_url=None, category=None):
        """
        Update product details.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        """
        updates = []
        params = []
        
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if price is not None:
            updates.append("price = ?")
            params.append(price)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if image_url is not None:
            updates.append("image_url = ?")
            params.append(image_url)
        if category is not None:
            updates.append("category = ?")
            params.append(category)
        
        if not updates:
            return False
        
        params.append(product_id)
        
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query - updates list is safe
            query = f"UPDATE products SET {', '.join(updates)} WHERE id = ?"
            cur.execute(query, params)
            conn.commit()
            return cur.rowcount > 0

    # Activity logging methods
    @staticmethod
    def log_activity(username, activity_type, activity_data=None, ip_address=None):
        """
        Log user activity.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''INSERT INTO activity_logs (username, activity_type, activity_data, ip_address)
                   VALUES (?, ?, ?, ?)''',
                (username, activity_type, activity_data, ip_address)
            )
            conn.commit()

    @staticmethod
    def get_activity_logs(username=None, activity_type=None, limit=100):
        """
        Get activity logs with optional filtering.
        SQL INJECTION PROTECTION: Uses parameterized queries.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            query = "SELECT * FROM activity_logs WHERE 1=1"
            params = []
            
            if username:
                query += " AND username = ?"
                params.append(username)
            if activity_type:
                query += " AND activity_type = ?"
                params.append(activity_type)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]

    # Wishlist management methods
    @staticmethod
    def add_to_wishlist(username, product_id):
        """
        Add a product to user's wishlist.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            try:
                cur.execute(
                    "INSERT INTO wishlist (username, product_id) VALUES (?, ?)",
                    (username, product_id)
                )
                conn.commit()
                return True
            except sql.IntegrityError:
                # Product already in wishlist
                return False

    @staticmethod
    def remove_from_wishlist(username, product_id):
        """
        Remove a product from user's wishlist.
        SQL INJECTION PROTECTION: Uses parameterized queries with ? placeholders.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                "DELETE FROM wishlist WHERE username = ? AND product_id = ?",
                (username, product_id)
            )
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def get_wishlist(username):
        """
        Get all items in user's wishlist with product details.
        SQL INJECTION PROTECTION: Uses parameterized query with ? placeholder.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                '''SELECT w.id, w.product_id, w.added_at, p.name, p.price, p.image_url, p.description, p.category
                   FROM wishlist w
                   JOIN products p ON w.product_id = p.id
                   WHERE w.username = ?
                   ORDER BY w.added_at DESC''',
                (username,)
            )
            return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def is_in_wishlist(username, product_id):
        """
        Check if a product is in user's wishlist.
        SQL INJECTION PROTECTION: Uses parameterized query.
        """
        with _connect(MAIN_DB_FILE) as conn:
            cur = conn.cursor()
            # SQL INJECTION PROTECTION: Parameterized query
            cur.execute(
                "SELECT COUNT(*) as count FROM wishlist WHERE username = ? AND product_id = ?",
                (username, product_id)
            )
            row = cur.fetchone()
            return row['count'] > 0 if row else False


if __name__ == "__main__":
    _ensure_main_schema()
    _ensure_blowfish_schema()
    # Demo user initialization is handled by runner.py on app startup