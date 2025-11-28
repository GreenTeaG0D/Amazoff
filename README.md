# Amazoff
Coursework for 6001 - Security (online shopping webapp)

## Requirements
- Python 3.x
- Flask
- SQLite3 (included with Python)

## Quick Start
```bash
python main.py
```
Then visit `http://localhost:5000`

**Demo Credentials:**
- Username: `user`
- Password: `pass`
- Role: Admin (full access to all features)

## Security Implementation
The webapp demonstrates secure design choices with custom implementations:
- **SHA-256 hashing** - Pure Python implementation for password hashing
- **Blowfish encryption** - CBC mode with PKCS#7 padding for data encryption
- **Session management** - Token-based authentication with IP binding, 30-minute timeout, and maximum 5 sessions per user
- **Database security** - Separate databases for user data and encryption keys
- **SQL Injection Protection** - All database queries use parameterized statements
- **XSS Protection** - Jinja2 auto-escaping and input sanitization throughout
- **File Upload Security** - Secure filename handling, file type whitelisting, and size limits
- **Role-Based Access Control (RBAC)** - Three-tier system (buyer, seller, admin) with route-level enforcement

**Note:** This is not production-ready; it serves as a vehicle to demonstrate security knowledge. External security vendors (e.g., OAuth) are not allowed, but implementing their algorithms is permitted with proper citations.

## Features Implemented

### User Features
- **Home Page** - Amazon-style layout with category navigation
- **User Registration** - Sign-up with SHA-256 password hashing (defaults to buyer role)
- **User Login** - Session-based authentication with modal popup support
- **User Dashboard** - Personalized dashboard for logged-in users
- **Product Browsing** - Category-based product listings (Electronics, Clothing, Home & Garden, Books, Gaming, Sports & Outdoors)
- **Product Detail Pages** - View detailed product information with reviews
- **Product Search** - Full-text search across product names and descriptions
- **Shopping Cart** - Add, update quantities, and remove items with real-time price calculations
- **Checkout & Purchase** - Complete purchase flow with order creation
- **Order History** - View all past purchases with order details
- **Product Reviews** - Leave reviews for purchased products with ratings, text formatting (HTML), and image uploads
- **View Counter** - Product view tracking visible to all users

### Seller Features
- **Product Creation** - Create new product listings with name, price, category, description, and image upload
- **Product Editing** - Edit details of existing products (name, price, description, category, image)
- **Seller Analytics** - View analytics for own products:
  - Total views across all products
  - Total items in shopping carts
  - Total sales revenue
  - Per-product breakdown (views, in-cart quantities, sales)
- **Transaction History** - View complete transaction history for all products sold

### Admin Features
- **All Seller Features** - Admins can create, edit, and manage products
- **User Management** - View all users, change roles (buyer ↔ seller), ban/unban users
- **System Analytics** - View total user count and system-wide cart analytics
- **Product Management** - View all products with IDs, edit any product, and delist products
- **Transaction History** - View all transactions across all sellers
- **User Search** - Search/filter users in the management panel

### Security Features
- **Account Banning** - Admins can ban users, which invalidates all sessions and prevents login
- **Session Limits** - Maximum 5 active sessions per user
- **Session Expiry** - Sessions expire after 30 minutes of inactivity
- **IP Binding** - Sessions are bound to IP addresses for additional security
- **Input Validation** - All user inputs are validated and sanitized
- **Redirect Protection** - Open redirect attacks prevented through URL validation

## Database Files
- `database.db` - User accounts, sessions, products, cart items, orders, reviews, activity logs
- `blowfish_material.db` - Encryption keys and IVs for Blowfish encryption

## Database Schema

### Main Tables
- `users` - User accounts with roles (buyer, seller, admin) and ban status
- `sessions` - Active user sessions with IP binding and timeout
- `products` - Product listings with view counts and seller tracking
- `cart_items` - Shopping cart items for each user
- `orders` - Completed purchase transactions
- `reviews` - Product reviews with ratings, HTML formatting, and images
- `activity_logs` - Comprehensive activity logging for analytics and security

## Logging and Analytics

The platform includes comprehensive activity logging to track:
- Page views and navigation patterns
- Product interactions and searches
- Shopping cart activities
- Purchase transactions
- Authentication events
- Review creation
- Product management activities

See `LOGGING_ANALYTICS.md` for detailed documentation on:
- Types of data collected
- Methods used for data collection
- Justification for data collection
- Privacy and security considerations

## File Structure
```
Amazoff/
├── main.py                 # Main Flask application
├── SecurityHandler.py      # Authentication and session management
├── DatabaseInterface.py    # Database operations (all parameterized queries)
├── BBCrypt.py             # SHA-256 and Blowfish implementations
├── hash_mix_constants.txt # SHA-256 constants
├── blowfish_constants.txt # Blowfish S-boxes and P-array
├── templates/             # Jinja2 HTML templates
│   ├── base.html         # Base template with navigation and login modal
│   ├── index.html        # Home page
│   ├── login.html        # Login page
│   ├── signup.html       # Registration page
│   ├── dashboard.html    # User dashboard
│   ├── listings.html     # Category product listings
│   ├── search.html       # Search results
│   ├── product_detail.html # Product detail page with reviews
│   ├── cart.html         # Shopping cart
│   ├── checkout.html     # Checkout page
│   ├── orders.html       # Order history
│   ├── admin.html        # Admin/Seller panel
│   ├── edit_product.html # Edit product form
│   ├── transactions.html # Transaction history
│   └── 404.html          # Error page
└── static/
    └── uploads/          # Product images (gitignored)
```

## Routes

### Public Routes
- `/`, `/home`, `/index` - Home page
- `/login` - Login page (GET/POST)
- `/signup` - Registration page (GET/POST)
- `/listings/<category>` - Product listings by category
- `/search/<query>` - Search products

### Authenticated Routes (All Roles)
- `/dashboard` - User dashboard
- `/cart` - Shopping cart
- `/cart/add` - Add item to cart (POST)
- `/cart/update` - Update cart quantity (POST)
- `/cart/remove` - Remove item from cart (POST)
- `/checkout` - Checkout page (GET/POST)
- `/orders` - Order history
- `/product/<product_id>` - Product detail page with reviews
- `/review/create` - Create or update product review (POST)

### Seller Routes
- `/admin` - Seller panel (product creation, analytics, and transaction history)
- `/admin/edit/<product_id>` - Edit product details (GET/POST)
- `/admin/transactions` - View transaction history for seller's products

### Admin Routes
- `/admin` - Admin panel (product creation, user management, analytics, transaction history)
- `/admin/edit/<product_id>` - Edit any product (GET/POST)
- `/admin/transactions` - View all transactions across all sellers
- `/admin/update_role` - Change user role (POST)
- `/admin/ban_user` - Ban/unban user (POST)
- `/admin/delist` - Delete product (POST)

## Role-Based Access Control (RBAC)

### Buyer
- Can view all products and categories
- Can add items to cart
- Can search products
- Cannot access admin panel
- Cannot create products

### Seller
- All buyer permissions
- Can create and edit product listings (own products only)
- Can view analytics for own products (including sales)
- Can view transaction history for own products
- Cannot view system-wide analytics
- Cannot manage users

### Admin
- All seller permissions
- Can create, edit, and delist any product
- Can view system-wide analytics
- Can view all transactions across all sellers
- Can manage users (change roles, ban/unban)
- Can view all products with IDs

## Code Reuse
Certain code within the HTML templates has been reused from a previous project (5005CMD), all code was still written by me and changes have been made where required.
No code to do with security has been reused.

## Documentation
- `LOGGING_ANALYTICS.md` - Comprehensive documentation on logging and analytics implementation, data collection methods, and privacy considerations

## External Sources
- Favicon: Generated using [favicon.io](https://favicon.io/favicon-generator/)
- Blowfish constants: S-boxes and P-array from [aluink/Blowfish](https://github.com/aluink/Blowfish/blob/master/constants.txt)
