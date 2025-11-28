# Logging and Analytics Documentation

## Overview

The Amazoff platform implements comprehensive activity logging and analytics to track user behavior, system usage, and business metrics. This document outlines the types of data collected, methods used, and justifications for data collection.

## Data Collection Justification

### Purpose
The logging and analytics system serves multiple critical purposes:

1. **Security Monitoring**: Track suspicious activities, failed login attempts, and potential security threats
2. **Business Intelligence**: Understand user behavior, popular products, and sales patterns
3. **System Optimization**: Identify performance bottlenecks and user experience issues
4. **Compliance**: Maintain audit trails for financial transactions and user actions
5. **Customer Support**: Assist users by tracking their activity history

### Legal and Ethical Considerations
- All logged data is stored securely in the database
- User privacy is maintained - no sensitive personal information (passwords, payment details) is logged
- Activity logs are accessible only to administrators
- Users are informed about data collection through this documentation

## Types of Data Collected

### 1. Page Views
**What**: Records when users visit different pages on the platform
**Data Collected**:
- Username (if authenticated) or null (for anonymous users)
- Activity type: `page_view`
- Activity data: Page identifier (e.g., 'home', 'dashboard', 'order_history')
- IP address
- Timestamp

**Justification**: 
- Understand which pages are most popular
- Identify user navigation patterns
- Measure engagement with different sections
- Detect unusual access patterns (potential security issues)

**Example Log Entry**:
```
username: "john_doe"
activity_type: "page_view"
activity_data: "dashboard"
ip_address: "192.168.1.100"
timestamp: "2025-01-15 10:30:00"
```

### 2. Product Interactions
**What**: Tracks when users view, search for, or interact with products
**Data Collected**:
- Username (if authenticated)
- Activity type: `product_view`, `search`
- Activity data: Product ID, search query, etc.
- IP address
- Timestamp

**Justification**:
- Identify popular products and trends
- Improve search functionality based on query patterns
- Personalize recommendations
- Track product performance metrics

**Example Log Entry**:
```
username: "john_doe"
activity_type: "product_view"
activity_data: "product_id=123"
ip_address: "192.168.1.100"
timestamp: "2025-01-15 10:35:00"
```

### 3. Shopping Cart Activities
**What**: Monitors cart additions, updates, and removals
**Data Collected**:
- Username (required - cart operations require authentication)
- Activity type: `cart_add`, `cart_update`, `cart_remove`
- Activity data: Product ID, quantity, cart item ID
- IP address
- Timestamp

**Justification**:
- Understand shopping behavior and abandonment patterns
- Identify products frequently added but not purchased
- Optimize checkout flow
- Detect fraudulent activity (unusual cart patterns)

**Example Log Entry**:
```
username: "john_doe"
activity_type: "cart_add"
activity_data: "product_id=123, quantity=2"
ip_address: "192.168.1.100"
timestamp: "2025-01-15 10:40:00"
```

### 4. Purchase Transactions
**What**: Records completed purchases
**Data Collected**:
- Username (required)
- Activity type: `purchase`
- Activity data: Product ID, quantity, price
- IP address
- Timestamp

**Justification**:
- Financial audit trail
- Sales analytics and reporting
- Revenue tracking
- Fraud detection
- Customer purchase history

**Example Log Entry**:
```
username: "john_doe"
activity_type: "purchase"
activity_data: "product_id=123, quantity=2, price=29.99"
ip_address: "192.168.1.100"
timestamp: "2025-01-15 10:45:00"
```

### 5. Authentication Events
**What**: Tracks login attempts (successful and failed)
**Data Collected**:
- Username (attempted username)
- Activity type: `login`
- Activity data: 'success' or 'failed'
- IP address
- Timestamp

**Justification**:
- Security monitoring for brute force attacks
- Account security analysis
- Identify compromised accounts
- Audit trail for account access

**Example Log Entry**:
```
username: "john_doe"
activity_type: "login"
activity_data: "success"
ip_address: "192.168.1.100"
timestamp: "2025-01-15 10:00:00"
```

### 6. Review Activities
**What**: Tracks when users create or update product reviews
**Data Collected**:
- Username (required)
- Activity type: `review_create`
- Activity data: Product ID, rating
- IP address
- Timestamp

**Justification**:
- Monitor review quality and frequency
- Identify review manipulation attempts
- Track product satisfaction metrics
- Content moderation support

**Example Log Entry**:
```
username: "john_doe"
activity_type: "review_create"
activity_data: "product_id=123, rating=5"
ip_address: "192.168.1.100"
timestamp: "2025-01-15 11:00:00"
```

### 7. Product Management Activities
**What**: Tracks seller/admin actions on products
**Data Collected**:
- Username (seller/admin)
- Activity type: `product_edit`, `product_create`
- Activity data: Product ID
- IP address
- Timestamp

**Justification**:
- Audit trail for product changes
- Track seller activity
- Detect unauthorized modifications
- Support dispute resolution

## Data Collection Methods

### 1. Server-Side Logging
**Implementation**: Activity logging is performed server-side in the Flask application
**Location**: `main.py` and `DatabaseInterface.py`
**Method**: 
- Logging functions are called at key points in the application flow
- Data is stored in the `activity_logs` table in the database
- Uses parameterized queries to prevent SQL injection

**Code Example**:
```python
DatabaseInterface.DatabaseInterface.log_activity(
    username, 'purchase',
    f'product_id={product_id}, quantity={quantity}, price={price}',
    request.remote_addr
)
```

### 2. Database Storage
**Table**: `activity_logs`
**Schema**:
```sql
CREATE TABLE activity_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    activity_type TEXT NOT NULL,
    activity_data TEXT,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES users(username)
)
```

**Storage Considerations**:
- All logs are stored in SQLite database
- Indexed by timestamp for efficient querying
- Foreign key relationship to users table
- Can be archived/exported for long-term storage

### 3. View Count Tracking
**Implementation**: Product view counts are stored directly in the `products` table
**Method**: Incremented via `increment_product_views()` function
**Justification**: Provides real-time view statistics without querying logs

## Analytics Features

### 1. Seller Analytics
**What**: Sellers can view analytics for their own products
**Metrics Provided**:
- Total views across all products
- Total items in shopping carts
- Total sales (from orders)
- Per-product breakdown (views, in-cart quantities, sales)

**Location**: Admin/Seller Panel (`/admin`)

### 2. Admin Analytics
**What**: System-wide analytics for administrators
**Metrics Provided**:
- Total user count
- System-wide cart analytics
- All product listings with view counts
- Transaction history across all sellers

**Location**: Admin Panel (`/admin`)

### 3. Transaction History
**What**: Detailed transaction records
**Available To**:
- Sellers: See transactions for their products only
- Admins: See all transactions
- Buyers: See their own order history

**Location**: 
- Sellers/Admins: `/admin/transactions`
- Buyers: `/orders`

## Data Retention and Privacy

### Retention Policy
- Activity logs are retained indefinitely in the database
- Logs can be exported and archived for compliance purposes
- Old logs can be purged based on organizational policy

### Privacy Protection
- IP addresses are logged for security but can be anonymized
- No sensitive personal information (passwords, payment details) is logged
- Usernames are logged but can be pseudonymized if required
- Activity data contains only non-sensitive identifiers (product IDs, quantities)

### Access Control
- Only administrators can access activity logs
- Regular users cannot view their own activity logs (privacy consideration)
- Logs are not exposed through public APIs

## Security Considerations

### Protection Against Log Injection
- All log data uses parameterized database queries
- User input is sanitized before logging
- Activity data is stored as text, not executed code

### Log Integrity
- Logs are written immediately after actions occur
- Database transactions ensure log consistency
- Timestamps are generated server-side (not client-side)

### Monitoring and Alerting
- Failed login attempts are logged for security analysis
- Unusual activity patterns can be identified through log analysis
- IP addresses help identify potential security threats

## Future Enhancements

Potential improvements to the logging system:

1. **Log Aggregation**: Implement log rotation and archival
2. **Real-time Analytics**: Dashboard with live activity feeds
3. **Anomaly Detection**: Automated detection of suspicious patterns
4. **Export Functionality**: Allow administrators to export logs for analysis
5. **Privacy Controls**: Allow users to request their activity data (GDPR compliance)
6. **Performance Metrics**: Track page load times and API response times

## Conclusion

The logging and analytics system provides essential insights into platform usage, security, and business performance while maintaining user privacy and data security. All data collection is justified by legitimate business and security needs, and the system is designed to be transparent and compliant with privacy best practices.

