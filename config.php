<?php
// Configuration for PHP S3 Server

// Debug mode - set to false in production
define('DEBUG', true);

// Data storage directory
define('DATA_DIR', __DIR__ . '/data');

// Access credentials for authentication
// Format: 'access_key_id' => 'secret_access_key'
// Both are required for secure signature verification
define('ACCESS_CREDENTIALS', [
    'put_your_access_key_here' => 'put_your_secret_key_here',
    // Add more key pairs as needed:
    // 'another_access_key' => 'another_secret_key',
]);

// Maximum request size (default: 100MB)
define('MAX_REQUEST_SIZE', 100 * 1024 * 1024);

// Presigned URL expiration override (in seconds)
// Can be a single value for all buckets, or per-bucket settings
// Values: 0 = use client expiration, -1 = never expire, >0 = override in seconds
// Examples: 3600 = 1 hour, 86400 = 1 day, 604800 = 1 week, 31536000 = 1 year
define('PRESIGNED_URL_EXPIRY', [
    '_default' => 0,           // Default for buckets not listed (0 = use client expiration)
    // 'shottr' => -1,         // Never expire for shottr bucket
    // 'private' => 3600,      // 1 hour for private bucket
]);
