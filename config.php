<?php
// Configuration for PHP S3 Server

// Data storage directory
define('DATA_DIR', __DIR__ . '/data');

// Allowed access keys for authentication
// Add your access keys here - these are used as the "Access Key ID" in S3 clients
define('ALLOWED_ACCESS_KEYS', ['put_your_key_here']);

// Maximum request size (default: 100MB)
define('MAX_REQUEST_SIZE', 100 * 1024 * 1024);
