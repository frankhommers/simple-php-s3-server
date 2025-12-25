# PHP S3 Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A lightweight S3-compatible object storage server implemented in PHP, using local filesystem as storage backend.

## Key Features

- ✅ S3 OBJECT API compatibility (PUT/GET/DELETE/POST)
- ✅ Multipart upload support
- ✅ No database required - pure filesystem storage
- ✅ Full AWS V4 signature authentication (including presigned URLs)
- ✅ Lightweight deployment (just 2 files)


## TLDR

Simply create a new website on your virtual host, place the `index.php` and `config.php` files from the GitHub repository into the website's root directory, modify the configuration in `config.php`, then configure the rewrite rule to set all routes to index.php, and you're ready to use it.

- **Endpoint**: Your website domain
- **Access Key**: Your configured access key
- **Secret Key**: Your configured secret key (used for signature verification)
- **Region**: Can be any value (e.g., `auto` or `us-east-1`)  

For example, if an object has:  
- `bucket="music"`  
- `key="hello.mp3"`  

It will be stored at: `./data/music/hello.mp3`  

You can also combine this with Cloudflare's CDN for faster and more stable performance.



## Quick Start

### Requirements

- PHP 8.0+
- Apache/Nginx (with mod_rewrite enabled)

### Installation

1. Set up a website

2. Download `index.php` and `config.php` to your website root directory

3. Create data directory  
Create a `data` folder in your website root directory

4. Configure URL rewriting (DirectAdmin example):  
Create `.htaccess` in root directory with:
```apache
<IfModule mod_rewrite.c>
    RewriteEngine On
    # If request is not for existing file/directory
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    # Redirect all requests to index.php
    RewriteRule ^(.*)$ index.php [L,QSA]
</IfModule>
```
> For other web servers, consult documentation on how to configure rewrite rules to redirect all requests to index.php

### Configuration

Edit `config.php`:
```php
// Debug mode - set to false in production
define('DEBUG', true);

// Data storage directory
define('DATA_DIR', __DIR__ . '/data');

// Access credentials (access_key => secret_key)
define('ACCESS_CREDENTIALS', [
    'your-access-key' => 'your-secret-key',
]);

// Maximum request size (default: 100MB)
define('MAX_REQUEST_SIZE', 100 * 1024 * 1024);
```

Use the same access key and secret key in your S3 client. Both are required for secure signature verification and presigned URL support.

### Start Using It!

#### Demo: Using with Minio Client

```python
oss_client = Minio("your-domain.com", access_key="your-access-key", secret_key="your-secret-key", secure=True)
```