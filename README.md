# PHP S3 Server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A lightweight S3-compatible object storage server implemented in PHP, using local filesystem as storage backend.

## Key Features

- ✅ S3 OBJECT API compatibility (PUT/GET/DELETE/POST)
- ✅ Multipart upload support
- ✅ No database required - pure filesystem storage
- ✅ Simple AWS V4 signature authentication
- ✅ Lightweight single-file deployment


## TLDR

Simply create a new website on your virtual host, place the `index.php` file from the GitHub repository into the website's root directory, modify the password configuration at the beginning of `index.php`, then config the rewite rule set all route to index.php, and you're ready to use it.

- **Endpoint**: Your website domain  
- **Access Key**: The password you configured  
- **Secret Key**: Can be any value (not used in this project)  
- **Region**: Can be any value (not used in this project)  

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

2. Download `index.php` to your website root directory

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

Edit the top section of `index.php`:
```php
define('ALLOWED_ACCESS_KEYS', ['your-access-key-here']);  
// Allowed access keys - when using third-party OSS tools, only the access-key is required.
// Other fields like region and secret-key can be arbitrary values.
```

### Start Using It!

#### Demo: Using in Minio

```python
oss_client = Minio("your-domain.com", access_key="your-access-key-here", secret_key="*", secure=True)

```