<?php
// Minimal S3-like PHP server

// Load configuration
require_once __DIR__ . '/config.php';

// Error reporting based on DEBUG setting
if (defined('DEBUG') && DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    // Log all requests to local file for debugging
    file_put_contents(__DIR__ . '/debug.log', date('Y-m-d H:i:s') . " {$_SERVER['REQUEST_METHOD']} {$_SERVER['REQUEST_URI']}\n", FILE_APPEND);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

// S3 XML namespace (can be overridden in config.php if needed)
if (!defined('S3_XML_NS')) {
    define('S3_XML_NS', 'http://s3.amazonaws.com/doc/2006-03-01/');
}

// AWS Signature V4 Authentication Functions

function get_signing_key($secret_key, $date_stamp, $region, $service) {
    $k_date = hash_hmac('sha256', $date_stamp, 'AWS4' . $secret_key, true);
    $k_region = hash_hmac('sha256', $region, $k_date, true);
    $k_service = hash_hmac('sha256', $service, $k_region, true);
    $k_signing = hash_hmac('sha256', 'aws4_request', $k_service, true);
    return $k_signing;
}

function get_canonical_uri($uri) {
    $path = parse_url($uri, PHP_URL_PATH);
    // Normalize the path
    $segments = explode('/', $path);
    $normalized = array_map('rawurlencode', array_map('rawurldecode', $segments));
    return implode('/', $normalized);
}

function get_canonical_query_string($exclude_signature = true) {
    $params = $_GET;
    if ($exclude_signature) {
        unset($params['X-Amz-Signature']);
    }
    ksort($params);
    $canonical = [];
    foreach ($params as $key => $value) {
        $canonical[] = rawurlencode($key) . '=' . rawurlencode($value);
    }
    return implode('&', $canonical);
}

function get_canonical_headers($signed_headers_list) {
    $headers = [];
    foreach ($signed_headers_list as $header_name) {
        $header_name = strtolower(trim($header_name));
        if ($header_name === 'host') {
            $headers[$header_name] = strtolower($_SERVER['HTTP_HOST']);
        } else {
            $server_key = 'HTTP_' . strtoupper(str_replace('-', '_', $header_name));
            if (isset($_SERVER[$server_key])) {
                $headers[$header_name] = trim($_SERVER[$server_key]);
            } elseif ($header_name === 'content-type' && isset($_SERVER['CONTENT_TYPE'])) {
                $headers[$header_name] = trim($_SERVER['CONTENT_TYPE']);
            } elseif ($header_name === 'content-length' && isset($_SERVER['CONTENT_LENGTH'])) {
                $headers[$header_name] = trim($_SERVER['CONTENT_LENGTH']);
            }
        }
    }
    ksort($headers);
    $canonical = '';
    foreach ($headers as $name => $value) {
        $canonical .= $name . ':' . $value . "\n";
    }
    return $canonical;
}

function verify_presigned_url() {
    // Check required parameters
    $required = ['X-Amz-Algorithm', 'X-Amz-Credential', 'X-Amz-Date', 'X-Amz-Expires', 'X-Amz-SignedHeaders', 'X-Amz-Signature'];
    foreach ($required as $param) {
        if (!isset($_GET[$param])) {
            return false;
        }
    }

    // Parse credential
    $credential_parts = explode('/', $_GET['X-Amz-Credential']);
    if (count($credential_parts) < 5) {
        return false;
    }
    $access_key = $credential_parts[0];
    $date_stamp = $credential_parts[1];
    $region = $credential_parts[2];
    $service = $credential_parts[3];

    // Check if access key exists
    if (!isset(ACCESS_CREDENTIALS[$access_key])) {
        return false;
    }
    $secret_key = ACCESS_CREDENTIALS[$access_key];

    // Check expiration
    $amz_date = $_GET['X-Amz-Date'];
    $expires = (int)$_GET['X-Amz-Expires'];
    $request_time = \DateTime::createFromFormat('Ymd\THis\Z', $amz_date, new \DateTimeZone('UTC'));
    if (!$request_time) {
        return false;
    }

    // Get bucket name from URI for per-bucket expiration settings
    $uri_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $path_parts = explode('/', trim($uri_path, '/'));
    $bucket = $path_parts[0] ?? '';

    // Get expiration override for this bucket
    $override = 0;
    if (defined('PRESIGNED_URL_EXPIRY')) {
        $expiry_config = PRESIGNED_URL_EXPIRY;
        if (isset($expiry_config[$bucket])) {
            $override = $expiry_config[$bucket];
        } elseif (isset($expiry_config['_default'])) {
            $override = $expiry_config['_default'];
        }
    }

    // Apply expiration check
    if ($override === -1) {
        // Never expire
    } elseif ($override > 0) {
        // Use override value
        $expiry_time = $request_time->getTimestamp() + $override;
        if (time() > $expiry_time) {
            generate_s3_error_response('ExpiredToken', 'Request has expired', 403);
        }
    } else {
        // Use client-provided expiration
        $expiry_time = $request_time->getTimestamp() + $expires;
        if (time() > $expiry_time) {
            generate_s3_error_response('ExpiredToken', 'Request has expired', 403);
        }
    }

    // Build canonical request
    $method = $_SERVER['REQUEST_METHOD'];
    $canonical_uri = get_canonical_uri($_SERVER['REQUEST_URI']);
    $canonical_query_string = get_canonical_query_string(true);
    $signed_headers = explode(';', strtolower($_GET['X-Amz-SignedHeaders']));
    $canonical_headers = get_canonical_headers($signed_headers);
    $signed_headers_str = implode(';', $signed_headers);
    $payload_hash = 'UNSIGNED-PAYLOAD';

    $canonical_request = $method . "\n" .
        $canonical_uri . "\n" .
        $canonical_query_string . "\n" .
        $canonical_headers . "\n" .
        $signed_headers_str . "\n" .
        $payload_hash;

    // Build string to sign
    $algorithm = 'AWS4-HMAC-SHA256';
    $credential_scope = $date_stamp . '/' . $region . '/' . $service . '/aws4_request';
    $string_to_sign = $algorithm . "\n" .
        $amz_date . "\n" .
        $credential_scope . "\n" .
        hash('sha256', $canonical_request);

    // Calculate signature
    $signing_key = get_signing_key($secret_key, $date_stamp, $region, $service);
    $calculated_signature = hash_hmac('sha256', $string_to_sign, $signing_key);

    // Compare signatures
    return hash_equals($calculated_signature, $_GET['X-Amz-Signature']);
}

function verify_authorization_header() {
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/AWS4-HMAC-SHA256\s+Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=(.+)/', $authorization, $matches)) {
        return false;
    }

    $credential = $matches[1];
    $signed_headers_str = $matches[2];
    $provided_signature = $matches[3];

    // Parse credential
    $credential_parts = explode('/', $credential);
    if (count($credential_parts) < 5) {
        return false;
    }
    $access_key = $credential_parts[0];
    $date_stamp = $credential_parts[1];
    $region = $credential_parts[2];
    $service = $credential_parts[3];

    // Check if access key exists
    if (!isset(ACCESS_CREDENTIALS[$access_key])) {
        return false;
    }
    $secret_key = ACCESS_CREDENTIALS[$access_key];

    // Get X-Amz-Date or Date header
    $amz_date = $_SERVER['HTTP_X_AMZ_DATE'] ?? '';
    if (!$amz_date) {
        return false;
    }

    // Build canonical request
    $method = $_SERVER['REQUEST_METHOD'];
    $canonical_uri = get_canonical_uri($_SERVER['REQUEST_URI']);
    $canonical_query_string = get_canonical_query_string(false);
    $signed_headers = explode(';', strtolower($signed_headers_str));
    $canonical_headers = get_canonical_headers($signed_headers);

    // Get payload hash
    $payload_hash = $_SERVER['HTTP_X_AMZ_CONTENT_SHA256'] ?? hash('sha256', file_get_contents('php://input'));

    $canonical_request = $method . "\n" .
        $canonical_uri . "\n" .
        $canonical_query_string . "\n" .
        $canonical_headers . "\n" .
        $signed_headers_str . "\n" .
        $payload_hash;

    // Build string to sign
    $algorithm = 'AWS4-HMAC-SHA256';
    $credential_scope = $date_stamp . '/' . $region . '/' . $service . '/aws4_request';
    $string_to_sign = $algorithm . "\n" .
        $amz_date . "\n" .
        $credential_scope . "\n" .
        hash('sha256', $canonical_request);

    // Calculate signature
    $signing_key = get_signing_key($secret_key, $date_stamp, $region, $service);
    $calculated_signature = hash_hmac('sha256', $string_to_sign, $signing_key);

    // Compare signatures
    return hash_equals($calculated_signature, $provided_signature);
}

function auth_check()
{
    // Check for presigned URL parameters
    if (isset($_GET['X-Amz-Signature'])) {
        if (!verify_presigned_url()) {
            generate_s3_error_response('SignatureDoesNotMatch', 'The request signature we calculated does not match the signature you provided', 403);
        }
        return true;
    }

    // Check for Authorization header
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        if (!verify_authorization_header()) {
            generate_s3_error_response('SignatureDoesNotMatch', 'The request signature we calculated does not match the signature you provided', 403);
        }
        return true;
    }

    // No authentication provided
    generate_s3_error_response('AccessDenied', 'Access Denied', 401);
}

// S3 error response function, separating S3 error codes from HTTP status codes
function generate_s3_error_response($s3_code, $message, $http_status, $resource = '')
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><Error xmlns="' . S3_XML_NS . '"></Error>');
    $xml->addChild('Code', $s3_code);
    $xml->addChild('Message', $message);
    $xml->addChild('Resource', $resource);
    $xml->addChild('RequestId', bin2hex(random_bytes(8))); // Add RequestId for better compatibility

    header('Content-Type: application/xml');
    http_response_code((int) $http_status);
    echo $xml->asXML();
    exit;
}

function generate_s3_list_objects_response($files, $bucket, $prefix = '')
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="' . S3_XML_NS . '"></ListBucketResult>');
    $xml->addChild('Name', $bucket);
    $xml->addChild('Prefix', $prefix);
    $xml->addChild('MaxKeys', '1000');
    $xml->addChild('IsTruncated', 'false');
    // Not implementing CommonPrefixes (delimiter) for now, keeping minimal

    foreach ($files as $file) {
        $contents = $xml->addChild('Contents');
        $contents->addChild('Key', htmlspecialchars($file['key'])); // Ensure XML special characters in key are escaped
        $contents->addChild('LastModified', date('Y-m-d\TH:i:s.000\Z', $file['timestamp']));
        $contents->addChild('Size', $file['size']);
        $contents->addChild('StorageClass', 'STANDARD');
    }

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}

function generate_s3_list_buckets_response($buckets)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="' . S3_XML_NS . '"></ListAllMyBucketsResult>');
    $owner = $xml->addChild('Owner');
    $owner->addChild('ID', 's3-server');
    $owner->addChild('DisplayName', 's3-server');
    
    $bucketsNode = $xml->addChild('Buckets');
    foreach ($buckets as $bucket) {
        $bucketNode = $bucketsNode->addChild('Bucket');
        $bucketNode->addChild('Name', $bucket);
        $bucketNode->addChild('CreationDate', date('Y-m-d\TH:i:s.000\Z', filemtime(DATA_DIR . '/' . $bucket)));
    }

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}

function generate_s3_create_multipart_upload_response($bucket, $key, $uploadId)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="' . S3_XML_NS . '"></InitiateMultipartUploadResult>');
    $xml->addChild('Bucket', $bucket);
    $xml->addChild('Key', htmlspecialchars($key)); // Escape special characters
    $xml->addChild('UploadId', $uploadId);

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}

function generate_s3_complete_multipart_upload_response($bucket, $key, $location)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="' . S3_XML_NS . '"></CompleteMultipartUploadResult>');
    $xml->addChild('Location', $location);
    $xml->addChild('Bucket', $bucket);
    $xml->addChild('Key', htmlspecialchars($key)); // Escape special characters

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}

// S3 ListParts response
function generate_s3_list_parts_response($bucket, $key, $uploadId, $parts)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><ListPartsResult xmlns="' . S3_XML_NS . '"></ListPartsResult>');
    $xml->addChild('Bucket', $bucket);
    $xml->addChild('Key', htmlspecialchars($key));
    $xml->addChild('UploadId', $uploadId);
    $xml->addChild('MaxParts', '1000');
    $xml->addChild('IsTruncated', 'false');

    foreach ($parts as $part) {
        $partNode = $xml->addChild('Part');
        $partNode->addChild('PartNumber', $part['number']);
        $partNode->addChild('LastModified', date('Y-m-d\TH:i:s.000\Z', $part['timestamp']));
        $partNode->addChild('ETag', $part['etag']);
        $partNode->addChild('Size', $part['size']);
    }

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}

// S3 CopyObject response
function generate_s3_copy_object_response($etag, $lastModified)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult xmlns="' . S3_XML_NS . '"></CopyObjectResult>');
    $xml->addChild('LastModified', date('Y-m-d\TH:i:s.000\Z', $lastModified));
    $xml->addChild('ETag', $etag);

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}


// S3 DeleteObjects (Bulk Delete) response
function generate_s3_delete_objects_response($deleted, $errors)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns="' . S3_XML_NS . '"></DeleteResult>');
    
    foreach ($deleted as $key) {
        $delNode = $xml->addChild('Deleted');
        $delNode->addChild('Key', htmlspecialchars($key));
    }
    
    foreach ($errors as $error) {
        $errNode = $xml->addChild('Error');
        $errNode->addChild('Key', htmlspecialchars($error['key']));
        $errNode->addChild('Code', $error['code']);
        $errNode->addChild('Message', $error['message']);
    }

    header('Content-Type: application/xml');
    http_response_code(200); // Bulk delete returns 200 regardless of individual success/failure
    echo $xml->asXML();
    exit;
}


function decode_s3_key($key) {
    // S3 uses rawurlencode, but some clients send spaces as '+'
    $decoded = str_replace('+', ' ', $key);
    return rawurldecode($decoded);
}

function encode_s3_key($key) {
    // S3 key encoding: split by '/' and rawurlencode each part
    $parts = explode('/', $key);
    $encodedParts = array_map('rawurlencode', $parts);
    return implode('/', $encodedParts);
}

function list_buckets()
{
    if (!file_exists(DATA_DIR)) {
        return [];
    }
    
    $buckets = [];
    $items = scandir(DATA_DIR);
    foreach ($items as $item) {
        if ($item !== '.' && $item !== '..' && is_dir(DATA_DIR . '/' . $item)) {
            $buckets[] = $item;
        }
    }
    
    return $buckets;
}

function list_files($bucket, $prefix = '')
{
    $dir = DATA_DIR . "/{$bucket}";
    $files = [];

    if (!file_exists($dir)) {
        return $files;
    }

    // Decode prefix for filesystem search
    $decodedPrefix = $prefix ? decode_s3_key($prefix) : '';

    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));

    foreach ($iterator as $file) {
        // Skip directories and internal .multipart directory
        if ($file->isDir()) {
            continue;
        }
        
        $filePath = $file->getRealPath();
        
        // Skip internal multipart upload directory
        if (strpos($filePath, DIRECTORY_SEPARATOR . '.multipart' . DIRECTORY_SEPARATOR) !== false) {
            continue;
        }

        $relativePath = str_replace('\\', '/', substr($filePath, strlen($dir) + 1));

        // Key fix: use decoded path for filesystem comparison
        if ($decodedPrefix && strpos($relativePath, $decodedPrefix) !== 0) {
            continue;
        }

        // Key returned to S3 client must be in S3 encoded format
        $s3Key = encode_s3_key($relativePath);
        
        $files[] = [
            'key' => $s3Key, // Return S3-encoded key name
            'size' => $file->getSize(),
            'timestamp' => $file->getMTime()
        ];
    }

    return $files;
}

function safe_delete_directory($dir) {
    if (!file_exists($dir)) {
        return true;
    }
    
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            safe_delete_directory($path);
        } else {
            unlink($path);
        }
    }
    return rmdir($dir);
}

// Unified file path handling (using decoded key)
function get_file_path($bucket, $key) {
    $decodedKey = decode_s3_key($key);
    return DATA_DIR . "/{$bucket}/{$decodedKey}";
}

// Stream copy function
function stream_copy($source, $dest) {
    $inputStream = fopen($source, 'rb');
    $outputStream = fopen($dest, 'wb');
    if (!$inputStream || !$outputStream) {
        if ($inputStream) fclose($inputStream);
        if ($outputStream) fclose($outputStream);
        return false;
    }
    stream_copy_to_stream($inputStream, $outputStream);
    fclose($inputStream);
    fclose($outputStream);
    return true;
}

// Ensure DATA_DIR exists
if (!file_exists(DATA_DIR)) {
    mkdir(DATA_DIR, 0777, true);
}

// Main request handling logic
$method = $_SERVER['REQUEST_METHOD'];

// Set CORS headers
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD");
header("Access-Control-Allow-Headers: Content-Type, Authorization, Content-Range, Range, X-Amz-Copy-Source");
header("Access-Control-Expose-Headers: ETag, Content-Length, Content-Range"); // Expose ETag etc.
header("Access-Control-Max-Age: 86400");

// Handle OPTIONS preflight request
if ($method === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Parse path - keep key in original encoded form
$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path_parts = explode('/', trim($request_uri, '/'));
$bucket = $path_parts[0] ?? '';
// Keep key in original encoded state
$key = implode('/', array_slice($path_parts, 1));

// Authentication check
auth_check();

// Check request size
if (isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > MAX_REQUEST_SIZE) {
    generate_s3_error_response('RequestTooLarge', 'Request too large', 413);
}

// Route requests
switch ($method) {
    case 'PUT':
        if (empty($bucket)) {
            generate_s3_error_response('InvalidBucketName', 'Bucket name required', 400);
        }
        
        // Check if this is a CopyObject request
        $copySource = $_SERVER['HTTP_X_AMZ_COPY_SOURCE'] ?? null;
        
        if (empty($key) && !$copySource) {
            // Create Bucket
            $bucketDir = DATA_DIR . "/{$bucket}";
            if (!file_exists($bucketDir)) {
                mkdir($bucketDir, 0777, true);
            }
            http_response_code(200);
            exit;
        }

        if ($copySource) {
            // Handle CopyObject
            // $copySource format: /source-bucket/source-key (key is URL encoded)
            $sourceParts = explode('/', ltrim($copySource, '/'), 2);
            if (count($sourceParts) < 2) {
                generate_s3_error_response('InvalidRequest', 'Invalid x-amz-copy-source header', 400);
            }
            $sourceBucket = $sourceParts[0];
            $sourceKey = $sourceParts[1]; // sourceKey stays encoded
            
            $sourcePath = get_file_path($sourceBucket, $sourceKey);
            $destPath = get_file_path($bucket, $key);

            if (!file_exists($sourcePath)) {
                generate_s3_error_response('NoSuchKey', 'Source object not found', 404, $copySource);
            }

            $dir = dirname($destPath);
            if (!file_exists($dir)) {
                mkdir($dir, 0777, true);
            }

            if (!copy($sourcePath, $destPath)) {
                generate_s3_error_response('InternalError', 'Failed to copy object', 500);
            }

            $etag = '"' . md5_file($destPath) . '"';
            $lastModified = filemtime($destPath);
            generate_s3_copy_object_response($etag, $lastModified);

        } elseif (isset($_GET['partNumber']) && isset($_GET['uploadId'])) {
            // Upload part
            $uploadId = $_GET['uploadId'];
            $partNumber = (int)$_GET['partNumber'];
            $decodedKey = decode_s3_key($key);
            $uploadDir = DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}/{$uploadId}";

            if (!file_exists($uploadDir)) {
                mkdir($uploadDir, 0777, true);
            }

            $partPath = "{$uploadDir}/{$partNumber}";

            // Use streaming to avoid memory overflow
            if (!stream_copy('php://input', $partPath)) {
                generate_s3_error_response('InternalError', 'Failed to write part file', 500, "/{$bucket}/{$key}");
            }
            
            header('ETag: "' . md5_file($partPath) . '"');
            http_response_code(200);
            exit;
        } else {
            // Upload single object
            $filePath = get_file_path($bucket, $key);
            $dir = dirname($filePath);

            if (!file_exists($dir)) {
                mkdir($dir, 0777, true);
            }

            // Use streaming to avoid memory overflow
            if (!stream_copy('php://input', $filePath)) {
                generate_s3_error_response('InternalError', 'Failed to write object file', 500, "/{$bucket}/{$key}");
            }

            header('ETag: "' . md5_file($filePath) . '"');
            http_response_code(200);
            exit;
        }
        break;


case 'POST':
        // Bucket validation is required
        if (empty($bucket)) {
            generate_s3_error_response('InvalidRequest', 'Bucket name required', 400);
        }
        
        if (isset($_GET['delete'])) {
            // Handle DeleteObjects (Bulk Delete)
            $input = file_get_contents('php://input');
            libxml_use_internal_errors(true);
            $xml = simplexml_load_string($input);
            if (!$xml) {
                generate_s3_error_response('InvalidXML', 'Invalid XML', 400);
            }

            $deleted = [];
            $errors = [];

            foreach ($xml->Object as $object) {
                $key = (string)$object->Key; // Key is S3 encoded
                if (empty($key)) continue;

                $filePath = get_file_path($bucket, $key);

                if (file_exists($filePath)) {
                    if (unlink($filePath)) {
                        $deleted[] = $key;
                        
                        // Reuse single file delete directory cleanup logic
                        $dir = dirname($filePath);
                        while ($dir !== (DATA_DIR . "/{$bucket}") && $dir !== DATA_DIR && is_dir($dir)) {
                            if (count(scandir($dir)) === 2) { // only . and ..
                                rmdir($dir);
                                $dir = dirname($dir);
                            } else {
                                break;
                            }
                        }
                    } else {
                        // File exists but deletion failed
                        $errors[] = ['key' => $key, 'code' => 'AccessDenied', 'message' => 'Error deleting file'];
                    }
                } else {
                    // S3 spec: deleting a non-existent key is considered success
                    $deleted[] = $key;
                }
            }

            generate_s3_delete_objects_response($deleted, $errors);

        } elseif (isset($_GET['uploads'])) {
            // Key validation moved here
            if (empty($key)) {
                 generate_s3_error_response('InvalidRequest', 'Key required for multipart upload', 400);
            }
            // Initiate multipart upload
            $uploadId = bin2hex(random_bytes(16));
            $decodedKey = decode_s3_key($key);
            $uploadDir = DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}/{$uploadId}";
            mkdir($uploadDir, 0777, true);

            generate_s3_create_multipart_upload_response($bucket, $key, $uploadId);

        } elseif (isset($_GET['uploadId'])) {
            // Key validation moved here
            if (empty($key)) {
                 generate_s3_error_response('InvalidRequest', 'Key required for multipart upload', 400);
            }
            // Complete multipart upload
            $uploadId = $_GET['uploadId'];
            $decodedKey = decode_s3_key($key);
            $uploadDir = DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}/{$uploadId}";

            if (!file_exists($uploadDir)) {
                generate_s3_error_response('NoSuchUpload', 'Upload ID not found', 404, "/{$bucket}/{$key}");
            }

            // Parse parts from XML
            $input = file_get_contents('php://input');
            libxml_use_internal_errors(true); // Suppress XML parsing warnings
            $xml = simplexml_load_string($input);
            if (!$xml) {
                generate_s3_error_response('InvalidXML', 'Invalid XML', 400, "/{$bucket}/{$key}");
            }
            
            $parts = [];
            foreach ($xml->Part as $part) {
                $partNumber = (int)$part->PartNumber;
                $parts[$partNumber] = (string)$part->ETag;
            }
            ksort($parts);

            // Merge parts
            $filePath = get_file_path($bucket, $key);
            $dir = dirname($filePath);
            if (!file_exists($dir)) {
                mkdir($dir, 0777, true);
            }

            $fp = fopen($filePath, 'wb');
            if (!$fp) {
                generate_s3_error_response('InternalError', 'Failed to create file', 500, "/{$bucket}/{$key}");
            }
            
            foreach (array_keys($parts) as $partNumber) {
                $partPath = "{$uploadDir}/{$partNumber}";
                if (!file_exists($partPath)) {
                    fclose($fp);
                    generate_s3_error_response('InvalidPart', "Part file missing: {$partNumber}", 400, "/{$bucket}/{$key}");
                }
                
                $partFp = fopen($partPath, 'rb');
                if ($partFp) {
                    stream_copy_to_stream($partFp, $fp);
                    fclose($partFp);
                }
            }
            fclose($fp);

            // Clean up
            safe_delete_directory($uploadDir);
            @rmdir(DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}");
            @rmdir(DATA_DIR . "/{$bucket}/.multipart");

            $location = "http://{$_SERVER['HTTP_HOST']}/{$bucket}/{$key}";
            generate_s3_complete_multipart_upload_response($bucket, $key, $location);
        } else {
            generate_s3_error_response('InvalidRequest', 'Invalid POST request', 400);
        }
        break;

        

    case 'GET':
        if (empty($bucket)) {
            // List all buckets
            $buckets = list_buckets();
            generate_s3_list_buckets_response($buckets);
        } elseif (empty($key)) {
            // List objects in bucket
            $prefix = $_GET['prefix'] ?? '';
            // $delimiter = $_GET['delimiter'] ?? null; // Not implemented yet
            $files = list_files($bucket, $prefix);
            generate_s3_list_objects_response($files, $bucket, $prefix);
        } else {
            // Check for ListParts
            if (isset($_GET['uploadId'])) {
                $uploadId = $_GET['uploadId'];
                $decodedKey = decode_s3_key($key);
                $uploadDir = DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}/{$uploadId}";

                if (!file_exists($uploadDir)) {
                    generate_s3_error_response('NoSuchUpload', 'Upload ID not found', 404, "/{$bucket}/{$key}");
                }

                $parts = [];
                $items = scandir($uploadDir);
                foreach ($items as $item) {
                    if (ctype_digit($item)) { // partNumber must be numeric
                        $partPath = "{$uploadDir}/{$item}";
                        $parts[] = [
                            'number' => (int)$item,
                            'timestamp' => filemtime($partPath),
                            'etag' => '"' . md5_file($partPath) . '"',
                            'size' => filesize($partPath)
                        ];
                    }
                }
                // Sort by PartNumber
                usort($parts, function($a, $b) { return $a['number'] <=> $b['number']; });

                generate_s3_list_parts_response($bucket, $key, $uploadId, $parts);
                exit;
            }
            
            // Download object
            $filePath = get_file_path($bucket, $key);
            
            if (!file_exists($filePath)) {
                error_log("File not found: {$filePath} (bucket: {$bucket}, key: {$key})");
                generate_s3_error_response('NoSuchKey', 'Object not found', 404, "/{$bucket}/{$key}");
            }

            $filesize = filesize($filePath);
            $mimeType = mime_content_type($filePath) ?: 'application/octet-stream';
            
            // Critical fix for S3 Browser bug: removed small file optimization.
            // Range requests must be handled correctly regardless of file size.

            $fp = fopen($filePath, 'rb');
            if ($fp === false) {
                generate_s3_error_response('InternalError', 'Failed to open file', 500, "/{$bucket}/{$key}");
            }

            // Enhanced range request handling
            $rangeHeader = $_SERVER['HTTP_RANGE'] ?? '';
            $start = 0;
            $end = $filesize - 1;
            $length = $filesize;
            $partialContent = false;

            if ($rangeHeader) {
                if (preg_match('/bytes=(\d+)-(\d+)/', $rangeHeader, $matches)) {
                    // Format: bytes=start-end
                    $rangeStart = (int)$matches[1];
                    $rangeEnd = (int)$matches[2];
                    
                    if ($rangeStart < 0 || $rangeEnd >= $filesize || $rangeStart > $rangeEnd) {
                        header("Content-Range: bytes */{$filesize}");
                        http_response_code(416); // Range Not Satisfiable
                        fclose($fp);
                        exit;
                    }
                    
                    $start = $rangeStart;
                    $end = $rangeEnd;
                    $partialContent = true;
                    
                } elseif (preg_match('/bytes=(\d+)-$/', $rangeHeader, $matches)) {
                    // Format: bytes=start- (from start to end of file)
                    $rangeStart = (int)$matches[1];
                    
                    if ($rangeStart >= $filesize) {
                        header("Content-Range: bytes */{$filesize}");
                        http_response_code(416);
                        fclose($fp);
                        exit;
                    }
                    
                    $start = $rangeStart;
                    $end = $filesize - 1;
                    $partialContent = true;
                    
                } elseif (preg_match('/bytes=-(\d+)/', $rangeHeader, $matches)) {
                    // Format: bytes=-suffix (last suffix bytes)
                    $suffix = (int)$matches[1];
                    
                    if ($suffix <= 0) {
                        header("Content-Range: bytes */{$filesize}");
                        http_response_code(416);
                        fclose($fp);
                        exit;
                    }
                    
                    $start = max(0, $filesize - $suffix);
                    $end = $filesize - 1;
                    $partialContent = true;
                }
            }

            // Calculate final length
            $length = $end - $start + 1;

            if ($partialContent) {
                http_response_code(206); // Partial Content
                header("Content-Range: bytes {$start}-{$end}/{$filesize}");
            } else {
                http_response_code(200); // OK
            }

            header('Accept-Ranges: bytes');
            header('Content-Type: ' . $mimeType);
            header('Content-Length: ' . $length);
            // S3 clients need filename* to handle non-ASCII characters
            $encodedBasename = rawurlencode(basename(decode_s3_key($key)));
            header('Content-Disposition: inline; filename="' . basename(decode_s3_key($key)) . '"; filename*="UTF-8\'\'' . $encodedBasename . '"');
            header('Last-Modified: ' . gmdate('D, d M Y H:i:s T', filemtime($filePath)));
            header('ETag: "' . md5_file($filePath) . '"');

            // Stream transfer
            if ($start > 0) {
                fseek($fp, $start);
            }

            $chunkSize = 8192;
            $bytesSent = 0;
            
            while (!feof($fp) && $bytesSent < $length) {
                if (connection_aborted()) {
                    break;
                }
                
                $bytesToRead = min($chunkSize, $length - $bytesSent);
                $buffer = fread($fp, $bytesToRead);
                
                if ($buffer === false) {
                    break;
                }
                
                echo $buffer;
                $bytesSent += strlen($buffer);
                flush();
            }

            fclose($fp);
            exit;
        }
        break;

    case 'HEAD':
        if (empty($bucket)) {
            // HEAD on root - service check
            http_response_code(200);
            exit;
        } elseif (empty($key)) {
            // HEAD on bucket - check if bucket exists
            $bucketDir = DATA_DIR . "/{$bucket}";
            if (!file_exists($bucketDir)) {
                generate_s3_error_response('NoSuchBucket', 'Bucket not found', 404, "/{$bucket}");
            }
            http_response_code(200);
            exit;
        }

        $filePath = get_file_path($bucket, $key);
        if (!file_exists($filePath)) {
            generate_s3_error_response('NoSuchKey', 'Object not found', 404, "/{$bucket}/{$key}");
        }

        header('Content-Length: ' . filesize($filePath));
        header('Content-Type: ' . (mime_content_type($filePath) ?: 'application/octet-stream'));
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s T', filemtime($filePath)));
        header('ETag: "' . md5_file($filePath) . '"');
        header('Accept-Ranges: bytes');
        http_response_code(200);
        exit;

    case 'DELETE':
        if (empty($bucket)) {
            generate_s3_error_response('InvalidBucketName', 'Bucket name required', 400);
        }
        
        if (isset($_GET['uploadId'])) {
            // Abort multipart upload
            $uploadId = $_GET['uploadId'];
            $decodedKey = decode_s3_key($key);
            $uploadDir = DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}/{$uploadId}";

            if (file_exists($uploadDir)) {
                safe_delete_directory($uploadDir);
                // Try to clean up parent directories
                @rmdir(DATA_DIR . "/{$bucket}/.multipart/{$decodedKey}");
                @rmdir(DATA_DIR . "/{$bucket}/.multipart");
            }
            http_response_code(204);
            exit;
        } elseif (empty($key)) {
            // Delete bucket (must be empty)
            $bucketDir = DATA_DIR . "/{$bucket}";
            if (!file_exists($bucketDir)) {
                generate_s3_error_response('NoSuchBucket', 'Bucket not found', 404, "/{$bucket}");
            }
            
            // Check if bucket is empty
            $items = array_diff(scandir($bucketDir), ['.', '..']);
            if (count($items) > 0) {
                 // Check if only .multipart directory exists
                if (count($items) === 1 && $items[2] === '.multipart' && is_dir($bucketDir . '/.multipart')) {
                     // If only .multipart directory exists, check if it's empty
                    $mpItems = array_diff(scandir($bucketDir . '/.multipart'), ['.', '..']);
                    if (count($mpItems) > 0) {
                        generate_s3_error_response('BucketNotEmpty', 'Bucket not empty', 409, "/{$bucket}");
                    }
                    // .multipart directory is empty, can be deleted
                    safe_delete_directory($bucketDir . '/.multipart');
                } else {
                     generate_s3_error_response('BucketNotEmpty', 'Bucket not empty', 409, "/{$bucket}");
                }
            }
            
            rmdir($bucketDir);
            http_response_code(204);
            exit;
        } else {
            // Delete object
            $filePath = get_file_path($bucket, $key);
            if (file_exists($filePath)) {
                unlink($filePath);
                
                // Clean up empty directories
                $dir = dirname($filePath);
                while ($dir !== (DATA_DIR . "/{$bucket}") && $dir !== DATA_DIR && is_dir($dir)) {
                    if (count(scandir($dir)) === 2) { // only . and ..
                        rmdir($dir);
                        $dir = dirname($dir);
                    } else {
                        break;
                    }
                }
            }
            http_response_code(204);
            exit;
        }
        break;

    default:
        generate_s3_error_response('MethodNotAllowed', 'Method not allowed', 405);
}
