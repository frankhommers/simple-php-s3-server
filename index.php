<?php
// Minimal S3-like PHP server

// Configuration
define('DATA_DIR', __DIR__ . '/data');
define('ALLOWED_ACCESS_KEYS', ['put_your_key_here']);
define('MAX_REQUEST_SIZE', 100 * 1024 * 1024); // 100MB
define('S3_XML_NS', 'http://s3.amazonaws.com/doc/2006-03-01/'); // [优化] S3 XML 命名空间

// Helper functions
function extract_access_key_id()
{
    // 从 Authorization header 提取
    $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/AWS4-HMAC-SHA256 Credential=([^\/]+)\//', $authorization, $matches)) {
        return $matches[1];
    }

    // 从 X-Amz-Credential URL 参数提取
    $credential = $_GET['X-Amz-Credential'] ?? '';
    if ($credential) {
        $parts = explode('/', $credential);
        return $parts[0] ?? null;
    }

    return null;
}

function auth_check()
{
    $access_key_id = extract_access_key_id();
    if (!$access_key_id || !in_array($access_key_id, ALLOWED_ACCESS_KEYS)) {
        // [优化] 使用标准S3错误码和HTTP状态码
        generate_s3_error_response('AccessDenied', 'Access Denied', 401);
    }
    return true;
}

// [优化] S3错误响应函数，分离S3错误码和HTTP状态码
function generate_s3_error_response($s3_code, $message, $http_status, $resource = '')
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><Error xmlns="' . S3_XML_NS . '"></Error>');
    $xml->addChild('Code', $s3_code);
    $xml->addChild('Message', $message);
    $xml->addChild('Resource', $resource);
    $xml->addChild('RequestId', bin2hex(random_bytes(8))); // 增加 RequestId 提高兼容性

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
    // 暂不实现 CommonPrefixes (delimiter)，保持最小可用

    foreach ($files as $file) {
        $contents = $xml->addChild('Contents');
        $contents->addChild('Key', htmlspecialchars($file['key'])); // [优化] 确保key中的XML特殊字符被转义
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
    $xml->addChild('Key', htmlspecialchars($key)); // [优化] 转义
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
    $xml->addChild('Key', htmlspecialchars($key)); // [优化] 转义

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}

// [新增] S3 ListParts 响应
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

// [新增] S3 CopyObject 响应
function generate_s3_copy_object_response($etag, $lastModified)
{
    $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult xmlns="' . S3_XML_NS . '"></CopyObjectResult>');
    $xml->addChild('LastModified', date('Y-m-d\TH:i:s.000\Z', $lastModified));
    $xml->addChild('ETag', $etag);

    header('Content-Type: application/xml');
    echo $xml->asXML();
    exit;
}


// [新增] S3 DeleteObjects (Bulk Delete) 响应
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
    http_response_code(200); // 批量删除无论成功与否，HTTP状态码通常都是200
    echo $xml->asXML();
    exit;
}


function decode_s3_key($key) {
    // S3使用rawurlencode，但有些客户端会把空格发成'+'
    $decoded = str_replace('+', ' ', $key);
    return rawurldecode($decoded);
}

function encode_s3_key($key) {
    // S3的Key编码是按'/'分割后，对每一部分进行rawurlencode
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

    // 解码前缀用于文件系统搜索
    $decodedPrefix = $prefix ? decode_s3_key($prefix) : '';

    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));

    foreach ($iterator as $file) {
        // [优化] 跳过目录本身和我们内部的.multipart目录
        if ($file->isDir()) {
            continue;
        }
        
        $filePath = $file->getRealPath();
        
        // [优化] 跳过内部分块上传目录
        if (strpos($filePath, DIRECTORY_SEPARATOR . '.multipart' . DIRECTORY_SEPARATOR) !== false) {
            continue;
        }

        $relativePath = str_replace('\\', '/', substr($filePath, strlen($dir) + 1));

        // 关键修复：在文件系统中使用解码后的路径进行比较
        if ($decodedPrefix && strpos($relativePath, $decodedPrefix) !== 0) {
            continue;
        }

        // [关键修复] 返回给S3客户端的Key必须是S3编码格式
        $s3Key = encode_s3_key($relativePath);
        
        $files[] = [
            'key' => $s3Key, // 返回S3编码后的键名
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

// 统一文件路径处理 (使用解码后的Key)
function get_file_path($bucket, $key) {
    $decodedKey = decode_s3_key($key);
    return DATA_DIR . "/{$bucket}/{$decodedKey}";
}

// [优化] 流式复制函数
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

// 主请求处理逻辑
$method = $_SERVER['REQUEST_METHOD'];

// 设置跨域头
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, HEAD");
header("Access-Control-Allow-Headers: Content-Type, Authorization, Content-Range, Range, X-Amz-Copy-Source");
header("Access-Control-Expose-Headers: ETag, Content-Length, Content-Range"); // [优化] 暴露 ETag 等
header("Access-Control-Max-Age: 86400");

// 处理 OPTIONS 预检请求
if ($method === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// 解析路径 - 保持原始编码的key
$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path_parts = explode('/', trim($request_uri, '/'));
$bucket = $path_parts[0] ?? '';
// 保持key的原始编码状态
$key = implode('/', array_slice($path_parts, 1));

// 认证检查
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
        
        // [新增] 检查是否为 CopyObject
        $copySource = $_SERVER['HTTP_X_AMZ_COPY_SOURCE'] ?? null;
        
        if (empty($key) && !$copySource) {
            // 创建 Bucket
            $bucketDir = DATA_DIR . "/{$bucket}";
            if (!file_exists($bucketDir)) {
                mkdir($bucketDir, 0777, true);
            }
            http_response_code(200);
            exit;
        }

        if ($copySource) {
            // [新增] 处理 CopyObject
            // $copySource 格式: /source-bucket/source-key (key是URL编码的)
            $sourceParts = explode('/', ltrim($copySource, '/'), 2);
            if (count($sourceParts) < 2) {
                generate_s3_error_response('InvalidRequest', 'Invalid x-amz-copy-source header', 400);
            }
            $sourceBucket = $sourceParts[0];
            $sourceKey = $sourceParts[1]; // sourceKey 保持编码状态
            
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

            // [优化] 使用流式传输，避免内存溢出
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

            // [优化] 使用流式传输，避免内存溢出
            if (!stream_copy('php://input', $filePath)) {
                generate_s3_error_response('InternalError', 'Failed to write object file', 500, "/{$bucket}/{$key}");
            }

            header('ETag: "' . md5_file($filePath) . '"');
            http_response_code(200);
            exit;
        }
        break;


case 'POST':
        // [修改] Bucket 检查是必须的
        if (empty($bucket)) {
            generate_s3_error_response('InvalidRequest', 'Bucket name required', 400);
        }
        
        if (isset($_GET['delete'])) {
            // [新增] 处理 DeleteObjects (Bulk Delete)
            $input = file_get_contents('php://input');
            libxml_use_internal_errors(true);
            $xml = simplexml_load_string($input);
            if (!$xml) {
                generate_s3_error_response('InvalidXML', 'Invalid XML', 400);
            }

            $deleted = [];
            $errors = [];

            foreach ($xml->Object as $object) {
                $key = (string)$object->Key; // Key 是 S3 编码的
                if (empty($key)) continue;

                $filePath = get_file_path($bucket, $key);

                if (file_exists($filePath)) {
                    if (unlink($filePath)) {
                        $deleted[] = $key;
                        
                        // [优化] 复用单文件删除的目录清理逻辑
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
                        // 文件存在但删除失败
                        $errors[] = ['key' => $key, 'code' => 'AccessDenied', 'message' => 'Error deleting file'];
                    }
                } else {
                    // S3 规范：删除一个不存在的 Key 视为成功
                    $deleted[] = $key;
                }
            }

            generate_s3_delete_objects_response($deleted, $errors);

        } elseif (isset($_GET['uploads'])) {
            // [修改] Key 检查移到这里
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
            // [修改] Key 检查移到这里
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
            libxml_use_internal_errors(true); // [优化] 抑制XML解析警告
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
            // $delimiter = $_GET['delimiter'] ?? null; // 暂不实现
            $files = list_files($bucket, $prefix);
            generate_s3_list_objects_response($files, $bucket, $prefix);
        } else {
            // Check for ListParts [新增]
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
                    if (ctype_digit($item)) { // partNumber 必须是数字
                        $partPath = "{$uploadDir}/{$item}";
                        $parts[] = [
                            'number' => (int)$item,
                            'timestamp' => filemtime($partPath),
                            'etag' => '"' . md5_file($partPath) . '"',
                            'size' => filesize($partPath)
                        ];
                    }
                }
                // 按 PartNumber 排序
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
            
            // [关键修复 S3 Browser Bug] 移除小文件优化。
            // 无论文件大小，都必须正确处理 Range 请求。

            $fp = fopen($filePath, 'rb');
            if ($fp === false) {
                generate_s3_error_response('InternalError', 'Failed to open file', 500, "/{$bucket}/{$key}");
            }

            // 增强的范围请求处理
            $rangeHeader = $_SERVER['HTTP_RANGE'] ?? '';
            $start = 0;
            $end = $filesize - 1;
            $length = $filesize;
            $partialContent = false;

            if ($rangeHeader) {
                if (preg_match('/bytes=(\d+)-(\d+)/', $rangeHeader, $matches)) {
                    // 格式: bytes=start-end
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
                    // 格式: bytes=start- (从start到文件末尾)
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
                    // 格式: bytes=-suffix (最后suffix个字节)
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

            // 计算最终长度
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
            // [优化] S3 客户端需要 filename* 来处理非 ASCII 字符
            $encodedBasename = rawurlencode(basename(decode_s3_key($key)));
            header('Content-Disposition: inline; filename="' . basename(decode_s3_key($key)) . '"; filename*="UTF-8\'\'' . $encodedBasename . '"');
            header('Last-Modified: ' . gmdate('D, d M Y H:i:s T', filemtime($filePath)));
            header('ETag: "' . md5_file($filePath) . '"');

            // 流式传输
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
        if (empty($bucket) || empty($key)) {
            generate_s3_error_response('InvalidRequest', 'Bucket and key required', 400);
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
                // [优化] 尝试清理父级目录
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
            
            // Check if bucket is empty (使用更简单的方式)
            $items = array_diff(scandir($bucketDir), ['.', '..']);
            if (count($items) > 0) {
                 // [优化] 检查是否只有 .multipart 目录
                if (count($items) === 1 && $items[2] === '.multipart' && is_dir($bucketDir . '/.multipart')) {
                     // 如果只有 .multipart 目录，检查它是否为空
                    $mpItems = array_diff(scandir($bucketDir . '/.multipart'), ['.', '..']);
                    if (count($mpItems) > 0) {
                        generate_s3_error_response('BucketNotEmpty', 'Bucket not empty', 409, "/{$bucket}");
                    }
                    // .multipart 目录为空，可以删除
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
