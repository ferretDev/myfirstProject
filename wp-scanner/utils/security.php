<?php
/**
 * Security Utilities
 *
 * Input validation, sanitization, and security helper functions
 */

namespace WPScanner\Utils;

class Security {

    private static $wp_root;

    /**
     * Initialize with WordPress root path
     */
    public static function init($wp_root) {
        self::$wp_root = realpath($wp_root);
    }

    /**
     * Validate file path is within WordPress root
     * CRITICAL: Prevents path traversal attacks
     */
    public static function validatePath($path) {
        if (empty($path)) {
            throw new \Exception('Path cannot be empty');
        }

        // Resolve to real path
        $real_path = realpath($path);

        // If file doesn't exist, check parent directory
        if ($real_path === false) {
            $parent = dirname($path);
            $real_parent = realpath($parent);

            if ($real_parent === false) {
                throw new \Exception('Invalid path: parent directory does not exist');
            }

            // Reconstruct path
            $real_path = $real_parent . '/' . basename($path);
        }

        // Ensure path is within WordPress root
        if (strpos($real_path, self::$wp_root) !== 0) {
            throw new \Exception('Path traversal detected: path outside WordPress root');
        }

        return $real_path;
    }

    /**
     * Sanitize filename for safe storage
     */
    public static function sanitizeFilename($filename) {
        // Remove directory separators
        $filename = str_replace(['/', '\\', "\0"], '', $filename);

        // Remove dangerous characters
        $filename = preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $filename);

        // Prevent double extensions like .php.jpg
        $filename = preg_replace('/\.php\./i', '.phptxt.', $filename);

        // Limit length
        if (strlen($filename) > 255) {
            $filename = substr($filename, 0, 255);
        }

        return $filename;
    }

    /**
     * Validate and sanitize integer input
     */
    public static function sanitizeInt($value, $min = null, $max = null) {
        $value = filter_var($value, FILTER_VALIDATE_INT);

        if ($value === false) {
            throw new \Exception('Invalid integer value');
        }

        if ($min !== null && $value < $min) {
            throw new \Exception("Value must be at least {$min}");
        }

        if ($max !== null && $value > $max) {
            throw new \Exception("Value must be at most {$max}");
        }

        return $value;
    }

    /**
     * Validate email address
     */
    public static function sanitizeEmail($email) {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new \Exception('Invalid email address');
        }

        return $email;
    }

    /**
     * Sanitize command line argument
     */
    public static function sanitizeCommandArg($arg) {
        // Remove null bytes
        $arg = str_replace("\0", '', $arg);

        // Remove shell metacharacters
        $arg = preg_replace('/[;&|`$]/', '', $arg);

        return trim($arg);
    }

    /**
     * Escape output for HTML
     * CRITICAL: Prevents XSS in reports
     */
    public static function escapeHtml($text) {
        return htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Escape output for HTML attributes
     */
    public static function escapeAttr($text) {
        return htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Escape output for JavaScript
     */
    public static function escapeJs($text) {
        return json_encode($text, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }

    /**
     * Sanitize regex pattern to prevent ReDoS
     */
    public static function sanitizeRegex($pattern) {
        // Check for excessive repetition that could cause ReDoS
        if (preg_match('/(\*\+|\+\*|\{\d+,\}\+|\+\{\d+,\})/', $pattern)) {
            throw new \Exception('Potentially dangerous regex pattern detected');
        }

        // Check for excessive nesting
        $nesting_level = 0;
        $max_nesting = 10;

        for ($i = 0; $i < strlen($pattern); $i++) {
            if ($pattern[$i] === '(') {
                $nesting_level++;
                if ($nesting_level > $max_nesting) {
                    throw new \Exception('Regex nesting too deep');
                }
            } elseif ($pattern[$i] === ')') {
                $nesting_level--;
            }
        }

        return $pattern;
    }

    /**
     * Validate user ID
     */
    public static function validateUserId($user_id) {
        $user_id = self::sanitizeInt($user_id, 1);

        // Prevent deleting user ID 1 (usually primary admin)
        if ($user_id === 1) {
            throw new \Exception('Cannot modify primary admin account (ID: 1)');
        }

        return $user_id;
    }

    /**
     * Confirm destructive operation
     */
    public static function confirmDestructive($message, $auto_confirm = false) {
        if ($auto_confirm) {
            return true;
        }

        echo "\n⚠️  WARNING: Destructive operation\n";
        echo $message . "\n";
        echo "Type 'yes' to confirm: ";

        $handle = fopen("php://stdin", "r");
        $line = fgets($handle);
        fclose($handle);

        return trim(strtolower($line)) === 'yes';
    }

    /**
     * Generate secure random token
     */
    public static function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }

    /**
     * Rate limit check (simple file-based)
     */
    public static function checkRateLimit($identifier, $max_attempts = 10, $time_window = 3600) {
        $rate_limit_file = WP_SCANNER_DIR . '/data/rate_limit.json';
        $rate_limits = [];

        if (file_exists($rate_limit_file)) {
            $rate_limits = json_decode(file_get_contents($rate_limit_file), true) ?: [];
        }

        $now = time();
        $key = md5($identifier);

        // Clean old entries
        foreach ($rate_limits as $k => $data) {
            if ($data['expires'] < $now) {
                unset($rate_limits[$k]);
            }
        }

        // Check current identifier
        if (isset($rate_limits[$key])) {
            if ($rate_limits[$key]['count'] >= $max_attempts) {
                $wait_time = $rate_limits[$key]['expires'] - $now;
                throw new \Exception("Rate limit exceeded. Try again in {$wait_time} seconds.");
            }

            $rate_limits[$key]['count']++;
        } else {
            $rate_limits[$key] = [
                'count' => 1,
                'expires' => $now + $time_window
            ];
        }

        file_put_contents($rate_limit_file, json_encode($rate_limits));
        return true;
    }

    /**
     * Validate file extension against whitelist
     */
    public static function validateFileExtension($filename, $allowed_extensions = []) {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if (empty($allowed_extensions)) {
            // Default safe extensions for reading
            $allowed_extensions = ['php', 'txt', 'html', 'htm', 'css', 'js', 'json', 'xml'];
        }

        if (!in_array($ext, $allowed_extensions)) {
            throw new \Exception("File extension '.{$ext}' not allowed");
        }

        return $ext;
    }

    /**
     * Check if operation requires sudo/elevated privileges
     */
    public static function requiresElevatedPrivileges() {
        if (function_exists('posix_geteuid')) {
            return posix_geteuid() === 0;
        }
        return false;
    }

    /**
     * Sanitize SQL LIMIT clause
     */
    public static function sanitizeSqlLimit($limit) {
        return self::sanitizeInt($limit, 1, 10000);
    }

    /**
     * Sanitize SQL ORDER BY clause
     */
    public static function sanitizeSqlOrderBy($order_by, $allowed_columns = []) {
        $order_by = strtoupper(trim($order_by));

        if (!in_array($order_by, ['ASC', 'DESC'])) {
            throw new \Exception('Invalid ORDER BY value');
        }

        return $order_by;
    }

    /**
     * Validate CIDR or IP address
     */
    public static function validateIp($ip) {
        // Check for CIDR notation
        if (strpos($ip, '/') !== false) {
            list($ip, $mask) = explode('/', $ip, 2);
            $mask = self::sanitizeInt($mask, 0, 32);
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new \Exception('Invalid IP address');
        }

        return $ip;
    }

    /**
     * Secure file deletion (overwrite before delete)
     */
    public static function secureDelete($filepath) {
        $filepath = self::validatePath($filepath);

        if (!file_exists($filepath)) {
            throw new \Exception('File not found');
        }

        if (!is_file($filepath)) {
            throw new \Exception('Not a file');
        }

        $size = filesize($filepath);

        // Overwrite with random data
        $handle = fopen($filepath, 'w');
        if ($handle) {
            fwrite($handle, random_bytes($size));
            fclose($handle);
        }

        // Delete file
        return unlink($filepath);
    }

    /**
     * Check if path is a dangerous location
     */
    public static function isDangerousPath($path) {
        $dangerous_paths = [
            '/etc/',
            '/bin/',
            '/sbin/',
            '/usr/bin/',
            '/usr/sbin/',
            '/var/www/',
            '/root/',
            '/home/',
        ];

        foreach ($dangerous_paths as $dangerous) {
            if (strpos($path, $dangerous) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Log security event
     */
    public static function logSecurityEvent($event_type, $details = []) {
        $security_log = WP_SCANNER_DIR . '/logs/security.log';

        $log_entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => $event_type,
            'details' => $details,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'CLI',
            'user' => get_current_user(),
        ];

        file_put_contents(
            $security_log,
            json_encode($log_entry) . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
    }

    /**
     * Verify file integrity with checksum
     */
    public static function verifyChecksum($filepath, $expected_checksum, $algorithm = 'sha256') {
        $filepath = self::validatePath($filepath);

        if (!file_exists($filepath)) {
            throw new \Exception('File not found');
        }

        $actual_checksum = hash_file($algorithm, $filepath);

        return hash_equals($expected_checksum, $actual_checksum);
    }

    /**
     * Detect suspicious file upload
     */
    public static function isSuspiciousUpload($filename, $content = null) {
        $suspicious = false;
        $reasons = [];

        // Check for double extensions
        if (preg_match('/\.(jpe?g|png|gif|pdf)\.(php|phtml|php3)/i', $filename)) {
            $suspicious = true;
            $reasons[] = 'Double extension detected';
        }

        // Check for null byte injection
        if (strpos($filename, "\0") !== false) {
            $suspicious = true;
            $reasons[] = 'Null byte in filename';
        }

        // Check content if provided
        if ($content !== null) {
            // Check for PHP tags in image files
            if (preg_match('/\.(jpe?g|png|gif)$/i', $filename) &&
                preg_match('/<\?php/i', $content)) {
                $suspicious = true;
                $reasons[] = 'PHP code in image file';
            }
        }

        return [
            'suspicious' => $suspicious,
            'reasons' => $reasons
        ];
    }
}
