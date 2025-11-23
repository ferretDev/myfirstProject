<?php
/**
 * WordPress File System Scanner
 *
 * Scans files for malicious content, suspicious patterns, and integrity violations
 */

namespace WPScanner\Filesystem\Scanners;

class FileScanner {

    private $wp_root;
    private $patterns;
    private $whitelist;
    private $quarantine_dir;

    public function __construct($wp_root, $patterns = [], $whitelist = []) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->patterns = $patterns;
        $this->whitelist = $whitelist;
        $this->quarantine_dir = WP_SCANNER_DIR . '/quarantine/';
    }

    /**
     * Scan PHP files for malicious code
     */
    public function scanPHPFiles($directory = null) {
        $directory = $directory ?: $this->wp_root;
        $results = [
            'scanned' => 0,
            'infected' => [],
            'suspicious' => []
        ];

        $files = $this->getPhpFiles($directory);

        foreach ($files as $file) {
            $results['scanned']++;
            $content = file_get_contents($file);

            // Skip if whitelisted
            if ($this->isWhitelisted($file)) {
                continue;
            }

            $scan_result = $this->scanFileContent($content, $file);

            if ($scan_result['status'] === 'infected') {
                $results['infected'][] = [
                    'file' => $file,
                    'patterns' => $scan_result['matches'],
                    'severity' => $scan_result['severity']
                ];
            } elseif ($scan_result['status'] === 'suspicious') {
                $results['suspicious'][] = [
                    'file' => $file,
                    'patterns' => $scan_result['matches']
                ];
            }
        }

        return $results;
    }

    /**
     * Scan file content for malicious patterns
     */
    private function scanFileContent($content, $filepath) {
        $matches = [];
        $severity = 'LOW';

        // Obfuscation patterns
        $obfuscation_patterns = [
            'base64_decode' => '/eval\s*\(\s*base64_decode/i',
            'gzinflate' => '/gzinflate\s*\(\s*base64_decode/i',
            'str_rot13' => '/str_rot13\s*\(/i',
            'hex_obfuscation' => '/\\\\x[0-9a-f]{2}/i'
        ];

        foreach ($obfuscation_patterns as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                $matches[] = $name;
                $severity = 'HIGH';
            }
        }

        // Dangerous function patterns
        $dangerous_functions = [
            'eval', 'exec', 'system', 'shell_exec', 'passthru',
            'proc_open', 'popen', 'assert', 'create_function'
        ];

        foreach ($dangerous_functions as $func) {
            if (preg_match("/{$func}\s*\(/i", $content)) {
                $matches[] = $func;
                if ($severity !== 'HIGH') {
                    $severity = 'MEDIUM';
                }
            }
        }

        // Backdoor patterns
        $backdoor_patterns = [
            'c99shell' => '/c99sh|c99shell/i',
            'r57shell' => '/r57shell/i',
            'wso_shell' => '/FilesMan|WSO/i',
            'password_param' => '/\$_(GET|POST|REQUEST)\[[\'"](pass|password|pwd)[\'"]\]/i',
            'command_param' => '/\$_(GET|POST|REQUEST)\[[\'"](cmd|command|exec)[\'"]\]/i'
        ];

        foreach ($backdoor_patterns as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                $matches[] = $name;
                $severity = 'CRITICAL';
            }
        }

        // File operation patterns
        $file_ops = [
            'file_put_contents' => '/file_put_contents\s*\(/i',
            'fwrite' => '/fwrite\s*\(/i',
            'fputs' => '/fputs\s*\(/i'
        ];

        foreach ($file_ops as $name => $pattern) {
            if (preg_match($pattern, $content)) {
                $matches[] = $name;
            }
        }

        if (!empty($matches)) {
            if ($severity === 'CRITICAL' || $severity === 'HIGH') {
                return ['status' => 'infected', 'matches' => $matches, 'severity' => $severity];
            } else {
                return ['status' => 'suspicious', 'matches' => $matches, 'severity' => $severity];
            }
        }

        return ['status' => 'clean', 'matches' => [], 'severity' => 'NONE'];
    }

    /**
     * Scan uploads directory for suspicious files
     */
    public function scanUploadsDirectory() {
        $uploads_dir = $this->wp_root . '/wp-content/uploads/';

        if (!is_dir($uploads_dir)) {
            return ['error' => 'Uploads directory not found'];
        }

        $results = [
            'php_files' => [],
            'executable_files' => [],
            'suspicious_extensions' => [],
            'double_extensions' => []
        ];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($uploads_dir, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $filename = $file->getFilename();
                $filepath = $file->getPathname();
                $extension = strtolower($file->getExtension());

                // PHP files in uploads (BAD!)
                if ($extension === 'php' || preg_match('/\.php\d?$/i', $filename)) {
                    $results['php_files'][] = [
                        'path' => $filepath,
                        'size' => $file->getSize(),
                        'modified' => date('Y-m-d H:i:s', $file->getMTime()),
                        'severity' => 'CRITICAL'
                    ];
                }

                // Executable extensions
                $exec_extensions = ['exe', 'sh', 'bat', 'cmd', 'com', 'pif', 'scr'];
                if (in_array($extension, $exec_extensions)) {
                    $results['executable_files'][] = $filepath;
                }

                // Suspicious extensions
                $suspicious_exts = ['phtml', 'php3', 'php4', 'php5', 'phps', 'pht', 'phar'];
                if (in_array($extension, $suspicious_exts)) {
                    $results['suspicious_extensions'][] = $filepath;
                }

                // Double extensions (e.g., image.jpg.php)
                if (preg_match('/\.(jpg|jpeg|png|gif|pdf)\.(php|phtml|php3)/i', $filename)) {
                    $results['double_extensions'][] = [
                        'path' => $filepath,
                        'severity' => 'CRITICAL'
                    ];
                }
            }
        }

        return $results;
    }

    /**
     * Get all PHP files in directory
     */
    private function getPhpFiles($directory) {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Check if file is whitelisted
     */
    private function isWhitelisted($filepath) {
        foreach ($this->whitelist as $pattern) {
            if (fnmatch($pattern, $filepath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Quarantine a suspicious file
     */
    public function quarantineFile($filepath) {
        if (!file_exists($filepath)) {
            return ['error' => 'File not found'];
        }

        // Create quarantine directory if it doesn't exist
        if (!is_dir($this->quarantine_dir)) {
            mkdir($this->quarantine_dir, 0755, true);
        }

        $filename = basename($filepath);
        $timestamp = date('Y-m-d_His');
        $quarantine_path = $this->quarantine_dir . $timestamp . '_' . $filename;

        // Copy file to quarantine
        if (copy($filepath, $quarantine_path)) {
            // Log the quarantine action
            $log_entry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'original_path' => $filepath,
                'quarantine_path' => $quarantine_path,
                'file_hash' => md5_file($filepath)
            ];

            file_put_contents(
                $this->quarantine_dir . 'quarantine.log',
                json_encode($log_entry) . PHP_EOL,
                FILE_APPEND
            );

            // Optionally delete the original
            // unlink($filepath);

            return [
                'success' => true,
                'quarantine_path' => $quarantine_path
            ];
        }

        return ['error' => 'Failed to quarantine file'];
    }

    /**
     * Calculate file hash for integrity checking
     */
    public function calculateFileHash($filepath) {
        return [
            'md5' => md5_file($filepath),
            'sha256' => hash_file('sha256', $filepath)
        ];
    }
}
