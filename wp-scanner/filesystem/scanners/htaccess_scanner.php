<?php
/**
 * .htaccess Security Scanner
 *
 * Scans and validates .htaccess files for malicious modifications and misconfigurations
 */

namespace WPScanner\Filesystem\Scanners;

class HtaccessScanner {

    private $wp_root;
    private $htaccess_path;

    public function __construct($wp_root) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->htaccess_path = $this->wp_root . '/.htaccess';
    }

    /**
     * Scan .htaccess file for malicious content
     */
    public function scanHtaccess() {
        if (!file_exists($this->htaccess_path)) {
            return ['error' => '.htaccess file not found'];
        }

        $content = file_get_contents($this->htaccess_path);
        $lines = explode("\n", $content);

        $results = [
            'suspicious_redirects' => [],
            'suspicious_rewrites' => [],
            'php_injections' => [],
            'auto_prepend_append' => [],
            'base64_content' => [],
            'external_references' => [],
            'allow_override_issues' => []
        ];

        foreach ($lines as $line_num => $line) {
            $line = trim($line);

            // Check for suspicious redirects
            if (preg_match('/^Redirect(Match)?\s+/i', $line)) {
                if (preg_match('/(http:\/\/|https:\/\/)([^\/]+)/', $line, $matches)) {
                    $domain = $matches[2];
                    // Check if redirecting to external domain
                    if (!$this->isLocalDomain($domain)) {
                        $results['suspicious_redirects'][] = [
                            'line' => $line_num + 1,
                            'content' => $line,
                            'domain' => $domain,
                            'severity' => 'HIGH'
                        ];
                    }
                }
            }

            // Check for suspicious rewrites
            if (preg_match('/^RewriteRule/i', $line)) {
                // Check for external rewrites
                if (preg_match('/(http:\/\/|https:\/\/)([^\/\s\]]+)/', $line, $matches)) {
                    $domain = $matches[2];
                    if (!$this->isLocalDomain($domain)) {
                        $results['suspicious_rewrites'][] = [
                            'line' => $line_num + 1,
                            'content' => $line,
                            'domain' => $domain,
                            'severity' => 'CRITICAL'
                        ];
                    }
                }

                // Check for base64 in rewrite rules
                if (preg_match('/base64/i', $line)) {
                    $results['base64_content'][] = [
                        'line' => $line_num + 1,
                        'content' => $line,
                        'severity' => 'HIGH'
                    ];
                }
            }

            // Check for PHP injection attempts
            if (preg_match('/php_value|php_flag/i', $line)) {
                // auto_prepend_file and auto_append_file are particularly dangerous
                if (preg_match('/auto_prepend_file|auto_append_file/i', $line)) {
                    $results['auto_prepend_append'][] = [
                        'line' => $line_num + 1,
                        'content' => $line,
                        'severity' => 'CRITICAL'
                    ];
                } else {
                    $results['php_injections'][] = [
                        'line' => $line_num + 1,
                        'content' => $line,
                        'severity' => 'MEDIUM'
                    ];
                }
            }

            // Check for base64 encoded content
            if (preg_match('/[A-Za-z0-9+\/]{100,}={0,2}/', $line)) {
                $results['base64_content'][] = [
                    'line' => $line_num + 1,
                    'content' => $line,
                    'severity' => 'HIGH'
                ];
            }

            // Check for external file references
            if (preg_match('/(http:\/\/|https:\/\/)([^\/\s]+)/', $line, $matches)) {
                $domain = $matches[2];
                if (!$this->isLocalDomain($domain) && !$this->isKnownGoodDomain($domain)) {
                    $results['external_references'][] = [
                        'line' => $line_num + 1,
                        'content' => $line,
                        'domain' => $domain,
                        'severity' => 'MEDIUM'
                    ];
                }
            }
        }

        // Check for overall integrity
        $integrity = $this->checkIntegrity($content);

        return [
            'file_path' => $this->htaccess_path,
            'total_lines' => count($lines),
            'issues_found' => $this->countIssues($results),
            'results' => $results,
            'integrity' => $integrity,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Check .htaccess integrity
     */
    private function checkIntegrity($content) {
        return [
            'file_hash' => md5($content),
            'size' => strlen($content),
            'modified' => date('Y-m-d H:i:s', filemtime($this->htaccess_path)),
            'permissions' => substr(sprintf('%o', fileperms($this->htaccess_path)), -4)
        ];
    }

    /**
     * Create baseline of .htaccess
     */
    public function createBaseline() {
        if (!file_exists($this->htaccess_path)) {
            return ['error' => '.htaccess file not found'];
        }

        $content = file_get_contents($this->htaccess_path);
        $baseline = [
            'timestamp' => time(),
            'created' => date('Y-m-d H:i:s'),
            'content_hash' => md5($content),
            'content' => $content,
            'size' => strlen($content),
            'permissions' => substr(sprintf('%o', fileperms($this->htaccess_path)), -4)
        ];

        $baseline_file = WP_SCANNER_DIR . '/data/htaccess_baseline.json';
        file_put_contents($baseline_file, json_encode($baseline, JSON_PRETTY_PRINT));

        return [
            'success' => true,
            'baseline_file' => $baseline_file,
            'content_hash' => $baseline['content_hash']
        ];
    }

    /**
     * Compare current .htaccess to baseline
     */
    public function compareToBaseline() {
        $baseline_file = WP_SCANNER_DIR . '/data/htaccess_baseline.json';

        if (!file_exists($baseline_file)) {
            return ['error' => 'No baseline found. Create one first.'];
        }

        $baseline = json_decode(file_get_contents($baseline_file), true);
        $current_content = file_get_contents($this->htaccess_path);
        $current_hash = md5($current_content);

        if ($current_hash === $baseline['content_hash']) {
            return [
                'changed' => false,
                'message' => '.htaccess file unchanged since baseline'
            ];
        }

        // File has changed - show differences
        $baseline_lines = explode("\n", $baseline['content']);
        $current_lines = explode("\n", $current_content);

        $diff = [
            'added_lines' => [],
            'removed_lines' => [],
            'modified_lines' => []
        ];

        // Simple diff
        $added = array_diff($current_lines, $baseline_lines);
        $removed = array_diff($baseline_lines, $current_lines);

        foreach ($added as $line_num => $line) {
            $diff['added_lines'][] = [
                'line' => $line_num + 1,
                'content' => $line
            ];
        }

        foreach ($removed as $line_num => $line) {
            $diff['removed_lines'][] = [
                'line' => $line_num + 1,
                'content' => $line
            ];
        }

        return [
            'changed' => true,
            'baseline_date' => $baseline['created'],
            'current_hash' => $current_hash,
            'baseline_hash' => $baseline['content_hash'],
            'differences' => $diff,
            'severity' => !empty($diff['added_lines']) ? 'HIGH' : 'MEDIUM'
        ];
    }

    /**
     * Scan all .htaccess files in WordPress installation
     */
    public function scanAllHtaccessFiles() {
        $results = [];
        $htaccess_files = [];

        // Find all .htaccess files
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->wp_root, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getFilename() === '.htaccess') {
                $htaccess_files[] = $file->getPathname();
            }
        }

        foreach ($htaccess_files as $htaccess_file) {
            $temp_scanner = new self($this->wp_root);
            $temp_scanner->htaccess_path = $htaccess_file;
            $results[$htaccess_file] = $temp_scanner->scanHtaccess();
        }

        return [
            'total_files' => count($htaccess_files),
            'scans' => $results
        ];
    }

    /**
     * Check if domain is local
     */
    private function isLocalDomain($domain) {
        $site_url = parse_url(get_site_url(), PHP_URL_HOST);
        return $domain === $site_url || $domain === 'localhost' || $domain === '127.0.0.1';
    }

    /**
     * Check if domain is known good (WordPress.org, etc.)
     */
    private function isKnownGoodDomain($domain) {
        $good_domains = [
            'wordpress.org',
            'api.wordpress.org',
            'downloads.wordpress.org',
            'wp.org'
        ];

        foreach ($good_domains as $good_domain) {
            if (strpos($domain, $good_domain) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Count total issues
     */
    private function countIssues($results) {
        $count = 0;
        foreach ($results as $category => $issues) {
            $count += count($issues);
        }
        return $count;
    }

    /**
     * Generate security recommendations
     */
    public function getRecommendations() {
        return [
            'best_practices' => [
                'Restrict directory browsing: Options -Indexes',
                'Protect wp-config.php: <Files wp-config.php> deny from all',
                'Block access to sensitive files',
                'Enable HTTPS redirection',
                'Set proper file upload restrictions'
            ],
            'security_rules' => [
                '# Protect wp-config.php',
                '<Files wp-config.php>',
                '    order allow,deny',
                '    deny from all',
                '</Files>',
                '',
                '# Disable directory browsing',
                'Options -Indexes',
                '',
                '# Protect .htaccess',
                '<Files .htaccess>',
                '    order allow,deny',
                '    deny from all',
                '</Files>'
            ]
        ];
    }
}
