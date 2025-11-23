<?php
/**
 * Security Hardening Module
 *
 * Applies WordPress security best practices and hardening measures
 */

namespace WPScanner\Core;

use WPScanner\Utils\Security;

class SecurityHardening {

    private $wp_root;
    private $results = [];

    public function __construct($wp_root) {
        $this->wp_root = rtrim($wp_root, '/');
    }

    /**
     * Run all hardening checks
     */
    public function auditSecurity() {
        $this->results = [
            'wp_config' => $this->auditWpConfig(),
            'file_permissions' => $this->auditCriticalPermissions(),
            'htaccess' => $this->auditHtaccessSecurity(),
            'directory_listing' => $this->checkDirectoryListing(),
            'xmlrpc' => $this->checkXmlRpc(),
            'file_editing' => $this->checkFileEditing(),
            'debug_mode' => $this->checkDebugMode(),
            'database_prefix' => $this->checkDatabasePrefix(),
            'admin_username' => $this->checkAdminUsername(),
        ];

        return $this->results;
    }

    /**
     * Audit wp-config.php security
     */
    private function auditWpConfig() {
        $wp_config = $this->wp_root . '/wp-config.php';
        $issues = [];
        $recommendations = [];

        if (!file_exists($wp_config)) {
            return ['error' => 'wp-config.php not found'];
        }

        $content = file_get_contents($wp_config);

        // Check file permissions
        $perms = substr(sprintf('%o', fileperms($wp_config)), -4);
        if ($perms !== '0440' && $perms !== '0400') {
            $issues[] = [
                'issue' => 'wp-config.php permissions too permissive',
                'current' => $perms,
                'recommended' => '0440 or 0400',
                'severity' => 'HIGH'
            ];
            $recommendations[] = 'chmod 0440 wp-config.php';
        }

        // Check for security keys
        $security_keys = [
            'AUTH_KEY',
            'SECURE_AUTH_KEY',
            'LOGGED_IN_KEY',
            'NONCE_KEY',
            'AUTH_SALT',
            'SECURE_AUTH_SALT',
            'LOGGED_IN_SALT',
            'NONCE_SALT',
        ];

        foreach ($security_keys as $key) {
            if (!preg_match("/define\s*\(\s*['\"]" . $key . "['\"]/", $content)) {
                $issues[] = [
                    'issue' => "Security key '{$key}' not defined",
                    'severity' => 'HIGH'
                ];
            } elseif (preg_match("/define\s*\(\s*['\"]" . $key . "['\"]\s*,\s*['\"]\s*['\"]\)/", $content)) {
                $issues[] = [
                    'issue' => "Security key '{$key}' is empty",
                    'severity' => 'CRITICAL'
                ];
            }
        }

        if (!empty($issues)) {
            $recommendations[] = 'Generate new security keys at https://api.wordpress.org/secret-key/1.1/salt/';
        }

        // Check for DISALLOW_FILE_EDIT
        if (!preg_match("/define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true\s*\)/i", $content)) {
            $issues[] = [
                'issue' => 'File editing not disabled in wp-config.php',
                'severity' => 'MEDIUM'
            ];
            $recommendations[] = "Add: define('DISALLOW_FILE_EDIT', true);";
        }

        // Check for WP_DEBUG in production
        if (preg_match("/define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)/i", $content)) {
            $issues[] = [
                'issue' => 'WP_DEBUG is enabled (should be false in production)',
                'severity' => 'MEDIUM'
            ];
            $recommendations[] = "Set: define('WP_DEBUG', false);";
        }

        // Check for FORCE_SSL_ADMIN
        if (!preg_match("/define\s*\(\s*['\"]FORCE_SSL_ADMIN['\"]\s*,\s*true\s*\)/i", $content)) {
            $issues[] = [
                'issue' => 'SSL not enforced for admin area',
                'severity' => 'MEDIUM'
            ];
            $recommendations[] = "Add: define('FORCE_SSL_ADMIN', true);";
        }

        return [
            'issues' => $issues,
            'recommendations' => $recommendations,
            'total_issues' => count($issues)
        ];
    }

    /**
     * Check critical file permissions
     */
    private function auditCriticalPermissions() {
        $critical_files = [
            'wp-config.php' => '0440',
            '.htaccess' => '0644',
            'index.php' => '0644',
        ];

        $issues = [];

        foreach ($critical_files as $file => $recommended) {
            $filepath = $this->wp_root . '/' . $file;

            if (!file_exists($filepath)) {
                continue;
            }

            $current = substr(sprintf('%o', fileperms($filepath)), -4);

            if ($current !== $recommended) {
                $issues[] = [
                    'file' => $file,
                    'current' => $current,
                    'recommended' => $recommended,
                    'severity' => $file === 'wp-config.php' ? 'HIGH' : 'MEDIUM'
                ];
            }
        }

        return [
            'issues' => $issues,
            'total_issues' => count($issues)
        ];
    }

    /**
     * Audit .htaccess security
     */
    private function auditHtaccessSecurity() {
        $htaccess = $this->wp_root . '/.htaccess';
        $missing_rules = [];

        if (!file_exists($htaccess)) {
            return [
                'warning' => '.htaccess file not found',
                'recommendation' => 'Create .htaccess with security rules'
            ];
        }

        $content = file_get_contents($htaccess);

        // Check for important security rules
        $security_rules = [
            'directory_browsing' => 'Options -Indexes',
            'wp_config_protection' => '<Files wp-config.php>',
            'htaccess_protection' => '<Files .htaccess>',
        ];

        foreach ($security_rules as $rule_name => $rule_pattern) {
            if (stripos($content, $rule_pattern) === false) {
                $missing_rules[] = $rule_name;
            }
        }

        return [
            'missing_rules' => $missing_rules,
            'total_missing' => count($missing_rules),
            'recommendation' => !empty($missing_rules) ? 'Add missing security rules to .htaccess' : null
        ];
    }

    /**
     * Check for directory listing vulnerability
     */
    private function checkDirectoryListing() {
        $test_dirs = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
        ];

        $vulnerable = [];

        foreach ($test_dirs as $dir) {
            $full_path = $this->wp_root . $dir;

            if (!is_dir($full_path)) {
                continue;
            }

            // Check for index.php or .htaccess
            $has_index = file_exists($full_path . 'index.php') ||
                        file_exists($full_path . 'index.html');

            if (!$has_index) {
                $vulnerable[] = $dir;
            }
        }

        return [
            'vulnerable_directories' => $vulnerable,
            'total_vulnerable' => count($vulnerable),
            'severity' => !empty($vulnerable) ? 'MEDIUM' : 'NONE'
        ];
    }

    /**
     * Check XML-RPC status
     */
    private function checkXmlRpc() {
        $xmlrpc_file = $this->wp_root . '/xmlrpc.php';

        if (!file_exists($xmlrpc_file)) {
            return [
                'status' => 'Not found',
                'severity' => 'NONE'
            ];
        }

        return [
            'status' => 'Enabled',
            'severity' => 'MEDIUM',
            'recommendation' => 'Disable XML-RPC if not needed (common brute-force target)',
            'action' => 'Block XML-RPC via .htaccess or plugin'
        ];
    }

    /**
     * Check file editing status
     */
    private function checkFileEditing() {
        $wp_config = $this->wp_root . '/wp-config.php';

        if (!file_exists($wp_config)) {
            return ['error' => 'wp-config.php not found'];
        }

        $content = file_get_contents($wp_config);

        $disabled = preg_match("/define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true\s*\)/i", $content);

        return [
            'status' => $disabled ? 'Disabled' : 'Enabled',
            'severity' => $disabled ? 'NONE' : 'MEDIUM',
            'recommendation' => $disabled ? null : "Add define('DISALLOW_FILE_EDIT', true); to wp-config.php"
        ];
    }

    /**
     * Check debug mode
     */
    private function checkDebugMode() {
        $wp_config = $this->wp_root . '/wp-config.php';

        if (!file_exists($wp_config)) {
            return ['error' => 'wp-config.php not found'];
        }

        $content = file_get_contents($wp_config);

        $debug_enabled = preg_match("/define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)/i", $content);

        return [
            'status' => $debug_enabled ? 'Enabled' : 'Disabled',
            'severity' => $debug_enabled ? 'HIGH' : 'NONE',
            'recommendation' => $debug_enabled ? "Set WP_DEBUG to false in production" : null
        ];
    }

    /**
     * Check database table prefix
     */
    private function checkDatabasePrefix() {
        $wp_config = $this->wp_root . '/wp-config.php';

        if (!file_exists($wp_config)) {
            return ['error' => 'wp-config.php not found'];
        }

        $content = file_get_contents($wp_config);

        if (preg_match("/\\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]/", $content, $matches)) {
            $prefix = $matches[1];

            $is_default = ($prefix === 'wp_');

            return [
                'prefix' => $prefix,
                'is_default' => $is_default,
                'severity' => $is_default ? 'LOW' : 'NONE',
                'recommendation' => $is_default ? 'Consider changing database prefix from default "wp_"' : null
            ];
        }

        return ['error' => 'Could not determine table prefix'];
    }

    /**
     * Check for default admin username
     */
    private function checkAdminUsername() {
        global $wpdb;

        if (!isset($wpdb)) {
            return ['error' => 'Database connection not available'];
        }

        $admin_user = $wpdb->get_var("
            SELECT user_login FROM {$wpdb->prefix}users WHERE ID = 1
        ");

        $is_default = ($admin_user === 'admin');

        return [
            'admin_username' => $admin_user,
            'is_default' => $is_default,
            'severity' => $is_default ? 'MEDIUM' : 'NONE',
            'recommendation' => $is_default ? 'Change default "admin" username' : null
        ];
    }

    /**
     * Apply hardening: Create index.php files
     */
    public function createIndexFiles($auto_confirm = false) {
        $directories = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
        ];

        if (!Security::confirmDestructive(
            "This will create index.php files in sensitive directories to prevent directory listing.",
            $auto_confirm
        )) {
            return ['cancelled' => true];
        }

        $created = [];
        $index_content = "<?php\n// Silence is golden.\n";

        foreach ($directories as $dir) {
            $full_path = $this->wp_root . $dir;

            if (!is_dir($full_path)) {
                continue;
            }

            $index_file = $full_path . 'index.php';

            if (!file_exists($index_file)) {
                if (file_put_contents($index_file, $index_content)) {
                    $created[] = $dir . 'index.php';
                }
            }
        }

        return [
            'created' => $created,
            'total_created' => count($created)
        ];
    }

    /**
     * Generate .htaccess security rules
     */
    public function generateHtaccessRules() {
        return <<<HTACCESS
# WordPress Security Scanner - Security Rules

# Disable directory browsing
Options -Indexes

# Protect wp-config.php
<Files wp-config.php>
    order allow,deny
    deny from all
</Files>

# Protect .htaccess
<Files .htaccess>
    order allow,deny
    deny from all
</Files>

# Protect wp-includes
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteRule ^wp-admin/includes/ - [F,L]
    RewriteRule !^wp-includes/ - [S=3]
    RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
    RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
    RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>

# Block access to sensitive files
<FilesMatch "^(wp-config\.php|\.htaccess|\.htpasswd|error_log|php\.ini|\.user\.ini)">
    order allow,deny
    deny from all
</FilesMatch>

# Disable PHP execution in uploads
<Directory "wp-content/uploads">
    <Files *.php>
        deny from all
    </Files>
</Directory>

# Limit file uploads
<FilesMatch "\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|htm|html|shtml|sh|cgi)$">
    deny from all
</FilesMatch>

# Block XML-RPC (if not needed)
#<Files xmlrpc.php>
#    order deny,allow
#    deny from all
#</Files>

# Protect against script injection
<IfModule mod_rewrite.c>
    RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]
    RewriteCond %{QUERY_STRING} GLOBALS(=|[|%[0-9A-Z]{0,2}) [OR]
    RewriteCond %{QUERY_STRING} _REQUEST(=|[|%[0-9A-Z]{0,2})
    RewriteRule ^(.*)$ index.php [F,L]
</IfModule>

HTACCESS;
    }

    /**
     * Generate hardening report
     */
    public function generateReport() {
        $audit = $this->auditSecurity();

        $total_issues = 0;
        foreach ($audit as $category => $data) {
            if (isset($data['total_issues'])) {
                $total_issues += $data['total_issues'];
            }
        }

        return [
            'summary' => [
                'total_issues' => $total_issues,
                'categories_checked' => count($audit),
                'security_score' => max(0, 100 - ($total_issues * 5))
            ],
            'audit_results' => $audit,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
