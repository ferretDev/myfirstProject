<?php
/**
 * WordPress Database Scanner
 *
 * Scans WordPress database for malicious content, suspicious patterns,
 * and anomalies that may indicate compromise or malicious activity.
 */

namespace WPScanner\Database\Scanners;

class DatabaseScanner {

    private $db;
    private $patterns;
    private $whitelist;

    public function __construct($wpdb, $patterns = [], $whitelist = []) {
        $this->db = $wpdb;
        $this->patterns = $patterns;
        $this->whitelist = $whitelist;
    }

    /**
     * Scan all posts for suspicious content
     */
    public function scanPosts() {
        $results = [
            'spam_content' => [],
            'suspicious_links' => [],
            'obfuscated_code' => [],
            'post_count_anomalies' => []
        ];

        // Detect spam content patterns
        $spam_patterns = [
            'pharma' => '/(viagra|cialis|pharmacy|pills)/i',
            'gambling' => '/(casino|poker|lottery|gambling)/i',
            'adult' => '/(porn|xxx|adult)/i',
            'base64' => '/eval\s*\(\s*base64_decode/i',
            'hidden_iframes' => '/<iframe[^>]*display:\s*none/i'
        ];

        foreach ($spam_patterns as $type => $pattern) {
            $suspicious_posts = $this->scanPostContent($pattern, $type);
            if (!empty($suspicious_posts)) {
                $results['spam_content'][$type] = $suspicious_posts;
            }
        }

        return $results;
    }

    /**
     * Detect unusual post count jumps
     */
    public function detectPostCountAnomalies($threshold = 50) {
        $query = "
            SELECT DATE(post_date) as date, COUNT(*) as count
            FROM {$this->db->prefix}posts
            WHERE post_status = 'publish'
            GROUP BY DATE(post_date)
            ORDER BY date DESC
            LIMIT 30
        ";

        $daily_counts = $this->db->get_results($query);
        $anomalies = [];

        for ($i = 1; $i < count($daily_counts); $i++) {
            $current = $daily_counts[$i-1]->count;
            $previous = $daily_counts[$i]->count;

            if ($previous > 0 && ($current / $previous) > $threshold) {
                $anomalies[] = [
                    'date' => $daily_counts[$i-1]->date,
                    'count' => $current,
                    'previous_avg' => $previous,
                    'spike_ratio' => round($current / $previous, 2)
                ];
            }
        }

        return $anomalies;
    }

    /**
     * Scan user roles for suspicious modifications
     */
    public function scanUserRoles() {
        $suspicious_users = [];

        // Check for users with admin capabilities
        $users = $this->db->get_results("
            SELECT ID, user_login, user_email, user_registered
            FROM {$this->db->prefix}users
        ");

        foreach ($users as $user) {
            $user_meta = get_userdata($user->ID);

            if ($user_meta && $user_meta->has_cap('administrator')) {
                // Check if admin was created recently
                $created = strtotime($user->user_registered);
                $week_ago = strtotime('-7 days');

                if ($created > $week_ago) {
                    $suspicious_users[] = [
                        'id' => $user->ID,
                        'login' => $user->user_login,
                        'email' => $user->user_email,
                        'registered' => $user->user_registered,
                        'reason' => 'Recently created admin account'
                    ];
                }
            }
        }

        return $suspicious_users;
    }

    /**
     * Scan options table for malicious modifications
     */
    public function scanOptions() {
        $critical_options = [
            'siteurl',
            'home',
            'admin_email',
            'users_can_register',
            'default_role',
            'active_plugins',
            'template',
            'stylesheet'
        ];

        $suspicious = [];

        foreach ($critical_options as $option) {
            $value = get_option($option);

            // Check for suspicious patterns
            if ($this->containsSuspiciousPatterns($value)) {
                $suspicious[] = [
                    'option' => $option,
                    'value' => $value,
                    'reason' => 'Contains suspicious patterns'
                ];
            }
        }

        return $suspicious;
    }

    /**
     * Scan for unauthorized database tables
     */
    public function scanUnauthorizedTables() {
        $all_tables = $this->db->get_results("SHOW TABLES", ARRAY_N);
        $wp_prefix = $this->db->prefix;

        $standard_tables = [
            'commentmeta', 'comments', 'links', 'options',
            'postmeta', 'posts', 'terms', 'term_relationships',
            'term_taxonomy', 'usermeta', 'users'
        ];

        $suspicious_tables = [];

        foreach ($all_tables as $table) {
            $table_name = $table[0];

            // Skip if not a WP table
            if (strpos($table_name, $wp_prefix) !== 0) {
                continue;
            }

            $short_name = str_replace($wp_prefix, '', $table_name);

            // Check if it's not a standard WP table
            if (!in_array($short_name, $standard_tables) &&
                !in_array($short_name, $this->whitelist)) {
                $suspicious_tables[] = $table_name;
            }
        }

        return $suspicious_tables;
    }

    /**
     * Pattern-based content scanning
     */
    private function scanPostContent($pattern, $type) {
        $query = $this->db->prepare("
            SELECT ID, post_title, post_content, post_date
            FROM {$this->db->prefix}posts
            WHERE post_content REGEXP %s
            LIMIT 100
        ", $pattern);

        return $this->db->get_results($query);
    }

    /**
     * Check if content contains suspicious patterns
     */
    private function containsSuspiciousPatterns($content) {
        $suspicious_patterns = [
            '/eval\s*\(/i',
            '/base64_decode/i',
            '/gzinflate/i',
            '/str_rot13/i',
            '/system\s*\(/i',
            '/exec\s*\(/i',
            '/shell_exec/i',
            '/assert\s*\(/i'
        ];

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Full database scan
     */
    public function runFullScan() {
        return [
            'posts' => $this->scanPosts(),
            'post_anomalies' => $this->detectPostCountAnomalies(),
            'users' => $this->scanUserRoles(),
            'options' => $this->scanOptions(),
            'tables' => $this->scanUnauthorizedTables(),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
