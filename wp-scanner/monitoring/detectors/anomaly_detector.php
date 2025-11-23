<?php
/**
 * Anomaly Detection System
 *
 * Detects unusual patterns and behaviors in WordPress that may indicate compromise
 */

namespace WPScanner\Monitoring\Detectors;

class AnomalyDetector {

    private $db;
    private $wp_root;

    public function __construct($wpdb, $wp_root) {
        $this->db = $wpdb;
        $this->wp_root = rtrim($wp_root, '/');
    }

    /**
     * Detect spam content in posts
     */
    public function detectSpamContent() {
        $spam_indicators = [
            'hidden_links' => '/<a[^>]*style=["\']display:\s*none/i',
            'hidden_divs' => '/<div[^>]*style=["\']display:\s*none[^>]*>.*?<a/is',
            'tiny_text' => '/font-size:\s*0|font-size:\s*1px/i',
            'white_text' => '/color:\s*#fff|color:\s*white/i',
            'iframe_injection' => '/<iframe[^>]*src=/i',
            'javascript_redirect' => '/window\.location|document\.location/i',
            'base64_images' => '/src=["\']data:image\/[^;]+;base64,/i'
        ];

        $results = [];

        foreach ($spam_indicators as $type => $pattern) {
            $query = $this->db->prepare("
                SELECT ID, post_title, post_content, post_date, post_modified
                FROM {$this->db->prefix}posts
                WHERE post_content REGEXP %s
                AND post_status = 'publish'
                LIMIT 50
            ", $pattern);

            $matches = $this->db->get_results($query);

            if (!empty($matches)) {
                $results[$type] = [
                    'count' => count($matches),
                    'posts' => $matches,
                    'severity' => 'HIGH'
                ];
            }
        }

        return $results;
    }

    /**
     * Detect post count jumps/spikes
     */
    public function detectPostCountJumps($threshold = 10, $days = 30) {
        // Get daily post counts
        $query = "
            SELECT DATE(post_date) as date, COUNT(*) as count
            FROM {$this->db->prefix}posts
            WHERE post_status = 'publish'
            AND post_date >= DATE_SUB(NOW(), INTERVAL {$days} DAY)
            GROUP BY DATE(post_date)
            ORDER BY date ASC
        ";

        $daily_counts = $this->db->get_results($query);

        if (count($daily_counts) < 2) {
            return ['insufficient_data' => true];
        }

        // Calculate baseline average
        $counts = array_column($daily_counts, 'count');
        $average = array_sum($counts) / count($counts);
        $stddev = $this->calculateStdDev($counts, $average);

        $spikes = [];

        foreach ($daily_counts as $day) {
            // Detect if count is significantly above average
            $z_score = ($stddev > 0) ? ($day->count - $average) / $stddev : 0;

            if ($day->count > ($average + ($threshold * $stddev)) || $z_score > 3) {
                $spikes[] = [
                    'date' => $day->date,
                    'count' => $day->count,
                    'average' => round($average, 2),
                    'deviation' => round($day->count - $average, 2),
                    'z_score' => round($z_score, 2),
                    'severity' => $z_score > 5 ? 'CRITICAL' : 'HIGH'
                ];
            }
        }

        return [
            'spikes_detected' => !empty($spikes),
            'total_spikes' => count($spikes),
            'average_daily_posts' => round($average, 2),
            'std_deviation' => round($stddev, 2),
            'spikes' => $spikes
        ];
    }

    /**
     * Detect unusual user activity
     */
    public function detectUnusualUserActivity() {
        $results = [];

        // Check for recently created admin accounts
        $recent_admins = $this->db->get_results("
            SELECT u.ID, u.user_login, u.user_email, u.user_registered
            FROM {$this->db->prefix}users u
            INNER JOIN {$this->db->prefix}usermeta um ON u.ID = um.user_id
            WHERE um.meta_key = '{$this->db->prefix}capabilities'
            AND um.meta_value LIKE '%administrator%'
            AND u.user_registered >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");

        if (!empty($recent_admins)) {
            $results['recent_admin_accounts'] = [
                'count' => count($recent_admins),
                'accounts' => $recent_admins,
                'severity' => 'HIGH'
            ];
        }

        // Check for users with suspicious usernames
        $suspicious_usernames = ['admin', 'administrator', 'root', 'test', 'demo', 'guest'];
        $placeholders = implode(',', array_fill(0, count($suspicious_usernames), '%s'));

        $suspicious_users = $this->db->get_results(
            $this->db->prepare("
                SELECT ID, user_login, user_email, user_registered
                FROM {$this->db->prefix}users
                WHERE user_login IN ($placeholders)
            ", $suspicious_usernames)
        );

        if (!empty($suspicious_users)) {
            $results['suspicious_usernames'] = [
                'count' => count($suspicious_users),
                'users' => $suspicious_users,
                'severity' => 'MEDIUM'
            ];
        }

        // Check for multiple failed login attempts
        // This would require integration with a login logging system

        return $results;
    }

    /**
     * Detect OAuth/JSON credential exposure
     */
    public function detectOAuthExposure() {
        $results = [];

        // Patterns to look for
        $oauth_patterns = [
            'access_token' => '/"access_token"\s*:\s*"[^"]+"/i',
            'refresh_token' => '/"refresh_token"\s*:\s*"[^"]+"/i',
            'client_secret' => '/"client_secret"\s*:\s*"[^"]+"/i',
            'api_key' => '/"api_key"\s*:\s*"[^"]+"/i',
            'private_key' => '/"private_key"\s*:\s*"-----BEGIN/i'
        ];

        // Check posts
        foreach ($oauth_patterns as $type => $pattern) {
            $query = $this->db->prepare("
                SELECT ID, post_title, post_date
                FROM {$this->db->prefix}posts
                WHERE post_content REGEXP %s
                LIMIT 20
            ", $pattern);

            $matches = $this->db->get_results($query);

            if (!empty($matches)) {
                $results['posts'][$type] = [
                    'count' => count($matches),
                    'posts' => $matches,
                    'severity' => 'CRITICAL'
                ];
            }
        }

        // Check options table
        foreach ($oauth_patterns as $type => $pattern) {
            $query = $this->db->prepare("
                SELECT option_name, option_value
                FROM {$this->db->prefix}options
                WHERE option_value REGEXP %s
                LIMIT 20
            ", $pattern);

            $matches = $this->db->get_results($query);

            if (!empty($matches)) {
                $results['options'][$type] = [
                    'count' => count($matches),
                    'options' => array_map(function($m) {
                        return ['name' => $m->option_name];
                    }, $matches),
                    'severity' => 'CRITICAL'
                ];
            }
        }

        // Check for exposed JSON files
        $json_files = $this->findJsonFiles();
        $exposed_credentials = [];

        foreach ($json_files as $file) {
            $content = file_get_contents($file);
            foreach ($oauth_patterns as $type => $pattern) {
                if (preg_match($pattern, $content)) {
                    $exposed_credentials[] = [
                        'file' => $file,
                        'type' => $type,
                        'severity' => 'CRITICAL'
                    ];
                }
            }
        }

        if (!empty($exposed_credentials)) {
            $results['files'] = $exposed_credentials;
        }

        return $results;
    }

    /**
     * Detect robots.txt changes
     */
    public function detectRobotsChanges() {
        $robots_path = $this->wp_root . '/robots.txt';
        $baseline_file = WP_SCANNER_DIR . '/data/robots_baseline.txt';

        if (!file_exists($robots_path)) {
            return ['status' => 'no_robots_file'];
        }

        $current_content = file_get_contents($robots_path);

        // If no baseline, create one
        if (!file_exists($baseline_file)) {
            file_put_contents($baseline_file, $current_content);
            return [
                'status' => 'baseline_created',
                'content_hash' => md5($current_content)
            ];
        }

        $baseline_content = file_get_contents($baseline_file);

        if (md5($current_content) === md5($baseline_content)) {
            return [
                'changed' => false,
                'status' => 'unchanged'
            ];
        }

        // Detect what changed
        $baseline_lines = explode("\n", $baseline_content);
        $current_lines = explode("\n", $current_content);

        $added = array_diff($current_lines, $baseline_lines);
        $removed = array_diff($baseline_lines, $current_lines);

        // Check for malicious patterns
        $suspicious_patterns = [
            'disallow_all' => '/Disallow:\s*\/$/i',
            'unusual_user_agent' => '/User-agent:\s*[^G][^o][^o]/i',  // Not Googlebot
            'external_sitemap' => '/Sitemap:\s*http/i'
        ];

        $suspicious_content = [];
        foreach ($suspicious_patterns as $type => $pattern) {
            if (preg_match($pattern, $current_content)) {
                $suspicious_content[] = $type;
            }
        }

        return [
            'changed' => true,
            'baseline_hash' => md5($baseline_content),
            'current_hash' => md5($current_content),
            'added_lines' => array_values($added),
            'removed_lines' => array_values($removed),
            'suspicious_patterns' => $suspicious_content,
            'severity' => !empty($suspicious_content) ? 'HIGH' : 'MEDIUM',
            'modified' => date('Y-m-d H:i:s', filemtime($robots_path))
        ];
    }

    /**
     * Find JSON files in WordPress installation
     */
    private function findJsonFiles() {
        $json_files = [];
        $search_dirs = [
            $this->wp_root . '/wp-content/uploads',
            $this->wp_root . '/wp-content/plugins'
        ];

        foreach ($search_dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'json') {
                    $json_files[] = $file->getPathname();
                }
            }
        }

        return $json_files;
    }

    /**
     * Calculate standard deviation
     */
    private function calculateStdDev($values, $mean) {
        $variance = 0.0;
        foreach ($values as $value) {
            $variance += pow($value - $mean, 2);
        }
        return sqrt($variance / count($values));
    }

    /**
     * Run full anomaly detection
     */
    public function runFullDetection() {
        return [
            'spam_content' => $this->detectSpamContent(),
            'post_count_jumps' => $this->detectPostCountJumps(),
            'user_activity' => $this->detectUnusualUserActivity(),
            'oauth_exposure' => $this->detectOAuthExposure(),
            'robots_changes' => $this->detectRobotsChanges(),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
