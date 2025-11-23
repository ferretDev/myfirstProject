<?php
/**
 * Database Change Detection & Analysis
 *
 * Monitors WordPress database for changes and anomalies
 */

namespace WPScanner\Database\Analyzers;

class ChangeDetector {

    private $db;
    private $baseline_file;

    public function __construct($wpdb, $baseline_path = null) {
        $this->db = $wpdb;
        $this->baseline_file = $baseline_path ?: WP_SCANNER_DIR . '/data/baseline.json';
    }

    /**
     * Create baseline snapshot of database state
     */
    public function createBaseline() {
        $baseline = [
            'timestamp' => time(),
            'post_count' => $this->getPostCount(),
            'user_count' => $this->getUserCount(),
            'admin_count' => $this->getAdminCount(),
            'option_checksums' => $this->getOptionChecksums(),
            'table_list' => $this->getTableList(),
            'plugin_list' => $this->getActivePlugins(),
            'theme' => $this->getActiveTheme(),
            'robots_content' => $this->getRobotsContent()
        ];

        file_put_contents($this->baseline_file, json_encode($baseline, JSON_PRETTY_PRINT));
        return $baseline;
    }

    /**
     * Compare current state to baseline
     */
    public function detectChanges() {
        if (!file_exists($this->baseline_file)) {
            return ['error' => 'No baseline found. Create one first.'];
        }

        $baseline = json_decode(file_get_contents($this->baseline_file), true);
        $current = $this->getCurrentState();

        $changes = [];

        // Post count changes
        if ($current['post_count'] > $baseline['post_count']) {
            $changes['post_count_increase'] = [
                'baseline' => $baseline['post_count'],
                'current' => $current['post_count'],
                'difference' => $current['post_count'] - $baseline['post_count']
            ];
        }

        // User count changes
        if ($current['user_count'] > $baseline['user_count']) {
            $changes['user_count_increase'] = [
                'baseline' => $baseline['user_count'],
                'current' => $current['user_count'],
                'difference' => $current['user_count'] - $baseline['user_count']
            ];
        }

        // Admin count changes (critical!)
        if ($current['admin_count'] != $baseline['admin_count']) {
            $changes['admin_count_change'] = [
                'baseline' => $baseline['admin_count'],
                'current' => $current['admin_count'],
                'severity' => 'HIGH'
            ];
        }

        // New tables
        $new_tables = array_diff($current['table_list'], $baseline['table_list']);
        if (!empty($new_tables)) {
            $changes['new_tables'] = $new_tables;
        }

        // Plugin changes
        $new_plugins = array_diff($current['plugin_list'], $baseline['plugin_list']);
        $removed_plugins = array_diff($baseline['plugin_list'], $current['plugin_list']);

        if (!empty($new_plugins)) {
            $changes['new_plugins'] = $new_plugins;
        }
        if (!empty($removed_plugins)) {
            $changes['removed_plugins'] = $removed_plugins;
        }

        // Theme change
        if ($current['theme'] !== $baseline['theme']) {
            $changes['theme_change'] = [
                'from' => $baseline['theme'],
                'to' => $current['theme']
            ];
        }

        // Robots.txt changes
        if ($current['robots_content'] !== $baseline['robots_content']) {
            $changes['robots_txt_modified'] = [
                'baseline_hash' => md5($baseline['robots_content']),
                'current_hash' => md5($current['robots_content'])
            ];
        }

        // Critical option changes
        foreach ($baseline['option_checksums'] as $option => $checksum) {
            if (isset($current['option_checksums'][$option]) &&
                $current['option_checksums'][$option] !== $checksum) {
                $changes['option_modified'][$option] = [
                    'baseline_hash' => $checksum,
                    'current_hash' => $current['option_checksums'][$option]
                ];
            }
        }

        return [
            'changes_detected' => !empty($changes),
            'change_count' => count($changes),
            'changes' => $changes,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Get current database state
     */
    private function getCurrentState() {
        return [
            'post_count' => $this->getPostCount(),
            'user_count' => $this->getUserCount(),
            'admin_count' => $this->getAdminCount(),
            'option_checksums' => $this->getOptionChecksums(),
            'table_list' => $this->getTableList(),
            'plugin_list' => $this->getActivePlugins(),
            'theme' => $this->getActiveTheme(),
            'robots_content' => $this->getRobotsContent()
        ];
    }

    private function getPostCount() {
        return (int) $this->db->get_var("SELECT COUNT(*) FROM {$this->db->prefix}posts WHERE post_status = 'publish'");
    }

    private function getUserCount() {
        return (int) $this->db->get_var("SELECT COUNT(*) FROM {$this->db->prefix}users");
    }

    private function getAdminCount() {
        global $wpdb;
        return (int) $wpdb->get_var("
            SELECT COUNT(DISTINCT user_id)
            FROM {$wpdb->prefix}usermeta
            WHERE meta_key = '{$wpdb->prefix}capabilities'
            AND meta_value LIKE '%administrator%'
        ");
    }

    private function getOptionChecksums() {
        $critical_options = [
            'siteurl', 'home', 'admin_email', 'users_can_register',
            'default_role', 'active_plugins', 'template', 'stylesheet'
        ];

        $checksums = [];
        foreach ($critical_options as $option) {
            $value = get_option($option);
            $checksums[$option] = md5(serialize($value));
        }

        return $checksums;
    }

    private function getTableList() {
        $tables = $this->db->get_results("SHOW TABLES", ARRAY_N);
        return array_map(function($t) { return $t[0]; }, $tables);
    }

    private function getActivePlugins() {
        return get_option('active_plugins', []);
    }

    private function getActiveTheme() {
        return get_option('stylesheet');
    }

    private function getRobotsContent() {
        $robots_path = ABSPATH . 'robots.txt';
        return file_exists($robots_path) ? file_get_contents($robots_path) : '';
    }

    /**
     * Detect post count spikes
     */
    public function detectPostSpikes($days = 30, $spike_threshold = 3) {
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
            return [];
        }

        // Calculate average
        $total = array_sum(array_column($daily_counts, 'count'));
        $avg = $total / count($daily_counts);

        $spikes = [];
        foreach ($daily_counts as $day) {
            if ($day->count > ($avg * $spike_threshold)) {
                $spikes[] = [
                    'date' => $day->date,
                    'count' => $day->count,
                    'average' => round($avg, 2),
                    'multiplier' => round($day->count / $avg, 2),
                    'severity' => $day->count > ($avg * 10) ? 'CRITICAL' : 'WARNING'
                ];
            }
        }

        return $spikes;
    }
}
