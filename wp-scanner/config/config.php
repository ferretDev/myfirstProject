<?php
/**
 * WordPress Scanner Configuration
 */

// Define scanner directory
if (!defined('WP_SCANNER_DIR')) {
    define('WP_SCANNER_DIR', dirname(__DIR__));
}

return [
    // WordPress installation path
    'wp_root' => ABSPATH ?? '/var/www/html',

    // Scanning options
    'scans' => [
        'database' => true,
        'filesystem' => true,
        'permissions' => true,
        'htaccess' => true,
        'anomalies' => true,
        'file_watching' => true,
    ],

    // Auto-remediation settings
    'auto_quarantine' => false,  // Automatically quarantine suspicious files
    'auto_fix_permissions' => false,  // Automatically fix file permissions

    // Alerting
    'alerts' => [
        'email' => true,
        'email_to' => 'admin@example.com',
        'slack' => false,
        'slack_webhook' => '',
    ],

    // Thresholds
    'thresholds' => [
        'post_spike_multiplier' => 10,  // Alert if posts increase by this multiplier
        'post_spike_days' => 30,  // Days to analyze for spikes
        'recent_admin_days' => 7,  // Alert for admins created in last N days
    ],

    // Whitelist - files/patterns to ignore
    'whitelist' => [
        'files' => [
            // Add specific files to whitelist
            // '/path/to/file.php',
        ],
        'patterns' => [
            // Add patterns to whitelist
            // '*/vendor/*',
            // '*/node_modules/*',
        ],
        'tables' => [
            // Additional DB tables to consider safe
            // 'custom_table_name',
        ],
    ],

    // Directories to exclude from scans
    'exclude_dirs' => [
        'wp-content/cache',
        'wp-content/backups',
        'node_modules',
        'vendor',
    ],

    // File extensions to scan
    'scan_extensions' => [
        'php', 'php3', 'php4', 'php5', 'phtml', 'phps',
        'js', 'html', 'htm',
    ],

    // Quarantine settings
    'quarantine' => [
        'enabled' => true,
        'directory' => WP_SCANNER_DIR . '/quarantine',
        'max_file_size' => 10485760,  // 10MB
    ],

    // Report settings
    'reports' => [
        'output_dir' => WP_SCANNER_DIR . '/reports',
        'format' => ['json', 'html'],
        'retention_days' => 30,  // Keep reports for N days
    ],

    // Data directory
    'data_dir' => WP_SCANNER_DIR . '/data',

    // Logging
    'logging' => [
        'enabled' => true,
        'file' => WP_SCANNER_DIR . '/logs/scanner.log',
        'level' => 'INFO',  // DEBUG, INFO, WARNING, ERROR
    ],

    // Performance settings
    'performance' => [
        'max_execution_time' => 300,  // 5 minutes
        'memory_limit' => '256M',
        'chunk_size' => 1000,  // Files to process at once
    ],

    // Monitoring intervals (for scheduled scans)
    'schedule' => [
        'full_scan' => 'weekly',  // daily, weekly, monthly
        'quick_scan' => 'daily',
        'file_watch' => 'hourly',
    ],

    // Integration settings
    'integrations' => [
        'wordfence' => false,
        'sucuri' => false,
        'cloudflare' => false,
    ],
];
