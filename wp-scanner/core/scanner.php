<?php
/**
 * WordPress Security Scanner - Core
 *
 * Main scanner orchestrator that coordinates all scanning modules
 */

namespace WPScanner\Core;

use WPScanner\Database\Scanners\DatabaseScanner;
use WPScanner\Database\Analyzers\ChangeDetector;
use WPScanner\Filesystem\Scanners\FileScanner;
use WPScanner\Filesystem\Scanners\HtaccessScanner;
use WPScanner\Filesystem\Watchers\FileWatcher;
use WPScanner\Filesystem\Permissions\PermissionChecker;
use WPScanner\Monitoring\Detectors\AnomalyDetector;
use WPScanner\Monitoring\Reports\ReportGenerator;

class Scanner {

    private $config;
    private $wpdb;
    private $wp_root;
    private $results;

    public function __construct($config = []) {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->wp_root = $this->config['wp_root'];
        $this->results = [];

        // Initialize WordPress database connection if available
        if (isset($GLOBALS['wpdb'])) {
            $this->wpdb = $GLOBALS['wpdb'];
        }
    }

    /**
     * Run comprehensive security scan
     */
    public function runFullScan($options = []) {
        $scan_start = microtime(true);

        echo "Starting WordPress Security Scan...\n";
        echo "================================\n\n";

        $this->results = [
            'scan_id' => uniqid('scan_'),
            'started_at' => date('Y-m-d H:i:s'),
            'scans' => []
        ];

        // Database scans
        if ($this->config['scan_database']) {
            echo "Scanning database...\n";
            $this->results['scans']['database'] = $this->scanDatabase();
            echo "✓ Database scan complete\n\n";
        }

        // File system scans
        if ($this->config['scan_filesystem']) {
            echo "Scanning file system...\n";
            $this->results['scans']['filesystem'] = $this->scanFileSystem();
            echo "✓ File system scan complete\n\n";
        }

        // Permission audit
        if ($this->config['scan_permissions']) {
            echo "Auditing file permissions...\n";
            $this->results['scans']['permissions'] = $this->auditPermissions();
            echo "✓ Permission audit complete\n\n";
        }

        // htaccess scan
        if ($this->config['scan_htaccess']) {
            echo "Scanning .htaccess files...\n";
            $this->results['scans']['htaccess'] = $this->scanHtaccess();
            echo "✓ .htaccess scan complete\n\n";
        }

        // Anomaly detection
        if ($this->config['scan_anomalies']) {
            echo "Running anomaly detection...\n";
            $this->results['scans']['anomalies'] = $this->detectAnomalies();
            echo "✓ Anomaly detection complete\n\n";
        }

        // File watching
        if ($this->config['file_watching']) {
            echo "Checking file changes...\n";
            $this->results['scans']['file_changes'] = $this->checkFileChanges();
            echo "✓ File change detection complete\n\n";
        }

        $scan_duration = round(microtime(true) - $scan_start, 2);
        $this->results['completed_at'] = date('Y-m-d H:i:s');
        $this->results['duration_seconds'] = $scan_duration;

        echo "================================\n";
        echo "Scan completed in {$scan_duration}s\n\n";

        // Generate report
        if ($this->config['generate_report']) {
            echo "Generating report...\n";
            $report = $this->generateReport();
            echo "✓ Report generated: {$report['html_report']}\n\n";
            $this->results['report'] = $report;
        }

        return $this->results;
    }

    /**
     * Scan database
     */
    private function scanDatabase() {
        $scanner = new DatabaseScanner($this->wpdb);
        $change_detector = new ChangeDetector($this->wpdb);

        return [
            'full_scan' => $scanner->runFullScan(),
            'changes' => $change_detector->detectChanges(),
            'post_spikes' => $change_detector->detectPostSpikes()
        ];
    }

    /**
     * Scan file system
     */
    private function scanFileSystem() {
        $scanner = new FileScanner($this->wp_root);

        $results = [
            'php_scan' => $scanner->scanPHPFiles(),
            'uploads_scan' => $scanner->scanUploadsDirectory()
        ];

        // Auto-quarantine critical files if enabled
        if ($this->config['auto_quarantine']) {
            if (!empty($results['uploads_scan']['php_files'])) {
                foreach ($results['uploads_scan']['php_files'] as $php_file) {
                    $scanner->quarantineFile($php_file['path']);
                }
            }
        }

        return $results;
    }

    /**
     * Audit permissions
     */
    private function auditPermissions() {
        $checker = new PermissionChecker($this->wp_root);
        return $checker->generateReport();
    }

    /**
     * Scan htaccess files
     */
    private function scanHtaccess() {
        $scanner = new HtaccessScanner($this->wp_root);
        return [
            'main_scan' => $scanner->scanHtaccess(),
            'all_files' => $scanner->scanAllHtaccessFiles(),
            'baseline_check' => $scanner->compareToBaseline()
        ];
    }

    /**
     * Detect anomalies
     */
    private function detectAnomalies() {
        $detector = new AnomalyDetector($this->wpdb, $this->wp_root);
        return $detector->runFullDetection();
    }

    /**
     * Check file changes
     */
    private function checkFileChanges() {
        $watcher = new FileWatcher($this->wp_root);
        return $watcher->detectChanges();
    }

    /**
     * Generate report
     */
    private function generateReport() {
        $generator = new ReportGenerator();
        return $generator->generateSecurityReport($this->results);
    }

    /**
     * Initialize baselines
     */
    public function initializeBaselines() {
        echo "Initializing security baselines...\n";
        echo "===================================\n\n";

        // Database baseline
        echo "Creating database baseline...\n";
        $change_detector = new ChangeDetector($this->wpdb);
        $db_baseline = $change_detector->createBaseline();
        echo "✓ Database baseline created\n\n";

        // File system baseline
        echo "Creating file system baseline...\n";
        $file_watcher = new FileWatcher($this->wp_root);
        $fs_baseline = $file_watcher->createSnapshot();
        echo "✓ File system baseline created ({$fs_baseline['files_tracked']} files)\n\n";

        // .htaccess baseline
        echo "Creating .htaccess baseline...\n";
        $htaccess_scanner = new HtaccessScanner($this->wp_root);
        $htaccess_baseline = $htaccess_scanner->createBaseline();
        echo "✓ .htaccess baseline created\n\n";

        echo "===================================\n";
        echo "All baselines initialized successfully\n\n";

        return [
            'database' => $db_baseline,
            'filesystem' => $fs_baseline,
            'htaccess' => $htaccess_baseline
        ];
    }

    /**
     * Quick scan (essential checks only)
     */
    public function runQuickScan() {
        echo "Running quick security scan...\n";
        echo "==============================\n\n";

        $results = [];

        // Critical database checks
        if ($this->wpdb) {
            $db_scanner = new DatabaseScanner($this->wpdb);
            $results['users'] = $db_scanner->scanUserRoles();
            $results['options'] = $db_scanner->scanOptions();
        }

        // Critical file checks
        $file_scanner = new FileScanner($this->wp_root);
        $results['uploads'] = $file_scanner->scanUploadsDirectory();

        // Permission checks
        $perm_checker = new PermissionChecker($this->wp_root);
        $results['permissions'] = $perm_checker->auditPermissions();

        echo "Quick scan complete\n\n";

        return $results;
    }

    /**
     * Get default configuration
     */
    private function getDefaultConfig() {
        return [
            'wp_root' => ABSPATH ?? getcwd(),
            'scan_database' => true,
            'scan_filesystem' => true,
            'scan_permissions' => true,
            'scan_htaccess' => true,
            'scan_anomalies' => true,
            'file_watching' => true,
            'generate_report' => true,
            'auto_quarantine' => false,
            'whitelist' => [],
            'patterns' => []
        ];
    }

    /**
     * Get scan results
     */
    public function getResults() {
        return $this->results;
    }

    /**
     * Export results to JSON
     */
    public function exportResults($filepath = null) {
        $filepath = $filepath ?: WP_SCANNER_DIR . '/data/latest_scan.json';
        file_put_contents($filepath, json_encode($this->results, JSON_PRETTY_PRINT));
        return $filepath;
    }
}
