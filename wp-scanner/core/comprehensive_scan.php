<?php
/**
 * Comprehensive Scan Orchestrator
 *
 * Coordinates all security scanning modules for complete WordPress security assessment
 */

namespace WPScanner\Core;

use WPScanner\Utils\Logger;
use WPScanner\Utils\Security;

class ComprehensiveScan {

    private $config;
    private $wp_root;
    private $wpdb;
    private $results;
    private $logger;
    private $start_time;

    public function __construct($config, $wpdb = null) {
        $this->config = $config;
        $this->wp_root = $config['wp_root'];
        $this->wpdb = $wpdb ?: $GLOBALS['wpdb'];
        $this->logger = new Logger();
        $this->results = [];
        $this->start_time = microtime(true);
    }

    /**
     * Run complete comprehensive security scan
     */
    public function execute($options = []) {
        echo "\n";
        echo "╔════════════════════════════════════════════════════════════════╗\n";
        echo "║      WordPress Comprehensive Security Scan - Version 2.0      ║\n";
        echo "╚════════════════════════════════════════════════════════════════╝\n";
        echo "\n";

        $this->results['scan_id'] = uniqid('comprehensive_');
        $this->results['started_at'] = date('Y-m-d H:i:s');
        $this->results['scans'] = [];
        $this->results['summary'] = [];

        // Phase 1: WordPress Core
        $this->runPhase1();

        // Phase 2: Plugins & Themes
        $this->runPhase2();

        // Phase 3: Database Security
        $this->runPhase3();

        // Phase 4: File System Security
        $this->runPhase4();

        // Phase 5: Configuration & Hardening
        $this->runPhase5();

        // Phase 6: Vulnerability Detection
        $this->runPhase6();

        // Generate comprehensive summary
        $this->generateSummary();

        // Calculate duration
        $duration = round(microtime(true) - $this->start_time, 2);
        $this->results['completed_at'] = date('Y-m-d H:i:s');
        $this->results['duration_seconds'] = $duration;

        echo "\n";
        echo "╔════════════════════════════════════════════════════════════════╗\n";
        echo "║                  Comprehensive Scan Complete                   ║\n";
        echo "║                  Duration: " . str_pad($duration . "s", 41) . "║\n";
        echo "╚════════════════════════════════════════════════════════════════╝\n";
        echo "\n";

        return $this->results;
    }

    /**
     * Phase 1: WordPress Core Integrity
     */
    private function runPhase1() {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│ Phase 1: WordPress Core Integrity                             │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        try {
            $integrity_checker = new IntegrityChecker($this->wp_root);

            echo "  → Checking WordPress core files...\n";
            $this->results['scans']['core_integrity'] = $integrity_checker->generateReport();

            $issues = $this->results['scans']['core_integrity']['summary']['total_issues'];
            if ($issues > 0) {
                echo "  ⚠  {$issues} core file issues detected\n";
            } else {
                echo "  ✓  Core files verified successfully\n";
            }

            $this->logger->info("Core integrity check completed", ['issues' => $issues]);
        } catch (\Exception $e) {
            echo "  ✗  Error: " . $e->getMessage() . "\n";
            $this->logger->error("Core integrity check failed", ['error' => $e->getMessage()]);
        }

        echo "\n";
    }

    /**
     * Phase 2: Plugins & Themes Integrity
     */
    private function runPhase2() {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│ Phase 2: Plugins & Themes Integrity                           │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        // Plugins
        try {
            $plugin_checker = new PluginIntegrityChecker($this->wp_root);

            echo "  → Checking plugin file integrity...\n";
            $this->results['scans']['plugins'] = $plugin_checker->generateReport();

            $issues = $this->results['scans']['plugins']['summary']['total_issues'];
            $plugins_affected = $this->results['scans']['plugins']['summary']['plugins_with_issues'];

            if ($issues > 0) {
                echo "  ⚠  {$issues} plugin issues in {$plugins_affected} plugins\n";
            } else {
                echo "  ✓  All plugins verified successfully\n";
            }

            $this->logger->info("Plugin integrity check completed", [
                'total_plugins' => $this->results['scans']['plugins']['summary']['total_plugins'],
                'issues' => $issues
            ]);
        } catch (\Exception $e) {
            echo "  ✗  Plugin check error: " . $e->getMessage() . "\n";
            $this->logger->error("Plugin integrity check failed", ['error' => $e->getMessage()]);
        }

        // Themes
        try {
            $theme_checker = new ThemeIntegrityChecker($this->wp_root);

            echo "  → Checking theme file integrity...\n";
            $this->results['scans']['themes'] = $theme_checker->generateReport();

            $issues = $this->results['scans']['themes']['summary']['total_issues'];
            $themes_affected = $this->results['scans']['themes']['summary']['themes_with_issues'];

            if ($issues > 0) {
                echo "  ⚠  {$issues} theme issues in {$themes_affected} themes\n";
            } else {
                echo "  ✓  All themes verified successfully\n";
            }

            $this->logger->info("Theme integrity check completed", [
                'total_themes' => $this->results['scans']['themes']['summary']['total_themes'],
                'issues' => $issues
            ]);
        } catch (\Exception $e) {
            echo "  ✗  Theme check error: " . $e->getMessage() . "\n";
            $this->logger->error("Theme integrity check failed", ['error' => $e->getMessage()]);
        }

        echo "\n";
    }

    /**
     * Phase 3: Database Security
     */
    private function runPhase3() {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│ Phase 3: Database Security                                     │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        try {
            require_once WP_SCANNER_DIR . '/database/scanners/db_scanner.php';
            require_once WP_SCANNER_DIR . '/database/analyzers/change_detector.php';
            require_once WP_SCANNER_DIR . '/monitoring/detectors/anomaly_detector.php';

            $db_scanner = new \WPScanner\Database\Scanners\DatabaseScanner($this->wpdb);
            $change_detector = new \WPScanner\Database\Analyzers\ChangeDetector($this->wpdb);
            $anomaly_detector = new \WPScanner\Monitoring\Detectors\AnomalyDetector($this->wpdb, $this->wp_root);

            echo "  → Scanning database for malicious content...\n";
            $db_results = $db_scanner->runFullScan();

            echo "  → Detecting database anomalies...\n";
            $anomaly_results = $anomaly_detector->runFullDetection();

            echo "  → Checking for database changes...\n";
            $change_results = $change_detector->detectChanges();

            $this->results['scans']['database'] = [
                'malware_scan' => $db_results,
                'anomalies' => $anomaly_results,
                'changes' => $change_results
            ];

            // Count issues
            $spam_count = 0;
            if (isset($db_results['posts']['spam_content'])) {
                foreach ($db_results['posts']['spam_content'] as $type => $items) {
                    $spam_count += count($items);
                }
            }

            if ($spam_count > 0) {
                echo "  ⚠  {$spam_count} spam content instances detected\n";
            } else {
                echo "  ✓  Database scan clean\n";
            }

            $this->logger->info("Database security check completed", ['spam_instances' => $spam_count]);
        } catch (\Exception $e) {
            echo "  ✗  Database check error: " . $e->getMessage() . "\n";
            $this->logger->error("Database security check failed", ['error' => $e->getMessage()]);
        }

        echo "\n";
    }

    /**
     * Phase 4: File System Security
     */
    private function runPhase4() {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│ Phase 4: File System Security                                  │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        try {
            require_once WP_SCANNER_DIR . '/filesystem/scanners/file_scanner.php';
            require_once WP_SCANNER_DIR . '/filesystem/scanners/htaccess_scanner.php';
            require_once WP_SCANNER_DIR . '/filesystem/permissions/permission_checker.php';
            require_once WP_SCANNER_DIR . '/filesystem/watchers/file_watcher.php';

            $file_scanner = new \WPScanner\Filesystem\Scanners\FileScanner($this->wp_root);
            $htaccess_scanner = new \WPScanner\Filesystem\Scanners\HtaccessScanner($this->wp_root);
            $permission_checker = new \WPScanner\Filesystem\Permissions\PermissionChecker($this->wp_root);
            $file_watcher = new \WPScanner\Filesystem\Watchers\FileWatcher($this->wp_root);

            echo "  → Scanning uploads directory...\n";
            $uploads_scan = $file_scanner->scanUploadsDirectory();

            echo "  → Checking file permissions...\n";
            $permissions = $permission_checker->generateReport();

            echo "  → Scanning .htaccess files...\n";
            $htaccess_results = $htaccess_scanner->scanHtaccess();

            echo "  → Detecting file changes...\n";
            $file_changes = $file_watcher->detectChanges();

            $this->results['scans']['filesystem'] = [
                'uploads' => $uploads_scan,
                'permissions' => $permissions,
                'htaccess' => $htaccess_results,
                'file_changes' => $file_changes
            ];

            // Check for critical issues
            $php_in_uploads = count($uploads_scan['php_files'] ?? []);
            $permission_issues = $permissions['summary']['total_issues'];

            if ($php_in_uploads > 0) {
                echo "  ⚠  {$php_in_uploads} PHP files in uploads (CRITICAL)\n";
            }
            if ($permission_issues > 0) {
                echo "  ⚠  {$permission_issues} permission issues detected\n";
            }
            if ($php_in_uploads === 0 && $permission_issues === 0) {
                echo "  ✓  File system security checks passed\n";
            }

            $this->logger->info("File system security check completed", [
                'php_in_uploads' => $php_in_uploads,
                'permission_issues' => $permission_issues
            ]);
        } catch (\Exception $e) {
            echo "  ✗  File system check error: " . $e->getMessage() . "\n";
            $this->logger->error("File system security check failed", ['error' => $e->getMessage()]);
        }

        echo "\n";
    }

    /**
     * Phase 5: Configuration & Hardening
     */
    private function runPhase5() {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│ Phase 5: Configuration & Hardening                             │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        try {
            $hardening = new SecurityHardening($this->wp_root);

            echo "  → Auditing security hardening...\n";
            $this->results['scans']['hardening'] = $hardening->generateReport();

            $hardening_issues = $this->results['scans']['hardening']['summary']['total_issues'];

            if ($hardening_issues > 0) {
                echo "  ⚠  {$hardening_issues} hardening issues detected\n";
            } else {
                echo "  ✓  Site is properly hardened\n";
            }

            $this->logger->info("Security hardening check completed", ['issues' => $hardening_issues]);
        } catch (\Exception $e) {
            echo "  ✗  Hardening check error: " . $e->getMessage() . "\n";
            $this->logger->error("Security hardening check failed", ['error' => $e->getMessage()]);
        }

        echo "\n";
    }

    /**
     * Phase 6: Vulnerability Detection
     */
    private function runPhase6() {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│ Phase 6: Known Vulnerability Detection                        │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        try {
            $vuln_checker = new VulnerabilityChecker();

            echo "  → Checking for known vulnerabilities...\n";
            $this->results['scans']['vulnerabilities'] = $vuln_checker->generateReport();

            $total_vulns = $this->results['scans']['vulnerabilities']['summary']['total_vulnerabilities'];

            if ($total_vulns > 0) {
                echo "  ⚠  {$total_vulns} known vulnerabilities detected (UPDATE IMMEDIATELY)\n";
            } else {
                echo "  ✓  No known vulnerabilities detected\n";
            }

            $this->logger->info("Vulnerability check completed", ['vulnerabilities' => $total_vulns]);
        } catch (\Exception $e) {
            echo "  ✗  Vulnerability check error: " . $e->getMessage() . "\n";
            $this->logger->error("Vulnerability check failed", ['error' => $e->getMessage()]);
        }

        echo "\n";
    }

    /**
     * Generate comprehensive summary
     */
    private function generateSummary() {
        $summary = [
            'risk_score' => 0,
            'risk_level' => 'LOW',
            'total_issues' => 0,
            'critical_issues' => 0,
            'high_issues' => 0,
            'medium_issues' => 0,
            'low_issues' => 0,
            'categories' => []
        ];

        // Core integrity issues
        if (isset($this->results['scans']['core_integrity']['summary'])) {
            $core_issues = $this->results['scans']['core_integrity']['summary']['total_issues'];
            $summary['total_issues'] += $core_issues;
            $summary['categories']['core_integrity'] = $core_issues;
            if ($core_issues > 0) {
                $summary['risk_score'] += ($core_issues * 10); // Core issues are serious
            }
        }

        // Plugin integrity issues
        if (isset($this->results['scans']['plugins']['summary'])) {
            $plugin_issues = $this->results['scans']['plugins']['summary']['total_issues'];
            $summary['total_issues'] += $plugin_issues;
            $summary['categories']['plugin_integrity'] = $plugin_issues;
            $summary['risk_score'] += ($plugin_issues * 8);
        }

        // Theme integrity issues
        if (isset($this->results['scans']['themes']['summary'])) {
            $theme_issues = $this->results['scans']['themes']['summary']['total_issues'];
            $summary['total_issues'] += $theme_issues;
            $summary['categories']['theme_integrity'] = $theme_issues;
            $summary['risk_score'] += ($theme_issues * 8);
        }

        // Vulnerabilities (CRITICAL)
        if (isset($this->results['scans']['vulnerabilities']['summary'])) {
            $vulns = $this->results['scans']['vulnerabilities']['summary']['total_vulnerabilities'];
            $summary['total_issues'] += $vulns;
            $summary['categories']['vulnerabilities'] = $vulns;
            $summary['critical_issues'] += $vulns;
            $summary['risk_score'] += ($vulns * 25); // Vulnerabilities are extremely serious
        }

        // File system issues
        if (isset($this->results['scans']['filesystem'])) {
            $php_in_uploads = count($this->results['scans']['filesystem']['uploads']['php_files'] ?? []);
            $permission_issues = $this->results['scans']['filesystem']['permissions']['summary']['total_issues'] ?? 0;

            $summary['total_issues'] += ($php_in_uploads + $permission_issues);
            $summary['categories']['filesystem'] = ($php_in_uploads + $permission_issues);

            if ($php_in_uploads > 0) {
                $summary['critical_issues'] += $php_in_uploads;
                $summary['risk_score'] += ($php_in_uploads * 20);
            }
            $summary['risk_score'] += ($permission_issues * 5);
        }

        // Hardening issues
        if (isset($this->results['scans']['hardening']['summary'])) {
            $hardening_issues = $this->results['scans']['hardening']['summary']['total_issues'];
            $summary['total_issues'] += $hardening_issues;
            $summary['categories']['hardening'] = $hardening_issues;
            $summary['risk_score'] += ($hardening_issues * 3);
        }

        // Determine risk level
        if ($summary['risk_score'] >= 100) {
            $summary['risk_level'] = 'CRITICAL';
        } elseif ($summary['risk_score'] >= 50) {
            $summary['risk_level'] = 'HIGH';
        } elseif ($summary['risk_score'] >= 25) {
            $summary['risk_level'] = 'MEDIUM';
        } else {
            $summary['risk_level'] = 'LOW';
        }

        $this->results['summary'] = $summary;

        // Display summary
        $this->displaySummary($summary);
    }

    /**
     * Display summary in console
     */
    private function displaySummary($summary) {
        echo "┌────────────────────────────────────────────────────────────────┐\n";
        echo "│                        SECURITY SUMMARY                        │\n";
        echo "└────────────────────────────────────────────────────────────────┘\n\n";

        // Risk level with color
        $risk_display = str_pad($summary['risk_level'], 10);
        $score_display = str_pad($summary['risk_score'] . "/100", 10);

        echo "  Risk Level:        {$risk_display}\n";
        echo "  Risk Score:        {$score_display}\n";
        echo "  Total Issues:      " . $summary['total_issues'] . "\n";
        echo "  Critical Issues:   " . $summary['critical_issues'] . "\n\n";

        echo "  Issues by Category:\n";
        foreach ($summary['categories'] as $category => $count) {
            if ($count > 0) {
                $cat_display = str_pad(ucwords(str_replace('_', ' ', $category)), 30);
                echo "    • {$cat_display} {$count}\n";
            }
        }

        echo "\n";

        // Recommendations based on risk level
        if ($summary['risk_level'] === 'CRITICAL' || $summary['risk_level'] === 'HIGH') {
            echo "  ⚠️  URGENT ACTIONS REQUIRED:\n";
            echo "    1. Create backup immediately (php scanner.php backup)\n";
            echo "    2. Review detailed report in wp-scanner/reports/\n";
            echo "    3. Update all vulnerable plugins/themes\n";
            echo "    4. Remove PHP files from uploads directory\n";
            echo "    5. Consider taking site offline until issues resolved\n\n";
        } elseif ($summary['risk_level'] === 'MEDIUM') {
            echo "  ℹ️  RECOMMENDED ACTIONS:\n";
            echo "    1. Review detailed report\n";
            echo "    2. Apply security hardening fixes\n";
            echo "    3. Update vulnerable components\n";
            echo "    4. Schedule regular security scans\n\n";
        } else {
            echo "  ✓  Site appears secure\n";
            echo "    • Continue regular monitoring\n";
            echo "    • Keep WordPress core, plugins, and themes updated\n\n";
        }
    }

    /**
     * Get scan results
     */
    public function getResults() {
        return $this->results;
    }

    /**
     * Save results to file
     */
    public function saveResults($filepath = null) {
        if ($filepath === null) {
            $filepath = WP_SCANNER_DIR . '/data/latest_comprehensive_scan.json';
        }

        file_put_contents($filepath, json_encode($this->results, JSON_PRETTY_PRINT));

        $this->logger->info("Scan results saved", ['file' => $filepath]);

        return $filepath;
    }
}
