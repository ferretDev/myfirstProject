#!/usr/bin/env php
<?php
/**
 * WordPress Security Scanner - Main Entry Point
 *
 * CLI interface for running WordPress security scans
 *
 * Usage:
 *   php scanner.php scan              Run full security scan
 *   php scanner.php quick             Run quick scan
 *   php scanner.php init              Initialize baselines
 *   php scanner.php watch             Start file watcher
 *   php scanner.php users             Audit user accounts
 *   php scanner.php report [scan_id]  View scan report
 */

// Error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Define constants
define('WP_SCANNER_DIR', __DIR__);

// Autoloader (simplified - in production use Composer)
spl_autoload_register(function ($class) {
    $prefix = 'WPScanner\\';
    $base_dir = __DIR__ . '/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

// Load configuration
$config = require WP_SCANNER_DIR . '/config/config.php';

// Create necessary directories
$dirs_to_create = [
    $config['data_dir'],
    $config['quarantine']['directory'],
    $config['reports']['output_dir'],
    dirname($config['logging']['file'])
];

foreach ($dirs_to_create as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// CLI Colors
class CLI {
    const RESET = "\033[0m";
    const RED = "\033[31m";
    const GREEN = "\033[32m";
    const YELLOW = "\033[33m";
    const BLUE = "\033[34m";
    const MAGENTA = "\033[35m";
    const CYAN = "\033[36m";
    const WHITE = "\033[37m";
    const BOLD = "\033[1m";

    public static function println($text, $color = self::WHITE) {
        echo $color . $text . self::RESET . PHP_EOL;
    }

    public static function success($text) {
        self::println("✓ " . $text, self::GREEN);
    }

    public static function error($text) {
        self::println("✗ " . $text, self::RED);
    }

    public static function warning($text) {
        self::println("⚠ " . $text, self::YELLOW);
    }

    public static function info($text) {
        self::println("ℹ " . $text, self::CYAN);
    }

    public static function header($text) {
        self::println("", self::WHITE);
        self::println(str_repeat("=", strlen($text)), self::BLUE);
        self::println($text, self::BOLD . self::BLUE);
        self::println(str_repeat("=", strlen($text)), self::BLUE);
        self::println("", self::WHITE);
    }
}

// Initialize security
WPScanner\Utils\Security::init($config['wp_root']);

// Parse command line arguments
$command = isset($argv[1]) ? WPScanner\Utils\Security::sanitizeCommandArg($argv[1]) : 'help';
$args = array_slice($argv, 2);

// Rate limiting (max 10 scans per hour)
try {
    WPScanner\Utils\Security::checkRateLimit('scanner_' . $command, 10, 3600);
} catch (\Exception $e) {
    CLI::error($e->getMessage());
    exit(1);
}

try {
    switch ($command) {
        case 'scan':
        case 'full':
            // Use new comprehensive scan orchestrator
            $comprehensive_scan = new WPScanner\Core\ComprehensiveScan($config, $GLOBALS['wpdb'] ?? null);
            $results = $comprehensive_scan->execute();

            // Save results
            $results_file = $comprehensive_scan->saveResults();

            // Generate enhanced report
            require_once WP_SCANNER_DIR . '/monitoring/reports/report_generator.php';
            $report_gen = new WPScanner\Monitoring\Reports\ReportGenerator();
            $report = $report_gen->generateSecurityReport($results);

            CLI::success("Comprehensive scan completed!");
            CLI::info("Scan ID: " . $results['scan_id']);
            CLI::info("Risk Level: " . $results['summary']['risk_level']);
            CLI::info("Total Issues: " . $results['summary']['total_issues']);
            CLI::info("HTML Report: " . $report['html_report']);

            // Send notifications if enabled
            if ($config['alerts']['email'] ?? false) {
                $notifier = new WPScanner\Utils\Notifier($config);
                $notifier->sendScanNotification($results);
                CLI::info("Email notification sent");
            }
            break;

        case 'quick':
            CLI::header("WordPress Security Scanner - Quick Scan");
            $scanner = new WPScanner\Core\Scanner($config);
            $results = $scanner->runQuickScan();

            CLI::success("Quick scan completed!");
            echo json_encode($results, JSON_PRETTY_PRINT) . PHP_EOL;
            break;

        case 'init':
        case 'baseline':
            CLI::header("Initialize Security Baselines");
            $scanner = new WPScanner\Core\Scanner($config);
            $baselines = $scanner->initializeBaselines();

            CLI::success("All baselines initialized successfully!");
            break;

        case 'watch':
            CLI::header("File System Watcher");
            CLI::info("Checking for file changes...");

            $watcher = new WPScanner\Filesystem\Watchers\FileWatcher($config['wp_root']);
            $changes = $watcher->detectChanges();

            if ($changes['changes_detected']) {
                CLI::warning("Changes detected!");
                echo json_encode($changes, JSON_PRETTY_PRINT) . PHP_EOL;
            } else {
                CLI::success("No file changes detected");
            }
            break;

        case 'users':
        case 'audit-users':
            CLI::header("User Account Audit");

            if (!isset($GLOBALS['wpdb'])) {
                CLI::error("WordPress database connection not available");
                exit(1);
            }

            $editor = new WPScanner\Utils\UserRoleEditor($GLOBALS['wpdb']);
            $report = $editor->generateUserSecurityReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if (!empty($report['security_issues'])) {
                CLI::warning("Security issues found in user accounts!");
            } else {
                CLI::success("No user security issues detected");
            }
            break;

        case 'permissions':
            CLI::header("File Permission Audit");

            $checker = new WPScanner\Filesystem\Permissions\PermissionChecker($config['wp_root']);
            $report = $checker->generateReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($report['summary']['total_issues'] > 0) {
                CLI::warning($report['summary']['total_issues'] . " permission issues found!");
            } else {
                CLI::success("No permission issues detected");
            }
            break;

        case 'htaccess':
            CLI::header(".htaccess Security Scan");

            $htaccess_scanner = new WPScanner\Filesystem\Scanners\HtaccessScanner($config['wp_root']);
            $results = $htaccess_scanner->scanHtaccess();

            echo json_encode($results, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($results['issues_found'] > 0) {
                CLI::warning($results['issues_found'] . " issues found in .htaccess!");
            } else {
                CLI::success("No .htaccess issues detected");
            }
            break;

        case 'anomalies':
            CLI::header("Anomaly Detection");

            if (!isset($GLOBALS['wpdb'])) {
                CLI::error("WordPress database connection not available");
                exit(1);
            }

            $detector = new WPScanner\Monitoring\Detectors\AnomalyDetector(
                $GLOBALS['wpdb'],
                $config['wp_root']
            );
            $results = $detector->runFullDetection();

            echo json_encode($results, JSON_PRETTY_PRINT) . PHP_EOL;
            break;

        case 'integrity':
            CLI::header("WordPress Core Integrity Check");

            $checker = new WPScanner\Core\IntegrityChecker($config['wp_root']);
            $report = $checker->generateReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($report['summary']['total_issues'] > 0) {
                CLI::warning($report['summary']['total_issues'] . " core integrity issues found!");
            } else {
                CLI::success("WordPress core files verified successfully");
            }
            break;

        case 'harden':
            CLI::header("Security Hardening");

            $hardening = new WPScanner\Core\SecurityHardening($config['wp_root']);
            $report = $hardening->generateReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($report['summary']['total_issues'] > 0) {
                CLI::warning($report['summary']['total_issues'] . " security issues found!");
                CLI::info("Run 'php scanner.php apply-hardening' to fix issues");
            } else {
                CLI::success("Site is properly hardened");
            }
            break;

        case 'apply-hardening':
            CLI::header("Apply Security Hardening");

            $hardening = new WPScanner\Core\SecurityHardening($config['wp_root']);

            echo "Creating index.php files in sensitive directories...\n";
            $result = $hardening->createIndexFiles(false);

            if (isset($result['created'])) {
                CLI::success("Created " . count($result['created']) . " index.php files");
            }

            echo "\nRecommended .htaccess rules:\n";
            echo $hardening->generateHtaccessRules();
            break;

        case 'backup':
            CLI::header("Create Backup");

            $backup = new WPScanner\Utils\Backup($config['wp_root']);
            $result = $backup->fullBackup(false);

            if (isset($result['success'])) {
                CLI::success("Backup created successfully");
                echo json_encode($result, JSON_PRETTY_PRINT) . PHP_EOL;
            }
            break;

        case 'list-backups':
            CLI::header("List Backups");

            $backup = new WPScanner\Utils\Backup($config['wp_root']);
            $backups = $backup->listBackups();

            if (empty($backups)) {
                CLI::info("No backups found");
            } else {
                echo json_encode($backups, JSON_PRETTY_PRINT) . PHP_EOL;
                $size = $backup->getTotalBackupSize();
                CLI::info("Total backup size: " . $size['human']);
            }
            break;

        case 'check-plugins':
            CLI::header("Plugin Integrity Check");

            $plugin_checker = new WPScanner\Core\PluginIntegrityChecker($config['wp_root']);
            $report = $plugin_checker->generateReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($report['summary']['total_issues'] > 0) {
                CLI::warning($report['summary']['total_issues'] . " plugin integrity issues found!");
            } else {
                CLI::success("All plugins verified successfully");
            }
            break;

        case 'check-themes':
            CLI::header("Theme Integrity Check");

            $theme_checker = new WPScanner\Core\ThemeIntegrityChecker($config['wp_root']);
            $report = $theme_checker->generateReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($report['summary']['total_issues'] > 0) {
                CLI::warning($report['summary']['total_issues'] . " theme integrity issues found!");
            } else {
                CLI::success("All themes verified successfully");
            }
            break;

        case 'create-plugin-baselines':
            CLI::header("Create Plugin Baselines");

            $plugin_checker = new WPScanner\Core\PluginIntegrityChecker($config['wp_root']);
            $result = $plugin_checker->createAllCustomBaselines();

            CLI::success("Created " . $result['total'] . " plugin baselines");
            break;

        case 'create-theme-baselines':
            CLI::header("Create Theme Baselines");

            $theme_checker = new WPScanner\Core\ThemeIntegrityChecker($config['wp_root']);
            $result = $theme_checker->createAllBaselines();

            CLI::success("Created " . $result['total'] . " theme baselines");
            break;

        case 'check-vulnerabilities':
        case 'vulns':
            CLI::header("Vulnerability Check");

            $vuln_checker = new WPScanner\Core\VulnerabilityChecker();
            $report = $vuln_checker->generateReport();

            echo json_encode($report, JSON_PRETTY_PRINT) . PHP_EOL;

            if ($report['summary']['total_vulnerabilities'] > 0) {
                CLI::warning($report['summary']['total_vulnerabilities'] . " known vulnerabilities found!");
                CLI::info("Update vulnerable plugins/themes immediately");
            } else {
                CLI::success("No known vulnerabilities detected");
            }
            break;

        case 'auto-fix':
        case 'remediate':
            CLI::header("Automated Remediation");

            // First, load latest scan results
            $latest_scan = WP_SCANNER_DIR . '/data/latest_comprehensive_scan.json';

            if (!file_exists($latest_scan)) {
                CLI::error("No scan results found. Run 'php scanner.php scan' first.");
                exit(1);
            }

            $scan_results = json_decode(file_get_contents($latest_scan), true);

            $remediation = new WPScanner\Core\AutoRemediation($config['wp_root'], false);
            $result = $remediation->remediate($scan_results, false);

            if (isset($result['fixes_applied']) && $result['fixes_applied'] > 0) {
                CLI::success($result['fixes_applied'] . " issues fixed automatically");
                CLI::info("Run another scan to verify fixes");
            } else {
                CLI::info("No fixes applied");
            }
            break;

        case 'test-email':
            CLI::header("Test Email Notification");

            $notifier = new WPScanner\Utils\Notifier($config);
            $result = $notifier->sendTest();

            if ($result['email']['sent'] ?? false) {
                CLI::success("Test email sent successfully");
            } else {
                CLI::error("Failed to send test email");
            }
            break;

        case 'patterns':
        case 'list-patterns':
            CLI::header("Malware Pattern Management");

            $pattern_updater = new WPScanner\Database\Patterns\PatternUpdater();
            $stats = $pattern_updater->generateStatistics();

            echo json_encode($stats, JSON_PRETTY_PRINT) . PHP_EOL;

            CLI::info("Total default patterns: " . $stats['pattern_summary']['total_default_patterns']);
            CLI::info("Total custom patterns: " . $stats['pattern_summary']['total_custom_patterns']);
            break;

        case 'add-pattern':
            CLI::header("Add Custom Pattern");

            if (count($args) < 3) {
                CLI::error("Usage: php scanner.php add-pattern <category> <pattern> <description> [severity]");
                exit(1);
            }

            $pattern_updater = new WPScanner\Database\Patterns\PatternUpdater();
            $category = $args[0];
            $pattern = $args[1];
            $description = $args[2];
            $severity = $args[3] ?? 'HIGH';

            try {
                $result = $pattern_updater->addCustomPattern($category, $pattern, $description, $severity);
                CLI::success("Custom pattern added to category: {$category}");
                CLI::info("Total custom patterns: " . $result['total_custom_patterns']);
            } catch (\Exception $e) {
                CLI::error("Failed to add pattern: " . $e->getMessage());
            }
            break;

        case 'test-pattern':
            CLI::header("Test Pattern");

            if (count($args) < 2) {
                CLI::error("Usage: php scanner.php test-pattern <pattern> <sample_text>");
                exit(1);
            }

            $pattern_updater = new WPScanner\Database\Patterns\PatternUpdater();
            $pattern = $args[0];
            $sample_text = $args[1];

            try {
                $result = $pattern_updater->testPattern($pattern, $sample_text);
                echo json_encode($result, JSON_PRETTY_PRINT) . PHP_EOL;

                if ($result['matched']) {
                    CLI::success("Pattern matched!");
                } else {
                    CLI::info("Pattern did not match");
                }
            } catch (\Exception $e) {
                CLI::error("Pattern test failed: " . $e->getMessage());
            }
            break;

        case 'export-patterns':
            CLI::header("Export Patterns");

            $output_file = $args[0] ?? WP_SCANNER_DIR . '/data/patterns_backup_' . date('Y-m-d_His') . '.json';

            $pattern_updater = new WPScanner\Database\Patterns\PatternUpdater();
            $result = $pattern_updater->exportPatterns($output_file);

            CLI::success("Patterns exported to: {$result['file']}");
            CLI::info("File size: " . round($result['size'] / 1024, 2) . " KB");
            break;

        case 'import-patterns':
            CLI::header("Import Patterns");

            if (count($args) < 1) {
                CLI::error("Usage: php scanner.php import-patterns <file> [merge]");
                exit(1);
            }

            $input_file = $args[0];
            $merge = ($args[1] ?? 'true') === 'true';

            $pattern_updater = new WPScanner\Database\Patterns\PatternUpdater();
            try {
                $result = $pattern_updater->importPatterns($input_file, $merge);
                CLI::success("Patterns imported successfully");
                CLI::info("Imported patterns: " . $result['imported']);
                CLI::info("Merge mode: " . ($result['merge_mode'] ? 'Yes' : 'No'));
            } catch (\Exception $e) {
                CLI::error("Import failed: " . $e->getMessage());
            }
            break;

        case 'memory':
        case 'memory-stats':
            CLI::header("Memory Statistics");

            $optimizer = WPScanner\Utils\MemoryOptimizer::getInstance();
            $stats = $optimizer->getMemoryStats();

            CLI::info("Current Usage: " . WPScanner\Utils\MemoryOptimizer::formatBytes($stats['current_usage']) .
                     " ({$stats['current_usage_mb']}MB)");
            CLI::info("Peak Usage: " . WPScanner\Utils\MemoryOptimizer::formatBytes($stats['peak_usage']) .
                     " ({$stats['peak_usage_mb']}MB)");
            CLI::info("Memory Limit: " . ($stats['limit_mb'] === 'unlimited' ? 'Unlimited' : $stats['limit_mb'] . 'MB'));

            if ($stats['limit_mb'] !== 'unlimited') {
                CLI::info("Memory Used: {$stats['percentage_used']}%");
                CLI::info("Available: " . WPScanner\Utils\MemoryOptimizer::formatBytes($stats['available']) .
                         " ({$stats['available_mb']}MB)");

                if ($stats['percentage_used'] > 80) {
                    CLI::warning("Memory usage above 80% - consider increasing PHP memory_limit");
                } elseif ($stats['percentage_used'] > 50) {
                    CLI::info("Memory usage healthy");
                } else {
                    CLI::success("Plenty of memory available");
                }
            } else {
                CLI::success("Memory limit is unlimited");
            }

            // Pattern cache status
            $patterns_loaded = (WPScanner\Utils\MemoryOptimizer::getCachedPatterns() !== null);
            CLI::info("Pattern Cache: " . ($patterns_loaded ? "Loaded" : "Not loaded"));
            break;

        case 'version':
        case '-v':
        case '--version':
            CLI::println("WordPress Security Scanner v2.0.1", CLI::CYAN);
            break;

        case 'help':
        case '-h':
        case '--help':
        default:
            CLI::header("WordPress Security Scanner");

            echo <<<HELP
Usage: php scanner.php [command] [options]

Commands:
  scan, full               Run comprehensive security scan (orchestrated, all modules)
  quick                    Run quick security scan (essential checks only)
  init, baseline           Initialize security baselines
  watch                    Check for file system changes
  users                    Audit user accounts and roles
  permissions              Audit file permissions
  htaccess                 Scan .htaccess files
  anomalies                Run anomaly detection
  integrity                Check WordPress core file integrity
  check-plugins            Verify plugin file integrity (repo + custom)
  check-themes             Verify theme file integrity
  create-plugin-baselines  Create baselines for custom/premium plugins
  create-theme-baselines   Create baselines for all themes
  check-vulnerabilities    Check for known vulnerabilities in WP/plugins/themes
  harden                   Audit security hardening
  apply-hardening          Apply security hardening fixes
  auto-fix, remediate      Automatically fix common security issues
  backup                   Create full backup (files + database)
  list-backups             List all backups
  test-email               Send test email notification
  patterns, list-patterns  List all malware patterns (default + custom)
  add-pattern              Add custom malware detection pattern
  test-pattern             Test a pattern against sample text
  export-patterns          Export patterns to JSON file (backup/sharing)
  import-patterns          Import patterns from JSON file
  memory, memory-stats     Show memory usage statistics
  version, -v              Show version information
  help, -h                 Show this help message

Examples:
  php scanner.php scan                    # Run comprehensive scan (all modules)
  php scanner.php auto-fix                # Auto-fix issues from last scan
  php scanner.php init                    # Initialize baselines
  php scanner.php check-plugins           # Check plugin integrity
  php scanner.php check-vulnerabilities   # Check known vulns
  php scanner.php backup                  # Create full backup
  php scanner.php test-email              # Test email notifications
  php scanner.php patterns                # List all patterns
  php scanner.php add-pattern "backdoor" "/c99shell/i" "C99 Shell backdoor" "CRITICAL"
  php scanner.php export-patterns         # Export patterns for backup

Features:
  ✓ Database malware scanning
  ✓ File system integrity checking
  ✓ WordPress core integrity verification
  ✓ Plugin integrity verification (repo & custom)
  ✓ Theme integrity verification
  ✓ Known vulnerability detection (WPScan API)
  ✓ Custom plugin/theme baseline system
  ✓ Permission auditing
  ✓ .htaccess security scanning
  ✓ User role monitoring
  ✓ Spam content detection
  ✓ Post count anomaly detection
  ✓ OAuth/credential exposure detection
  ✓ robots.txt change monitoring
  ✓ File quarantine system
  ✓ Security hardening recommendations
  ✓ Automated backup system
  ✓ Comprehensive reporting (JSON + HTML)
  ✓ Updateable malware pattern system
  ✓ Custom pattern management
  ✓ Pattern import/export
  ✓ Automated remediation engine
  ✓ Email/Slack/webhook notifications
  ✓ Cron job scheduling

For more information, see README.md

HELP;
            break;
    }
} catch (Exception $e) {
    CLI::error("Error: " . $e->getMessage());
    if ($config['logging']['enabled']) {
        $logger = new WPScanner\Utils\Logger();
        $logger->error($e->getMessage(), ['trace' => $e->getTraceAsString()]);
    }
    exit(1);
}

exit(0);
