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
            CLI::header("WordPress Security Scanner - Full Scan");
            $scanner = new WPScanner\Core\Scanner($config);
            $results = $scanner->runFullScan();

            if (isset($results['report'])) {
                CLI::success("Scan completed successfully!");
                CLI::info("Scan ID: " . $results['scan_id']);
                CLI::info("Report: " . $results['report']['html_report']);
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

        case 'version':
        case '-v':
        case '--version':
            CLI::println("WordPress Security Scanner v1.0.0", CLI::CYAN);
            break;

        case 'help':
        case '-h':
        case '--help':
        default:
            CLI::header("WordPress Security Scanner");

            echo <<<HELP
Usage: php scanner.php [command] [options]

Commands:
  scan, full          Run comprehensive security scan
  quick               Run quick security scan (essential checks only)
  init, baseline      Initialize security baselines
  watch               Check for file system changes
  users               Audit user accounts and roles
  permissions         Audit file permissions
  htaccess            Scan .htaccess files
  anomalies           Run anomaly detection
  integrity           Check WordPress core file integrity
  harden              Audit security hardening
  apply-hardening     Apply security hardening fixes
  backup              Create full backup (files + database)
  list-backups        List all backups
  version, -v         Show version information
  help, -h            Show this help message

Examples:
  php scanner.php scan              # Run full scan
  php scanner.php quick             # Quick scan
  php scanner.php init              # Initialize baselines
  php scanner.php integrity         # Check WP core integrity
  php scanner.php harden            # Audit hardening
  php scanner.php backup            # Create backup

Features:
  ✓ Database malware scanning
  ✓ File system integrity checking
  ✓ WordPress core integrity verification
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
  ✓ Comprehensive reporting

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
