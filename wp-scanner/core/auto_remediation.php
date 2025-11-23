<?php
/**
 * Automated Remediation Engine
 *
 * Automatically fixes common security issues with user approval
 */

namespace WPScanner\Core;

use WPScanner\Utils\Security;
use WPScanner\Utils\Backup;
use WPScanner\Utils\Logger;

class AutoRemediation {

    private $wp_root;
    private $backup;
    private $logger;
    private $dry_run;
    private $fixes_applied = [];

    public function __construct($wp_root, $dry_run = false) {
        $this->wp_root = $wp_root;
        $this->backup = new Backup($wp_root);
        $this->logger = new Logger();
        $this->dry_run = $dry_run;
    }

    /**
     * Run automated remediation based on scan results
     */
    public function remediate($scan_results, $auto_confirm = false) {
        echo "\n";
        echo "╔════════════════════════════════════════════════════════════════╗\n";
        echo "║              Automated Remediation Engine                      ║\n";
        echo "╚════════════════════════════════════════════════════════════════╝\n";
        echo "\n";

        if ($this->dry_run) {
            echo "  ℹ️  DRY RUN MODE - No changes will be made\n\n";
        }

        // Create backup before any changes
        if (!$this->dry_run && !$auto_confirm) {
            if (!Security::confirmDestructive("Create backup before remediation?", false)) {
                echo "  Backup skipped. Proceeding with caution...\n\n";
            } else {
                echo "  → Creating backup...\n";
                $this->backup->fullBackup(true);
                echo "  ✓ Backup created\n\n";
            }
        }

        $remediation_plan = $this->analyzeScanResults($scan_results);

        if (empty($remediation_plan)) {
            echo "  ✓ No issues found that can be automatically remediated\n\n";
            return ['fixes_applied' => 0, 'plan' => []];
        }

        // Display remediation plan
        echo "  Remediation Plan:\n";
        echo "  " . str_repeat("─", 60) . "\n";
        foreach ($remediation_plan as $i => $fix) {
            $num = str_pad($i + 1, 2, '0', STR_PAD_LEFT);
            echo "  {$num}. [{$fix['severity']}] {$fix['description']}\n";
        }
        echo "\n";

        // Confirm remediation
        if (!$auto_confirm) {
            if (!Security::confirmDestructive(
                "Apply " . count($remediation_plan) . " automated fixes?",
                false
            )) {
                echo "  Remediation cancelled.\n\n";
                return ['fixes_applied' => 0, 'plan' => $remediation_plan, 'cancelled' => true];
            }
        }

        // Execute remediation
        echo "\n  Executing remediation...\n";
        echo "  " . str_repeat("─", 60) . "\n\n";

        foreach ($remediation_plan as $fix) {
            $this->executeFix($fix);
        }

        echo "\n";
        echo "  ✓ Remediation complete\n";
        echo "  " . count($this->fixes_applied) . " fixes applied successfully\n\n";

        $this->logger->info("Auto remediation completed", [
            'fixes_applied' => count($this->fixes_applied),
            'plan' => $remediation_plan
        ]);

        return [
            'fixes_applied' => count($this->fixes_applied),
            'plan' => $remediation_plan,
            'results' => $this->fixes_applied
        ];
    }

    /**
     * Analyze scan results and create remediation plan
     */
    private function analyzeScanResults($scan_results) {
        $plan = [];

        // PHP files in uploads directory (CRITICAL)
        if (isset($scan_results['scans']['filesystem']['uploads']['php_files'])) {
            foreach ($scan_results['scans']['filesystem']['uploads']['php_files'] as $php_file) {
                $plan[] = [
                    'type' => 'quarantine_file',
                    'severity' => 'CRITICAL',
                    'description' => "Quarantine PHP file in uploads: " . basename($php_file['path']),
                    'data' => $php_file
                ];
            }
        }

        // World-writable files (HIGH)
        if (isset($scan_results['scans']['filesystem']['permissions']['details']['world_writable'])) {
            foreach ($scan_results['scans']['filesystem']['permissions']['details']['world_writable'] as $item) {
                $plan[] = [
                    'type' => 'fix_permissions',
                    'severity' => 'HIGH',
                    'description' => "Fix world-writable: " . basename($item['path']),
                    'data' => $item
                ];
            }
        }

        // Insecure file permissions (MEDIUM)
        if (isset($scan_results['scans']['filesystem']['permissions']['details']['insecure_files'])) {
            foreach ($scan_results['scans']['filesystem']['permissions']['details']['insecure_files'] as $item) {
                $plan[] = [
                    'type' => 'fix_permissions',
                    'severity' => 'MEDIUM',
                    'description' => "Fix file permissions: " . basename($item['path']),
                    'data' => $item
                ];
            }
        }

        // Missing index.php files (MEDIUM)
        if (isset($scan_results['scans']['filesystem']['directory_listing'])) {
            $vulnerable = $scan_results['scans']['filesystem']['directory_listing']['vulnerable_directories'] ?? [];
            foreach ($vulnerable as $dir) {
                $plan[] = [
                    'type' => 'create_index',
                    'severity' => 'MEDIUM',
                    'description' => "Create index.php in: {$dir}",
                    'data' => ['directory' => $dir]
                ];
            }
        }

        // Security hardening issues
        if (isset($scan_results['scans']['hardening'])) {
            $hardening = $scan_results['scans']['hardening'];

            // WP_DEBUG enabled (MEDIUM)
            if (isset($hardening['audit_results']['debug_mode']['status']) &&
                $hardening['audit_results']['debug_mode']['status'] === 'Enabled') {
                $plan[] = [
                    'type' => 'disable_debug',
                    'severity' => 'MEDIUM',
                    'description' => "Disable WP_DEBUG in production",
                    'data' => []
                ];
            }

            // File editing enabled (MEDIUM)
            if (isset($hardening['audit_results']['file_editing']['status']) &&
                $hardening['audit_results']['file_editing']['status'] === 'Enabled') {
                $plan[] = [
                    'type' => 'disable_file_edit',
                    'severity' => 'MEDIUM',
                    'description' => "Disable file editing in wp-config.php",
                    'data' => []
                ];
            }
        }

        // Sort by severity
        usort($plan, function($a, $b) {
            $severity_order = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];
            return $severity_order[$a['severity']] - $severity_order[$b['severity']];
        });

        return $plan;
    }

    /**
     * Execute a single fix
     */
    private function executeFix($fix) {
        echo "  → {$fix['description']}... ";

        if ($this->dry_run) {
            echo "[DRY RUN]\n";
            return;
        }

        try {
            $result = false;

            switch ($fix['type']) {
                case 'quarantine_file':
                    $result = $this->quarantineFile($fix['data']);
                    break;

                case 'fix_permissions':
                    $result = $this->fixPermissions($fix['data']);
                    break;

                case 'create_index':
                    $result = $this->createIndexFile($fix['data']);
                    break;

                case 'disable_debug':
                    $result = $this->disableDebug();
                    break;

                case 'disable_file_edit':
                    $result = $this->disableFileEdit();
                    break;

                default:
                    echo "✗ Unknown fix type\n";
                    return;
            }

            if ($result) {
                echo "✓\n";
                $this->fixes_applied[] = $fix;
                $this->logger->info("Fix applied", ['fix' => $fix]);
            } else {
                echo "✗ Failed\n";
                $this->logger->warning("Fix failed", ['fix' => $fix]);
            }
        } catch (\Exception $e) {
            echo "✗ Error: " . $e->getMessage() . "\n";
            $this->logger->error("Fix error", ['fix' => $fix, 'error' => $e->getMessage()]);
        }
    }

    /**
     * Quarantine a suspicious file
     */
    private function quarantineFile($file_data) {
        require_once WP_SCANNER_DIR . '/filesystem/scanners/file_scanner.php';
        $scanner = new \WPScanner\Filesystem\Scanners\FileScanner($this->wp_root);

        $result = $scanner->quarantineFile($file_data['path']);

        return isset($result['success']) && $result['success'];
    }

    /**
     * Fix file permissions
     */
    private function fixPermissions($file_data) {
        require_once WP_SCANNER_DIR . '/filesystem/permissions/permission_checker.php';
        $checker = new \WPScanner\Filesystem\Permissions\PermissionChecker($this->wp_root);

        $result = $checker->fixPermissions($file_data['path']);

        return isset($result['success']) && $result['success'];
    }

    /**
     * Create index.php file in directory
     */
    private function createIndexFile($data) {
        $directory = $this->wp_root . $data['directory'];
        $index_file = $directory . 'index.php';

        if (file_exists($index_file)) {
            return true; // Already exists
        }

        $content = "<?php\n// Silence is golden.\n";

        return file_put_contents($index_file, $content) !== false;
    }

    /**
     * Disable WP_DEBUG
     */
    private function disableDebug() {
        $wp_config = $this->wp_root . '/wp-config.php';

        if (!file_exists($wp_config)) {
            return false;
        }

        $content = file_get_contents($wp_config);

        // Replace WP_DEBUG true with false
        $content = preg_replace(
            "/define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)/i",
            "define('WP_DEBUG', false)",
            $content
        );

        return file_put_contents($wp_config, $content) !== false;
    }

    /**
     * Disable file editing
     */
    private function disableFileEdit() {
        $wp_config = $this->wp_root . '/wp-config.php';

        if (!file_exists($wp_config)) {
            return false;
        }

        $content = file_get_contents($wp_config);

        // Check if already exists
        if (strpos($content, 'DISALLOW_FILE_EDIT') !== false) {
            return true; // Already set
        }

        // Add before "That's all, stop editing"
        $content = str_replace(
            "/* That's all, stop editing!",
            "define('DISALLOW_FILE_EDIT', true);\n\n/* That's all, stop editing!",
            $content
        );

        return file_put_contents($wp_config, $content) !== false;
    }

    /**
     * Generate remediation report
     */
    public function generateReport() {
        return [
            'fixes_applied' => count($this->fixes_applied),
            'details' => $this->fixes_applied,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
