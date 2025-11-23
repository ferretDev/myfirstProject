<?php
/**
 * WordPress Core Integrity Checker
 *
 * Verifies WordPress core files against official checksums
 */

namespace WPScanner\Core;

use WPScanner\Utils\Security;

class IntegrityChecker {

    private $wp_root;
    private $wp_version;
    private $checksums;

    public function __construct($wp_root) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->wp_version = $this->getWordPressVersion();
    }

    /**
     * Get WordPress version
     */
    private function getWordPressVersion() {
        $version_file = $this->wp_root . '/wp-includes/version.php';

        if (!file_exists($version_file)) {
            throw new \Exception('WordPress version file not found');
        }

        include $version_file;
        return $wp_version ?? 'unknown';
    }

    /**
     * Fetch official checksums from WordPress.org
     */
    public function fetchOfficialChecksums() {
        $api_url = sprintf(
            'https://api.wordpress.org/core/checksums/1.0/?version=%s',
            urlencode($this->wp_version)
        );

        $response = @file_get_contents($api_url);

        if ($response === false) {
            throw new \Exception('Failed to fetch checksums from WordPress.org');
        }

        $data = json_decode($response, true);

        if (!isset($data['checksums'])) {
            throw new \Exception('Invalid checksum data received');
        }

        $this->checksums = $data['checksums'];
        return $this->checksums;
    }

    /**
     * Verify WordPress core integrity
     */
    public function verifyIntegrity() {
        echo "Fetching official checksums for WordPress {$this->wp_version}...\n";

        try {
            $this->fetchOfficialChecksums();
        } catch (\Exception $e) {
            return [
                'error' => $e->getMessage(),
                'suggestion' => 'Check internet connection or verify WordPress version'
            ];
        }

        echo "Verifying " . count($this->checksums) . " core files...\n";

        $results = [
            'version' => $this->wp_version,
            'total_files' => count($this->checksums),
            'verified' => 0,
            'modified' => [],
            'missing' => [],
            'extra' => [],
        ];

        // Check each file in checksums
        foreach ($this->checksums as $file => $expected_hash) {
            $filepath = $this->wp_root . '/' . $file;

            if (!file_exists($filepath)) {
                $results['missing'][] = [
                    'file' => $file,
                    'expected_hash' => $expected_hash,
                    'severity' => 'HIGH'
                ];
                continue;
            }

            $actual_hash = md5_file($filepath);

            if ($actual_hash !== $expected_hash) {
                $results['modified'][] = [
                    'file' => $file,
                    'expected_hash' => $expected_hash,
                    'actual_hash' => $actual_hash,
                    'size' => filesize($filepath),
                    'modified_time' => date('Y-m-d H:i:s', filemtime($filepath)),
                    'severity' => $this->assessSeverity($file)
                ];
            } else {
                $results['verified']++;
            }
        }

        // Check for extra files in core directories
        $results['extra'] = $this->findExtraFiles();

        return $results;
    }

    /**
     * Find files not in official WordPress core
     */
    private function findExtraFiles() {
        $extra = [];
        $core_dirs = [
            'wp-admin',
            'wp-includes',
        ];

        foreach ($core_dirs as $dir) {
            $full_path = $this->wp_root . '/' . $dir;

            if (!is_dir($full_path)) {
                continue;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($full_path, \RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $relative = str_replace($this->wp_root . '/', '', $file->getPathname());

                    // Skip .htaccess and index.php in some dirs
                    if (basename($relative) === '.htaccess' || basename($relative) === 'index.php') {
                        continue;
                    }

                    // Check if file is in official checksums
                    if (!isset($this->checksums[$relative])) {
                        $extra[] = [
                            'file' => $relative,
                            'size' => $file->getSize(),
                            'modified' => date('Y-m-d H:i:s', $file->getMTime()),
                            'severity' => 'MEDIUM'
                        ];
                    }
                }
            }
        }

        return $extra;
    }

    /**
     * Assess severity based on file location
     */
    private function assessSeverity($file) {
        // Critical core files
        $critical_files = [
            'wp-settings.php',
            'wp-config-sample.php',
            'wp-load.php',
            'wp-blog-header.php',
        ];

        if (in_array($file, $critical_files)) {
            return 'CRITICAL';
        }

        // wp-admin files
        if (strpos($file, 'wp-admin/') === 0) {
            return 'HIGH';
        }

        // wp-includes files
        if (strpos($file, 'wp-includes/') === 0) {
            return 'HIGH';
        }

        return 'MEDIUM';
    }

    /**
     * Download and restore a single core file
     */
    public function restoreCoreFile($file) {
        // Validate path
        Security::validatePath($this->wp_root . '/' . $file);

        // Confirm it's a core file
        if (!isset($this->checksums[$file])) {
            throw new \Exception('File is not a WordPress core file');
        }

        // Download URL
        $download_url = sprintf(
            'https://core.svn.wordpress.org/tags/%s/%s',
            $this->wp_version,
            $file
        );

        echo "Downloading {$file} from WordPress.org...\n";

        $content = @file_get_contents($download_url);

        if ($content === false) {
            throw new \Exception('Failed to download file from WordPress.org');
        }

        // Verify hash before writing
        $actual_hash = md5($content);
        if ($actual_hash !== $this->checksums[$file]) {
            throw new \Exception('Downloaded file checksum mismatch!');
        }

        // Backup existing file
        $filepath = $this->wp_root . '/' . $file;
        if (file_exists($filepath)) {
            $backup_path = $filepath . '.backup.' . time();
            copy($filepath, $backup_path);
            echo "Created backup: {$backup_path}\n";
        }

        // Write new file
        if (file_put_contents($filepath, $content) === false) {
            throw new \Exception('Failed to write file');
        }

        echo "✓ Restored {$file}\n";

        return [
            'success' => true,
            'file' => $file,
            'hash' => $actual_hash
        ];
    }

    /**
     * Restore all modified core files
     */
    public function restoreAllModified($auto_confirm = false) {
        $results = $this->verifyIntegrity();

        if (empty($results['modified'])) {
            echo "No modified files found.\n";
            return;
        }

        $count = count($results['modified']);

        if (!Security::confirmDestructive(
            "This will restore {$count} modified WordPress core files. Continue?",
            $auto_confirm
        )) {
            echo "Operation cancelled.\n";
            return;
        }

        $restored = [];
        $failed = [];

        foreach ($results['modified'] as $modified) {
            try {
                $result = $this->restoreCoreFile($modified['file']);
                $restored[] = $result;
            } catch (\Exception $e) {
                $failed[] = [
                    'file' => $modified['file'],
                    'error' => $e->getMessage()
                ];
            }
        }

        return [
            'restored' => $restored,
            'failed' => $failed,
            'summary' => [
                'total' => $count,
                'restored' => count($restored),
                'failed' => count($failed)
            ]
        ];
    }

    /**
     * Generate integrity report
     */
    public function generateReport() {
        $results = $this->verifyIntegrity();

        $total_issues = count($results['modified']) +
                       count($results['missing']) +
                       count($results['extra']);

        return [
            'summary' => [
                'wordpress_version' => $this->wp_version,
                'total_core_files' => $results['total_files'],
                'verified_ok' => $results['verified'],
                'modified' => count($results['modified']),
                'missing' => count($results['missing']),
                'extra' => count($results['extra']),
                'total_issues' => $total_issues,
                'integrity_status' => $total_issues === 0 ? 'CLEAN' : 'COMPROMISED'
            ],
            'details' => $results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Quick integrity check (just count issues)
     */
    public function quickCheck() {
        try {
            $this->fetchOfficialChecksums();
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }

        $issues = 0;

        // Sample 10% of files for quick check
        $sample_size = max(10, (int)(count($this->checksums) * 0.1));
        $sampled = array_rand($this->checksums, $sample_size);

        foreach ($sampled as $file) {
            $filepath = $this->wp_root . '/' . $this->checksums[$file];

            if (!file_exists($filepath)) {
                $issues++;
                continue;
            }

            if (md5_file($filepath) !== $this->checksums[$file]) {
                $issues++;
            }
        }

        $estimated_total = (int)(($issues / $sample_size) * count($this->checksums));

        return [
            'sampled' => $sample_size,
            'issues_found' => $issues,
            'estimated_total_issues' => $estimated_total,
            'status' => $estimated_total === 0 ? 'LIKELY_CLEAN' : 'LIKELY_COMPROMISED'
        ];
    }
}
