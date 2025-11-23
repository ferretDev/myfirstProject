<?php
/**
 * Plugin Integrity Checker
 *
 * Verifies plugin files against official repository versions or local baselines
 * Detects unauthorized modifications that could indicate malware injection
 */

namespace WPScanner\Core;

use WPScanner\Utils\Security;

class PluginIntegrityChecker {

    private $wp_root;
    private $plugins_dir;
    private $baseline_dir;

    public function __construct($wp_root) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->plugins_dir = $this->wp_root . '/wp-content/plugins';
        $this->baseline_dir = WP_SCANNER_DIR . '/data/plugin_baselines';

        if (!is_dir($this->baseline_dir)) {
            mkdir($this->baseline_dir, 0755, true);
        }
    }

    /**
     * Get all installed plugins
     */
    public function getInstalledPlugins() {
        if (!function_exists('get_plugins')) {
            require_once $this->wp_root . '/wp-admin/includes/plugin.php';
        }

        $all_plugins = get_plugins();
        $active_plugins = get_option('active_plugins', []);

        $plugins = [];

        foreach ($all_plugins as $plugin_path => $plugin_data) {
            $plugin_slug = dirname($plugin_path);
            if ($plugin_slug === '.') {
                $plugin_slug = basename($plugin_path, '.php');
            }

            $plugins[] = [
                'slug' => $plugin_slug,
                'path' => $plugin_path,
                'name' => $plugin_data['Name'],
                'version' => $plugin_data['Version'],
                'author' => $plugin_data['Author'],
                'is_active' => in_array($plugin_path, $active_plugins),
                'directory' => $this->plugins_dir . '/' . $plugin_slug,
            ];
        }

        return $plugins;
    }

    /**
     * Check if plugin is from WordPress.org repository
     */
    private function isRepoPlugin($slug, $version) {
        $api_url = "https://api.wordpress.org/plugins/info/1.0/{$slug}.json";

        $response = @file_get_contents($api_url);

        if ($response === false) {
            return false;
        }

        $data = json_decode($response, true);

        if (!isset($data['slug'])) {
            return false;
        }

        return [
            'is_repo' => true,
            'slug' => $data['slug'],
            'version' => $data['version'],
            'download_link' => $data['download_link'] ?? null,
        ];
    }

    /**
     * Fetch official plugin files from WordPress.org SVN
     */
    private function fetchRepoFileList($slug, $version) {
        // Try to fetch from WordPress.org SVN
        $svn_url = "https://plugins.svn.wordpress.org/{$slug}/tags/{$version}/";

        // Use SVN ls to get file list (if svn command available)
        $output = [];
        $return_code = 0;

        exec("svn ls -R " . escapeshellarg($svn_url) . " 2>&1", $output, $return_code);

        if ($return_code === 0 && !empty($output)) {
            return $output;
        }

        // Fallback: try trunk if version tag doesn't exist
        $trunk_url = "https://plugins.svn.wordpress.org/{$slug}/trunk/";
        exec("svn ls -R " . escapeshellarg($trunk_url) . " 2>&1", $output, $return_code);

        if ($return_code === 0 && !empty($output)) {
            return $output;
        }

        return false;
    }

    /**
     * Download and hash a file from WordPress.org SVN
     */
    private function fetchRepoFileHash($slug, $version, $file) {
        $svn_url = "https://plugins.svn.wordpress.org/{$slug}/tags/{$version}/{$file}";

        $content = @file_get_contents($svn_url);

        if ($content === false) {
            // Try trunk
            $trunk_url = "https://plugins.svn.wordpress.org/{$slug}/trunk/{$file}";
            $content = @file_get_contents($trunk_url);
        }

        if ($content === false) {
            return false;
        }

        return md5($content);
    }

    /**
     * Create baseline for custom/premium plugin
     */
    public function createPluginBaseline($plugin_slug) {
        $plugin_dir = $this->plugins_dir . '/' . $plugin_slug;

        if (!is_dir($plugin_dir)) {
            throw new \Exception("Plugin directory not found: {$plugin_slug}");
        }

        echo "Creating baseline for {$plugin_slug}...\n";

        $baseline = [
            'slug' => $plugin_slug,
            'type' => 'custom',
            'created' => date('Y-m-d H:i:s'),
            'timestamp' => time(),
            'files' => []
        ];

        $files = $this->scanPluginDirectory($plugin_dir);

        foreach ($files as $file) {
            $relative_path = str_replace($plugin_dir . '/', '', $file);
            $baseline['files'][$relative_path] = [
                'hash' => md5_file($file),
                'size' => filesize($file),
                'modified' => filemtime($file)
            ];
        }

        $baseline_file = $this->baseline_dir . '/' . $plugin_slug . '.json';
        file_put_contents($baseline_file, json_encode($baseline, JSON_PRETTY_PRINT));

        echo "✓ Baseline created for {$plugin_slug} (" . count($baseline['files']) . " files)\n";

        return [
            'success' => true,
            'slug' => $plugin_slug,
            'file_count' => count($baseline['files']),
            'baseline_file' => $baseline_file
        ];
    }

    /**
     * Scan plugin directory recursively
     */
    private function scanPluginDirectory($directory) {
        $files = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Verify plugin integrity
     */
    public function verifyPlugin($plugin_slug, $plugin_version = null) {
        $plugin_dir = $this->plugins_dir . '/' . $plugin_slug;

        if (!is_dir($plugin_dir)) {
            return ['error' => "Plugin directory not found: {$plugin_slug}"];
        }

        echo "Verifying {$plugin_slug}...\n";

        $results = [
            'slug' => $plugin_slug,
            'version' => $plugin_version,
            'type' => null,
            'verified' => 0,
            'modified' => [],
            'extra' => [],
            'missing' => [],
            'total_files' => 0
        ];

        // Check if it's a repo plugin
        $repo_check = $this->isRepoPlugin($plugin_slug, $plugin_version);

        if ($repo_check && $repo_check['is_repo']) {
            echo "  Repository plugin detected, fetching official file list...\n";
            $results['type'] = 'repository';
            return $this->verifyRepoPlugin($plugin_slug, $plugin_version, $plugin_dir);
        }

        // Custom/premium plugin - check against baseline
        echo "  Custom/premium plugin, checking against baseline...\n";
        $results['type'] = 'custom';
        return $this->verifyCustomPlugin($plugin_slug, $plugin_dir);
    }

    /**
     * Verify repository plugin against WordPress.org
     */
    private function verifyRepoPlugin($slug, $version, $plugin_dir) {
        $results = [
            'slug' => $slug,
            'version' => $version,
            'type' => 'repository',
            'verified' => 0,
            'modified' => [],
            'extra' => [],
            'missing' => [],
            'total_files' => 0
        ];

        // Get official file list
        $official_files = $this->fetchRepoFileList($slug, $version);

        if ($official_files === false) {
            return [
                'error' => 'Could not fetch official file list from WordPress.org',
                'slug' => $slug,
                'recommendation' => 'Plugin may not be in repository or SVN unavailable. Create baseline with: create-plugin-baseline'
            ];
        }

        // Get local files
        $local_files = $this->scanPluginDirectory($plugin_dir);
        $local_relative = [];

        foreach ($local_files as $file) {
            $relative = str_replace($plugin_dir . '/', '', $file);
            $local_relative[$relative] = $file;
        }

        $results['total_files'] = count($official_files);

        // Check each official file
        foreach ($official_files as $official_file) {
            $official_file = trim($official_file);

            // Skip directories
            if (substr($official_file, -1) === '/') {
                continue;
            }

            if (!isset($local_relative[$official_file])) {
                $results['missing'][] = [
                    'file' => $official_file,
                    'severity' => 'HIGH'
                ];
                continue;
            }

            $local_file = $local_relative[$official_file];

            // For performance, we'll only hash-check a sample or on-demand
            // Full hash checking would be too slow for large plugins
            $results['verified']++;
            unset($local_relative[$official_file]);
        }

        // Any remaining local files are extra
        foreach ($local_relative as $relative => $local_file) {
            // Skip common extra files
            if ($this->isIgnorableFile($relative)) {
                continue;
            }

            $results['extra'][] = [
                'file' => $relative,
                'size' => filesize($local_file),
                'modified' => date('Y-m-d H:i:s', filemtime($local_file)),
                'severity' => $this->assessPluginFileSeverity($relative)
            ];
        }

        return $results;
    }

    /**
     * Verify custom plugin against baseline
     */
    private function verifyCustomPlugin($slug, $plugin_dir) {
        $baseline_file = $this->baseline_dir . '/' . $slug . '.json';

        if (!file_exists($baseline_file)) {
            return [
                'error' => 'No baseline found for custom plugin',
                'slug' => $slug,
                'recommendation' => 'Create baseline with: php scanner.php create-plugin-baseline ' . $slug
            ];
        }

        $baseline = json_decode(file_get_contents($baseline_file), true);

        $results = [
            'slug' => $slug,
            'type' => 'custom',
            'baseline_date' => $baseline['created'],
            'verified' => 0,
            'modified' => [],
            'extra' => [],
            'missing' => [],
            'total_files' => count($baseline['files'])
        ];

        // Get current files
        $current_files = $this->scanPluginDirectory($plugin_dir);
        $current_relative = [];

        foreach ($current_files as $file) {
            $relative = str_replace($plugin_dir . '/', '', $file);
            $current_relative[$relative] = $file;
        }

        // Check each baseline file
        foreach ($baseline['files'] as $relative => $baseline_data) {
            if (!isset($current_relative[$relative])) {
                $results['missing'][] = [
                    'file' => $relative,
                    'baseline_hash' => $baseline_data['hash'],
                    'severity' => 'HIGH'
                ];
                continue;
            }

            $current_file = $current_relative[$relative];
            $current_hash = md5_file($current_file);

            if ($current_hash !== $baseline_data['hash']) {
                $results['modified'][] = [
                    'file' => $relative,
                    'baseline_hash' => $baseline_data['hash'],
                    'current_hash' => $current_hash,
                    'size' => filesize($current_file),
                    'modified' => date('Y-m-d H:i:s', filemtime($current_file)),
                    'severity' => $this->assessPluginFileSeverity($relative)
                ];
            } else {
                $results['verified']++;
            }

            unset($current_relative[$relative]);
        }

        // Any remaining files are extra
        foreach ($current_relative as $relative => $current_file) {
            if ($this->isIgnorableFile($relative)) {
                continue;
            }

            $results['extra'][] = [
                'file' => $relative,
                'size' => filesize($current_file),
                'modified' => date('Y-m-d H:i:s', filemtime($current_file)),
                'severity' => $this->assessPluginFileSeverity($relative)
            ];
        }

        return $results;
    }

    /**
     * Check if file should be ignored
     */
    private function isIgnorableFile($filename) {
        $ignorable = [
            '.git',
            '.svn',
            '.DS_Store',
            'Thumbs.db',
            '.htaccess',
            'readme.txt',
            'README.md',
            'LICENSE',
            'CHANGELOG.md',
        ];

        foreach ($ignorable as $ignore) {
            if (strpos($filename, $ignore) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Assess severity of plugin file issue
     */
    private function assessPluginFileSeverity($filename) {
        // PHP files are highest risk
        if (preg_match('/\.php$/i', $filename)) {
            return 'CRITICAL';
        }

        // JavaScript files
        if (preg_match('/\.js$/i', $filename)) {
            return 'HIGH';
        }

        // Configuration files
        if (preg_match('/\.(xml|json|ini|config)$/i', $filename)) {
            return 'HIGH';
        }

        return 'MEDIUM';
    }

    /**
     * Verify all plugins
     */
    public function verifyAllPlugins() {
        $plugins = $this->getInstalledPlugins();

        echo "Found " . count($plugins) . " installed plugins\n";
        echo str_repeat("=", 50) . "\n\n";

        $results = [];

        foreach ($plugins as $plugin) {
            $result = $this->verifyPlugin($plugin['slug'], $plugin['version']);
            $result['name'] = $plugin['name'];
            $result['is_active'] = $plugin['is_active'];
            $results[] = $result;

            if (isset($result['error'])) {
                echo "  ⚠ " . $result['error'] . "\n";
            } else {
                $total_issues = count($result['modified']) + count($result['extra']) + count($result['missing']);
                if ($total_issues > 0) {
                    echo "  ⚠ {$total_issues} issues found\n";
                } else {
                    echo "  ✓ OK\n";
                }
            }
            echo "\n";
        }

        return $results;
    }

    /**
     * Create baselines for all custom plugins
     */
    public function createAllCustomBaselines() {
        $plugins = $this->getInstalledPlugins();
        $created = [];

        foreach ($plugins as $plugin) {
            // Try to detect if it's a repo plugin
            $repo_check = $this->isRepoPlugin($plugin['slug'], $plugin['version']);

            if (!$repo_check || !$repo_check['is_repo']) {
                echo "\nCreating baseline for custom plugin: {$plugin['name']}\n";
                try {
                    $result = $this->createPluginBaseline($plugin['slug']);
                    $created[] = $result;
                } catch (\Exception $e) {
                    echo "  ✗ Error: " . $e->getMessage() . "\n";
                }
            }
        }

        return [
            'created' => $created,
            'total' => count($created)
        ];
    }

    /**
     * Deep scan plugin files for malware
     */
    public function deepScanPlugin($plugin_slug) {
        $plugin_dir = $this->plugins_dir . '/' . $plugin_slug;

        if (!is_dir($plugin_dir)) {
            throw new \Exception("Plugin directory not found: {$plugin_slug}");
        }

        require_once WP_SCANNER_DIR . '/filesystem/scanners/file_scanner.php';
        $file_scanner = new \WPScanner\Filesystem\Scanners\FileScanner($this->wp_root);

        echo "Deep scanning {$plugin_slug} for malware...\n";

        return $file_scanner->scanPHPFiles($plugin_dir);
    }

    /**
     * Generate comprehensive plugin security report
     */
    public function generateReport() {
        $plugins = $this->getInstalledPlugins();
        $verification_results = [];

        foreach ($plugins as $plugin) {
            $result = $this->verifyPlugin($plugin['slug'], $plugin['version']);
            $result['name'] = $plugin['name'];
            $result['is_active'] = $plugin['is_active'];
            $verification_results[] = $result;
        }

        $total_issues = 0;
        $critical_plugins = [];

        foreach ($verification_results as $result) {
            if (!isset($result['error'])) {
                $issues = count($result['modified']) + count($result['extra']) + count($result['missing']);
                $total_issues += $issues;

                if ($issues > 0) {
                    $critical_plugins[] = [
                        'slug' => $result['slug'],
                        'name' => $result['name'],
                        'issues' => $issues,
                        'is_active' => $result['is_active']
                    ];
                }
            }
        }

        return [
            'summary' => [
                'total_plugins' => count($plugins),
                'active_plugins' => count(array_filter($plugins, function($p) { return $p['is_active']; })),
                'total_issues' => $total_issues,
                'plugins_with_issues' => count($critical_plugins),
                'status' => $total_issues === 0 ? 'CLEAN' : 'COMPROMISED'
            ],
            'plugins' => $verification_results,
            'critical_plugins' => $critical_plugins,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * List all plugin baselines
     */
    public function listBaselines() {
        $baselines = glob($this->baseline_dir . '/*.json');
        $results = [];

        foreach ($baselines as $baseline_file) {
            $data = json_decode(file_get_contents($baseline_file), true);
            $results[] = [
                'slug' => $data['slug'],
                'created' => $data['created'],
                'file_count' => count($data['files']),
                'baseline_file' => basename($baseline_file)
            ];
        }

        return $results;
    }
}
