<?php
/**
 * Theme Integrity Checker
 *
 * Verifies theme files against official repository versions or local baselines
 */

namespace WPScanner\Core;

use WPScanner\Utils\Security;

class ThemeIntegrityChecker {

    private $wp_root;
    private $themes_dir;
    private $baseline_dir;

    public function __construct($wp_root) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->themes_dir = $this->wp_root . '/wp-content/themes';
        $this->baseline_dir = WP_SCANNER_DIR . '/data/theme_baselines';

        if (!is_dir($this->baseline_dir)) {
            mkdir($this->baseline_dir, 0755, true);
        }
    }

    /**
     * Get all installed themes
     */
    public function getInstalledThemes() {
        if (!function_exists('wp_get_themes')) {
            require_once $this->wp_root . '/wp-includes/theme.php';
        }

        $all_themes = wp_get_themes();
        $active_theme = wp_get_theme();

        $themes = [];

        foreach ($all_themes as $theme_slug => $theme) {
            $themes[] = [
                'slug' => $theme_slug,
                'name' => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'author' => $theme->get('Author'),
                'is_active' => ($theme_slug === $active_theme->get_stylesheet()),
                'directory' => $this->themes_dir . '/' . $theme_slug,
                'parent' => $theme->get('Template'),
            ];
        }

        return $themes;
    }

    /**
     * Check if theme is from WordPress.org repository
     */
    private function isRepoTheme($slug) {
        $api_url = "https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={$slug}";

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
            'version' => $data['version'] ?? null,
            'download_link' => $data['download_link'] ?? null,
        ];
    }

    /**
     * Create baseline for custom/premium theme
     */
    public function createThemeBaseline($theme_slug) {
        $theme_dir = $this->themes_dir . '/' . $theme_slug;

        if (!is_dir($theme_dir)) {
            throw new \Exception("Theme directory not found: {$theme_slug}");
        }

        echo "Creating baseline for theme: {$theme_slug}...\n";

        $baseline = [
            'slug' => $theme_slug,
            'type' => 'custom',
            'created' => date('Y-m-d H:i:s'),
            'timestamp' => time(),
            'files' => []
        ];

        $files = $this->scanThemeDirectory($theme_dir);

        foreach ($files as $file) {
            $relative_path = str_replace($theme_dir . '/', '', $file);
            $baseline['files'][$relative_path] = [
                'hash' => md5_file($file),
                'size' => filesize($file),
                'modified' => filemtime($file)
            ];
        }

        $baseline_file = $this->baseline_dir . '/' . $theme_slug . '.json';
        file_put_contents($baseline_file, json_encode($baseline, JSON_PRETTY_PRINT));

        echo "✓ Baseline created for {$theme_slug} (" . count($baseline['files']) . " files)\n";

        return [
            'success' => true,
            'slug' => $theme_slug,
            'file_count' => count($baseline['files']),
            'baseline_file' => $baseline_file
        ];
    }

    /**
     * Scan theme directory recursively
     */
    private function scanThemeDirectory($directory) {
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
     * Verify theme integrity
     */
    public function verifyTheme($theme_slug) {
        $theme_dir = $this->themes_dir . '/' . $theme_slug;

        if (!is_dir($theme_dir)) {
            return ['error' => "Theme directory not found: {$theme_slug}"];
        }

        echo "Verifying theme: {$theme_slug}...\n";

        // Check if it's a repo theme
        $repo_check = $this->isRepoTheme($theme_slug);

        if ($repo_check && $repo_check['is_repo']) {
            echo "  Repository theme detected\n";
            // For repo themes, we'll use baseline approach since SVN access is limited
            // You could enhance this to download and compare if needed
        }

        // Check against baseline
        echo "  Checking against baseline...\n";
        return $this->verifyCustomTheme($theme_slug, $theme_dir);
    }

    /**
     * Verify custom theme against baseline
     */
    private function verifyCustomTheme($slug, $theme_dir) {
        $baseline_file = $this->baseline_dir . '/' . $slug . '.json';

        if (!file_exists($baseline_file)) {
            return [
                'error' => 'No baseline found for theme',
                'slug' => $slug,
                'recommendation' => 'Create baseline with: php scanner.php create-theme-baseline ' . $slug
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
        $current_files = $this->scanThemeDirectory($theme_dir);
        $current_relative = [];

        foreach ($current_files as $file) {
            $relative = str_replace($theme_dir . '/', '', $file);
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
                    'severity' => $this->assessThemeFileSeverity($relative)
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
                'severity' => $this->assessThemeFileSeverity($relative)
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
            'readme.txt',
            'README.md',
            'LICENSE',
            'CHANGELOG.md',
            'screenshot.png',
            'screenshot.jpg',
        ];

        foreach ($ignorable as $ignore) {
            if (strpos($filename, $ignore) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Assess severity of theme file issue
     */
    private function assessThemeFileSeverity($filename) {
        // PHP files are highest risk
        if (preg_match('/\.php$/i', $filename)) {
            // functions.php is especially critical
            if (basename($filename) === 'functions.php') {
                return 'CRITICAL';
            }
            return 'HIGH';
        }

        // JavaScript files
        if (preg_match('/\.js$/i', $filename)) {
            return 'HIGH';
        }

        // CSS files (could contain encoded malware)
        if (preg_match('/\.css$/i', $filename)) {
            return 'MEDIUM';
        }

        return 'LOW';
    }

    /**
     * Verify all themes
     */
    public function verifyAllThemes() {
        $themes = $this->getInstalledThemes();

        echo "Found " . count($themes) . " installed themes\n";
        echo str_repeat("=", 50) . "\n\n";

        $results = [];

        foreach ($themes as $theme) {
            $result = $this->verifyTheme($theme['slug']);
            $result['name'] = $theme['name'];
            $result['is_active'] = $theme['is_active'];
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
     * Create baselines for all themes
     */
    public function createAllBaselines() {
        $themes = $this->getInstalledThemes();
        $created = [];

        foreach ($themes as $theme) {
            echo "\nCreating baseline for theme: {$theme['name']}\n";
            try {
                $result = $this->createThemeBaseline($theme['slug']);
                $created[] = $result;
            } catch (\Exception $e) {
                echo "  ✗ Error: " . $e->getMessage() . "\n";
            }
        }

        return [
            'created' => $created,
            'total' => count($created)
        ];
    }

    /**
     * Generate theme security report
     */
    public function generateReport() {
        $themes = $this->getInstalledThemes();
        $verification_results = [];

        foreach ($themes as $theme) {
            $result = $this->verifyTheme($theme['slug']);
            $result['name'] = $theme['name'];
            $result['is_active'] = $theme['is_active'];
            $verification_results[] = $result;
        }

        $total_issues = 0;
        $compromised_themes = [];

        foreach ($verification_results as $result) {
            if (!isset($result['error'])) {
                $issues = count($result['modified']) + count($result['extra']) + count($result['missing']);
                $total_issues += $issues;

                if ($issues > 0) {
                    $compromised_themes[] = [
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
                'total_themes' => count($themes),
                'active_theme' => count(array_filter($themes, function($t) { return $t['is_active']; })),
                'total_issues' => $total_issues,
                'themes_with_issues' => count($compromised_themes),
                'status' => $total_issues === 0 ? 'CLEAN' : 'COMPROMISED'
            ],
            'themes' => $verification_results,
            'compromised_themes' => $compromised_themes,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
