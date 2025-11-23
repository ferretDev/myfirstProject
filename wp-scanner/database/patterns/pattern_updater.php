<?php
/**
 * Malware Pattern Updater
 *
 * Allows updating malware patterns from remote sources or custom files
 * Provides version control and automatic updates
 */

namespace WPScanner\Database\Patterns;

use WPScanner\Utils\Security;
use WPScanner\Utils\Logger;

class PatternUpdater {

    private $pattern_dir;
    private $custom_pattern_file;
    private $version_file;
    private $logger;

    // Official pattern sources (can be configured)
    private $remote_sources = [
        'wordpress_signatures' => 'https://raw.githubusercontent.com/WordPress/wpcs-docs/master/inline-documentation-standards.md',
        // Add your own pattern repository URL here
    ];

    public function __construct() {
        $this->pattern_dir = WP_SCANNER_DIR . '/database/patterns/';
        $this->custom_pattern_file = $this->pattern_dir . 'custom_patterns.json';
        $this->version_file = $this->pattern_dir . 'pattern_version.json';
        $this->logger = new Logger();

        if (!is_dir($this->pattern_dir)) {
            mkdir($this->pattern_dir, 0755, true);
        }
    }

    /**
     * Get current pattern version
     */
    public function getCurrentVersion() {
        if (!file_exists($this->version_file)) {
            return [
                'version' => '1.0.0',
                'last_updated' => null,
                'pattern_count' => 0,
                'custom_patterns' => 0
            ];
        }

        return json_decode(file_get_contents($this->version_file), true);
    }

    /**
     * Update pattern version info
     */
    private function updateVersionInfo($pattern_count, $custom_count) {
        $version_info = [
            'version' => '2.0.0',
            'last_updated' => date('Y-m-d H:i:s'),
            'pattern_count' => $pattern_count,
            'custom_patterns' => $custom_count,
            'scanner_version' => '2.0.0'
        ];

        file_put_contents($this->version_file, json_encode($version_info, JSON_PRETTY_PRINT));
        return $version_info;
    }

    /**
     * Load custom patterns
     */
    public function loadCustomPatterns() {
        if (!file_exists($this->custom_pattern_file)) {
            return [];
        }

        $patterns = json_decode(file_get_contents($this->custom_pattern_file), true);
        return $patterns ?? [];
    }

    /**
     * Add custom pattern
     */
    public function addCustomPattern($category, $pattern, $description, $severity = 'HIGH') {
        // Validate regex pattern (prevent ReDoS)
        if (!Security::sanitizeRegex($pattern)) {
            throw new \Exception('Invalid or potentially dangerous regex pattern');
        }

        $custom_patterns = $this->loadCustomPatterns();

        if (!isset($custom_patterns[$category])) {
            $custom_patterns[$category] = [];
        }

        $custom_patterns[$category][] = [
            'pattern' => $pattern,
            'description' => $description,
            'severity' => $severity,
            'added' => date('Y-m-d H:i:s'),
            'enabled' => true
        ];

        file_put_contents($this->custom_pattern_file, json_encode($custom_patterns, JSON_PRETTY_PRINT));

        $this->logger->info("Custom pattern added: {$category} - {$description}");

        return [
            'success' => true,
            'category' => $category,
            'total_custom_patterns' => count($custom_patterns)
        ];
    }

    /**
     * Remove custom pattern by index
     */
    public function removeCustomPattern($category, $index) {
        $custom_patterns = $this->loadCustomPatterns();

        if (!isset($custom_patterns[$category][$index])) {
            throw new \Exception("Pattern not found in category: {$category}");
        }

        unset($custom_patterns[$category][$index]);
        $custom_patterns[$category] = array_values($custom_patterns[$category]); // Re-index

        file_put_contents($this->custom_pattern_file, json_encode($custom_patterns, JSON_PRETTY_PRINT));

        $this->logger->info("Custom pattern removed: {$category}[{$index}]");

        return [
            'success' => true,
            'category' => $category,
            'remaining' => count($custom_patterns[$category])
        ];
    }

    /**
     * Toggle pattern enabled/disabled
     */
    public function togglePattern($category, $index) {
        $custom_patterns = $this->loadCustomPatterns();

        if (!isset($custom_patterns[$category][$index])) {
            throw new \Exception("Pattern not found in category: {$category}");
        }

        $current_status = $custom_patterns[$category][$index]['enabled'] ?? true;
        $custom_patterns[$category][$index]['enabled'] = !$current_status;

        file_put_contents($this->custom_pattern_file, json_encode($custom_patterns, JSON_PRETTY_PRINT));

        $new_status = $custom_patterns[$category][$index]['enabled'] ? 'enabled' : 'disabled';
        $this->logger->info("Pattern {$new_status}: {$category}[{$index}]");

        return [
            'success' => true,
            'category' => $category,
            'index' => $index,
            'enabled' => $custom_patterns[$category][$index]['enabled']
        ];
    }

    /**
     * Merge custom patterns with default patterns
     */
    public function getMergedPatterns() {
        // Load default patterns from malicious_patterns.php
        require_once $this->pattern_dir . 'malicious_patterns.php';
        $default_patterns = \WPScanner\Database\Patterns\MaliciousPatterns::getPatterns();

        // Load custom patterns
        $custom_patterns = $this->loadCustomPatterns();

        // Merge patterns
        foreach ($custom_patterns as $category => $patterns) {
            if (!isset($default_patterns[$category])) {
                $default_patterns[$category] = [];
            }

            // Add enabled custom patterns
            foreach ($patterns as $pattern_data) {
                if ($pattern_data['enabled']) {
                    $default_patterns[$category][] = $pattern_data['pattern'];
                }
            }
        }

        return $default_patterns;
    }

    /**
     * Export patterns to file (for backup/sharing)
     */
    public function exportPatterns($output_file) {
        Security::validatePath($output_file);

        $export_data = [
            'version' => $this->getCurrentVersion(),
            'exported' => date('Y-m-d H:i:s'),
            'custom_patterns' => $this->loadCustomPatterns(),
            'default_patterns' => \WPScanner\Database\Patterns\MaliciousPatterns::getPatterns()
        ];

        file_put_contents($output_file, json_encode($export_data, JSON_PRETTY_PRINT));

        $this->logger->info("Patterns exported to: {$output_file}");

        return [
            'success' => true,
            'file' => $output_file,
            'size' => filesize($output_file)
        ];
    }

    /**
     * Import patterns from file
     */
    public function importPatterns($input_file, $merge = true) {
        Security::validatePath($input_file);

        if (!file_exists($input_file)) {
            throw new \Exception("Import file not found: {$input_file}");
        }

        $import_data = json_decode(file_get_contents($input_file), true);

        if (!isset($import_data['custom_patterns'])) {
            throw new \Exception("Invalid pattern file format");
        }

        if ($merge) {
            // Merge with existing patterns
            $existing_patterns = $this->loadCustomPatterns();
            $custom_patterns = array_merge_recursive($existing_patterns, $import_data['custom_patterns']);
        } else {
            // Replace existing patterns
            $custom_patterns = $import_data['custom_patterns'];
        }

        file_put_contents($this->custom_pattern_file, json_encode($custom_patterns, JSON_PRETTY_PRINT));

        $this->logger->info("Patterns imported from: {$input_file}");

        return [
            'success' => true,
            'imported' => count($custom_patterns),
            'merge_mode' => $merge
        ];
    }

    /**
     * List all patterns with metadata
     */
    public function listAllPatterns() {
        $default_patterns = \WPScanner\Database\Patterns\MaliciousPatterns::getPatterns();
        $custom_patterns = $this->loadCustomPatterns();

        $summary = [
            'default_categories' => count($default_patterns),
            'custom_categories' => count($custom_patterns),
            'total_default_patterns' => 0,
            'total_custom_patterns' => 0,
            'categories' => []
        ];

        // Count default patterns
        foreach ($default_patterns as $category => $patterns) {
            $count = count($patterns);
            $summary['total_default_patterns'] += $count;
            $summary['categories'][$category] = [
                'default_count' => $count,
                'custom_count' => 0,
                'custom_patterns' => []
            ];
        }

        // Count custom patterns
        foreach ($custom_patterns as $category => $patterns) {
            $enabled_count = 0;
            foreach ($patterns as $idx => $pattern_data) {
                if ($pattern_data['enabled']) {
                    $enabled_count++;
                }
            }

            $summary['total_custom_patterns'] += $enabled_count;

            if (!isset($summary['categories'][$category])) {
                $summary['categories'][$category] = [
                    'default_count' => 0,
                    'custom_count' => 0,
                    'custom_patterns' => []
                ];
            }

            $summary['categories'][$category]['custom_count'] = $enabled_count;
            $summary['categories'][$category]['custom_patterns'] = $patterns;
        }

        return $summary;
    }

    /**
     * Test pattern against sample text
     */
    public function testPattern($pattern, $sample_text) {
        // Validate regex pattern
        if (!Security::sanitizeRegex($pattern)) {
            throw new \Exception('Invalid or potentially dangerous regex pattern');
        }

        $matches = [];
        $result = @preg_match($pattern, $sample_text, $matches);

        if ($result === false) {
            return [
                'success' => false,
                'error' => 'Invalid regex pattern',
                'pattern' => $pattern
            ];
        }

        return [
            'success' => true,
            'matched' => $result === 1,
            'pattern' => $pattern,
            'matches' => $matches,
            'sample_length' => strlen($sample_text)
        ];
    }

    /**
     * Generate pattern statistics
     */
    public function generateStatistics() {
        $patterns = $this->listAllPatterns();
        $version = $this->getCurrentVersion();

        return [
            'version_info' => $version,
            'pattern_summary' => $patterns,
            'generated' => date('Y-m-d H:i:s')
        ];
    }
}
