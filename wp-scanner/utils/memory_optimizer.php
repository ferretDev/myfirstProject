<?php
/**
 * Memory Optimizer
 *
 * Provides memory-efficient file reading, pattern caching, and resource management
 * Prevents memory exhaustion on large WordPress installations
 */

namespace WPScanner\Utils;

class MemoryOptimizer {

    // Singleton pattern cache
    private static $pattern_cache = null;
    private static $instance = null;

    // Configuration
    private $max_file_size = 10485760; // 10MB default
    private $chunk_size = 8192; // 8KB chunks for streaming
    private $memory_limit = null;
    private $memory_threshold = 0.8; // 80% threshold

    private function __construct() {
        $this->memory_limit = $this->getMemoryLimit();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Get PHP memory limit in bytes
     */
    private function getMemoryLimit() {
        $memory_limit = ini_get('memory_limit');

        if ($memory_limit == -1) {
            return PHP_INT_MAX; // No limit
        }

        // Convert shorthand notation to bytes
        $unit = strtolower(substr($memory_limit, -1));
        $value = (int)$memory_limit;

        switch ($unit) {
            case 'g':
                $value *= 1024;
            case 'm':
                $value *= 1024;
            case 'k':
                $value *= 1024;
        }

        return $value;
    }

    /**
     * Check if we're approaching memory limit
     */
    public function checkMemoryUsage() {
        $used = memory_get_usage(true);
        $limit = $this->memory_limit;

        if ($limit === PHP_INT_MAX) {
            return true; // No limit
        }

        $percentage = $used / $limit;

        return [
            'safe' => $percentage < $this->memory_threshold,
            'used' => $used,
            'limit' => $limit,
            'percentage' => round($percentage * 100, 2),
            'available' => $limit - $used
        ];
    }

    /**
     * Memory-safe file reader
     * Only loads file if it's within size limits
     */
    public function safeReadFile($filepath, $max_size = null) {
        $max_size = $max_size ?: $this->max_file_size;

        if (!file_exists($filepath)) {
            throw new \Exception("File not found: {$filepath}");
        }

        $filesize = filesize($filepath);

        // Check if file is too large
        if ($filesize > $max_size) {
            return [
                'success' => false,
                'error' => 'FILE_TOO_LARGE',
                'size' => $filesize,
                'max_size' => $max_size,
                'message' => "File exceeds maximum size ({$filesize} > {$max_size})"
            ];
        }

        // Check memory availability
        $memory_check = $this->checkMemoryUsage();
        if (!$memory_check['safe']) {
            return [
                'success' => false,
                'error' => 'INSUFFICIENT_MEMORY',
                'memory_usage' => $memory_check['percentage'] . '%',
                'message' => 'Insufficient memory available'
            ];
        }

        // Safe to read
        $content = file_get_contents($filepath);

        return [
            'success' => true,
            'content' => $content,
            'size' => $filesize
        ];
    }

    /**
     * Stream-based file scanner for large files
     * Scans without loading entire file into memory
     */
    public function streamScanFile($filepath, $patterns, $max_line_length = 8192) {
        if (!file_exists($filepath)) {
            throw new \Exception("File not found: {$filepath}");
        }

        $handle = fopen($filepath, 'r');
        if (!$handle) {
            throw new \Exception("Cannot open file: {$filepath}");
        }

        $matches = [];
        $line_number = 0;

        while (!feof($handle)) {
            $line = fgets($handle, $max_line_length);
            $line_number++;

            // Check patterns
            foreach ($patterns as $category => $pattern_list) {
                if (is_array($pattern_list)) {
                    foreach ($pattern_list as $name => $pattern) {
                        if (is_array($pattern)) {
                            foreach ($pattern as $p) {
                                if (@preg_match($p, $line)) {
                                    $matches[] = [
                                        'line' => $line_number,
                                        'category' => $category,
                                        'pattern' => $name,
                                        'preview' => substr($line, 0, 100)
                                    ];
                                }
                            }
                        } else {
                            if (@preg_match($pattern, $line)) {
                                $matches[] = [
                                    'line' => $line_number,
                                    'category' => $category,
                                    'pattern' => $name,
                                    'preview' => substr($line, 0, 100)
                                ];
                            }
                        }
                    }
                }
            }

            // Yield control periodically to prevent blocking
            if ($line_number % 1000 == 0) {
                usleep(1); // Microsleep to prevent CPU hogging
            }
        }

        fclose($handle);

        return [
            'success' => true,
            'matches' => $matches,
            'lines_scanned' => $line_number
        ];
    }

    /**
     * Get cached patterns (singleton pattern)
     * Prevents loading patterns multiple times
     */
    public static function getCachedPatterns() {
        if (self::$pattern_cache === null) {
            require_once WP_SCANNER_DIR . '/database/patterns/malicious_patterns.php';
            self::$pattern_cache = \WPScanner\Database\Patterns\MaliciousPatterns::getPatterns();
        }

        return self::$pattern_cache;
    }

    /**
     * Load patterns with custom patterns merged
     */
    public static function getOptimizedPatterns() {
        // Load base patterns (cached)
        $patterns = self::getCachedPatterns();

        // Load custom patterns if pattern updater exists
        if (class_exists('WPScanner\Database\Patterns\PatternUpdater')) {
            try {
                require_once WP_SCANNER_DIR . '/database/patterns/pattern_updater.php';
                $updater = new \WPScanner\Database\Patterns\PatternUpdater();
                $custom_patterns = $updater->loadCustomPatterns();

                // Merge custom patterns
                foreach ($custom_patterns as $category => $custom_list) {
                    if (!isset($patterns[$category])) {
                        $patterns[$category] = [];
                    }

                    foreach ($custom_list as $pattern_data) {
                        if ($pattern_data['enabled']) {
                            $patterns[$category][] = $pattern_data['pattern'];
                        }
                    }
                }
            } catch (\Exception $e) {
                // Silently fall back to default patterns
            }
        }

        return $patterns;
    }

    /**
     * Clear pattern cache (useful after adding new patterns)
     */
    public static function clearPatternCache() {
        self::$pattern_cache = null;
    }

    /**
     * Batch process array in chunks to manage memory
     */
    public function batchProcess($items, $callback, $batch_size = 100) {
        $results = [];
        $total = count($items);
        $processed = 0;

        for ($i = 0; $i < $total; $i += $batch_size) {
            $batch = array_slice($items, $i, $batch_size);

            foreach ($batch as $item) {
                $results[] = $callback($item);
                $processed++;
            }

            // Check memory after each batch
            $memory_check = $this->checkMemoryUsage();
            if (!$memory_check['safe']) {
                return [
                    'success' => false,
                    'error' => 'MEMORY_LIMIT_REACHED',
                    'processed' => $processed,
                    'total' => $total,
                    'results' => $results,
                    'memory_usage' => $memory_check['percentage'] . '%'
                ];
            }

            // Force garbage collection between batches
            gc_collect_cycles();
        }

        return [
            'success' => true,
            'processed' => $processed,
            'total' => $total,
            'results' => $results
        ];
    }

    /**
     * Database query with chunking
     */
    public function chunkQuery($wpdb, $query, $callback, $chunk_size = 1000) {
        $offset = 0;
        $total_processed = 0;

        while (true) {
            $chunked_query = $query . " LIMIT {$chunk_size} OFFSET {$offset}";
            $results = $wpdb->get_results($chunked_query);

            if (empty($results)) {
                break; // No more results
            }

            foreach ($results as $row) {
                $callback($row);
                $total_processed++;
            }

            $offset += $chunk_size;

            // Check memory between chunks
            $memory_check = $this->checkMemoryUsage();
            if (!$memory_check['safe']) {
                return [
                    'success' => false,
                    'error' => 'MEMORY_LIMIT_REACHED',
                    'processed' => $total_processed,
                    'memory_usage' => $memory_check['percentage'] . '%'
                ];
            }

            // Cleanup
            gc_collect_cycles();
        }

        return [
            'success' => true,
            'processed' => $total_processed
        ];
    }

    /**
     * Get memory statistics
     */
    public function getMemoryStats() {
        return [
            'current_usage' => memory_get_usage(true),
            'current_usage_mb' => round(memory_get_usage(true) / 1024 / 1024, 2),
            'peak_usage' => memory_get_peak_usage(true),
            'peak_usage_mb' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'limit' => $this->memory_limit,
            'limit_mb' => $this->memory_limit === PHP_INT_MAX ? 'unlimited' : round($this->memory_limit / 1024 / 1024, 2),
            'percentage_used' => $this->memory_limit === PHP_INT_MAX ? 0 : round((memory_get_usage(true) / $this->memory_limit) * 100, 2),
            'available' => $this->memory_limit === PHP_INT_MAX ? 'unlimited' : $this->memory_limit - memory_get_usage(true),
            'available_mb' => $this->memory_limit === PHP_INT_MAX ? 'unlimited' : round(($this->memory_limit - memory_get_usage(true)) / 1024 / 1024, 2)
        ];
    }

    /**
     * Set maximum file size for scanning
     */
    public function setMaxFileSize($bytes) {
        $this->max_file_size = $bytes;
    }

    /**
     * Set memory threshold (percentage)
     */
    public function setMemoryThreshold($percentage) {
        $this->memory_threshold = $percentage;
    }

    /**
     * Format bytes to human-readable
     */
    public static function formatBytes($bytes, $precision = 2) {
        if ($bytes === PHP_INT_MAX || $bytes < 0) {
            return 'Unlimited';
        }

        $units = ['B', 'KB', 'MB', 'GB', 'TB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, $precision) . ' ' . $units[$i];
    }

    /**
     * Log memory usage
     */
    public function logMemoryUsage($context = '') {
        $stats = $this->getMemoryStats();

        $logger = new Logger();
        $logger->info("Memory Usage [{$context}]: {$stats['current_usage_mb']}MB / {$stats['limit_mb']}MB ({$stats['percentage_used']}%)");

        return $stats;
    }
}
