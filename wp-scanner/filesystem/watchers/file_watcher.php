<?php
/**
 * File System Watcher
 *
 * Monitors WordPress files for changes, additions, and deletions
 */

namespace WPScanner\Filesystem\Watchers;

class FileWatcher {

    private $wp_root;
    private $snapshot_file;
    private $watched_directories;

    public function __construct($wp_root, $snapshot_path = null) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->snapshot_file = $snapshot_path ?: WP_SCANNER_DIR . '/data/file_snapshot.json';
        $this->watched_directories = [
            $this->wp_root . '/wp-admin',
            $this->wp_root . '/wp-includes',
            $this->wp_root . '/wp-content/themes',
            $this->wp_root . '/wp-content/plugins',
            $this->wp_root . '/wp-content/uploads'
        ];
    }

    /**
     * Create initial file system snapshot
     */
    public function createSnapshot() {
        $snapshot = [
            'timestamp' => time(),
            'created' => date('Y-m-d H:i:s'),
            'files' => []
        ];

        foreach ($this->watched_directories as $directory) {
            if (!is_dir($directory)) {
                continue;
            }

            $files = $this->scanDirectory($directory);
            foreach ($files as $file) {
                $snapshot['files'][$file] = [
                    'hash' => md5_file($file),
                    'size' => filesize($file),
                    'modified' => filemtime($file),
                    'permissions' => substr(sprintf('%o', fileperms($file)), -4)
                ];
            }
        }

        file_put_contents($this->snapshot_file, json_encode($snapshot, JSON_PRETTY_PRINT));
        return [
            'success' => true,
            'files_tracked' => count($snapshot['files']),
            'snapshot_file' => $this->snapshot_file
        ];
    }

    /**
     * Compare current state to snapshot
     */
    public function detectChanges() {
        if (!file_exists($this->snapshot_file)) {
            return ['error' => 'No snapshot found. Create one first.'];
        }

        $snapshot = json_decode(file_get_contents($this->snapshot_file), true);
        $current_files = $this->getCurrentFileState();

        $changes = [
            'added' => [],
            'modified' => [],
            'deleted' => [],
            'permissions_changed' => []
        ];

        // Find added and modified files
        foreach ($current_files as $filepath => $file_data) {
            if (!isset($snapshot['files'][$filepath])) {
                // New file added
                $changes['added'][] = [
                    'path' => $filepath,
                    'size' => $file_data['size'],
                    'modified' => date('Y-m-d H:i:s', $file_data['modified']),
                    'severity' => $this->assessSeverity($filepath, 'added')
                ];
            } else {
                // Check if file was modified
                if ($file_data['hash'] !== $snapshot['files'][$filepath]['hash']) {
                    $changes['modified'][] = [
                        'path' => $filepath,
                        'old_hash' => $snapshot['files'][$filepath]['hash'],
                        'new_hash' => $file_data['hash'],
                        'modified' => date('Y-m-d H:i:s', $file_data['modified']),
                        'severity' => $this->assessSeverity($filepath, 'modified')
                    ];
                }

                // Check if permissions changed
                if ($file_data['permissions'] !== $snapshot['files'][$filepath]['permissions']) {
                    $changes['permissions_changed'][] = [
                        'path' => $filepath,
                        'old_permissions' => $snapshot['files'][$filepath]['permissions'],
                        'new_permissions' => $file_data['permissions']
                    ];
                }
            }
        }

        // Find deleted files
        foreach ($snapshot['files'] as $filepath => $file_data) {
            if (!isset($current_files[$filepath])) {
                $changes['deleted'][] = [
                    'path' => $filepath,
                    'last_known_hash' => $file_data['hash'],
                    'severity' => $this->assessSeverity($filepath, 'deleted')
                ];
            }
        }

        return [
            'changes_detected' => !empty($changes['added']) || !empty($changes['modified']) || !empty($changes['deleted']),
            'summary' => [
                'added' => count($changes['added']),
                'modified' => count($changes['modified']),
                'deleted' => count($changes['deleted']),
                'permissions_changed' => count($changes['permissions_changed'])
            ],
            'changes' => $changes,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Get current file system state
     */
    private function getCurrentFileState() {
        $files = [];

        foreach ($this->watched_directories as $directory) {
            if (!is_dir($directory)) {
                continue;
            }

            $scanned = $this->scanDirectory($directory);
            foreach ($scanned as $file) {
                if (file_exists($file)) {
                    $files[$file] = [
                        'hash' => md5_file($file),
                        'size' => filesize($file),
                        'modified' => filemtime($file),
                        'permissions' => substr(sprintf('%o', fileperms($file)), -4)
                    ];
                }
            }
        }

        return $files;
    }

    /**
     * Scan directory recursively
     */
    private function scanDirectory($directory) {
        $files = [];

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $files[] = $file->getPathname();
                }
            }
        } catch (\Exception $e) {
            // Handle permission errors, etc.
        }

        return $files;
    }

    /**
     * Assess severity of file change
     */
    private function assessSeverity($filepath, $change_type) {
        // Critical locations
        if (strpos($filepath, '/wp-admin/') !== false ||
            strpos($filepath, '/wp-includes/') !== false) {
            return 'CRITICAL';
        }

        // Uploads directory
        if (strpos($filepath, '/wp-content/uploads/') !== false) {
            // PHP files in uploads are critical
            if (preg_match('/\.php\d?$/i', $filepath)) {
                return 'CRITICAL';
            }
            return 'MEDIUM';
        }

        // Plugin/theme modifications
        if (strpos($filepath, '/wp-content/plugins/') !== false ||
            strpos($filepath, '/wp-content/themes/') !== false) {
            return 'HIGH';
        }

        return 'LOW';
    }

    /**
     * Monitor specific file for changes
     */
    public function watchFile($filepath) {
        if (!file_exists($filepath)) {
            return ['error' => 'File not found'];
        }

        return [
            'path' => $filepath,
            'hash' => md5_file($filepath),
            'size' => filesize($filepath),
            'modified' => date('Y-m-d H:i:s', filemtime($filepath)),
            'permissions' => substr(sprintf('%o', fileperms($filepath)), -4),
            'owner' => posix_getpwuid(fileowner($filepath)),
            'group' => posix_getgrgid(filegroup($filepath))
        ];
    }

    /**
     * Real-time monitoring (requires inotify extension)
     */
    public function startRealtimeMonitoring() {
        if (!extension_loaded('inotify')) {
            return ['error' => 'inotify extension not available'];
        }

        $inotify = inotify_init();
        $watches = [];

        foreach ($this->watched_directories as $directory) {
            if (is_dir($directory)) {
                $watches[$directory] = inotify_add_watch(
                    $inotify,
                    $directory,
                    IN_MODIFY | IN_CREATE | IN_DELETE | IN_ATTRIB
                );
            }
        }

        return [
            'status' => 'monitoring_started',
            'watched_directories' => count($watches),
            'inotify_descriptor' => $inotify
        ];
    }
}
