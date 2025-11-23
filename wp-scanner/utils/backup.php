<?php
/**
 * Backup Utility
 *
 * Create and manage backups before making changes
 */

namespace WPScanner\Utils;

class Backup {

    private $backup_dir;
    private $wp_root;

    public function __construct($wp_root, $backup_dir = null) {
        $this->wp_root = rtrim($wp_root, '/');
        $this->backup_dir = $backup_dir ?: WP_SCANNER_DIR . '/backups/';

        if (!is_dir($this->backup_dir)) {
            mkdir($this->backup_dir, 0755, true);
        }
    }

    /**
     * Backup a single file
     */
    public function backupFile($filepath) {
        $filepath = Security::validatePath($filepath);

        if (!file_exists($filepath)) {
            throw new \Exception('File not found');
        }

        $filename = basename($filepath);
        $timestamp = date('Y-m-d_His');
        $backup_name = sprintf('%s.%s.backup', $filename, $timestamp);
        $backup_path = $this->backup_dir . $backup_name;

        if (!copy($filepath, $backup_path)) {
            throw new \Exception('Failed to create backup');
        }

        // Create metadata
        $metadata = [
            'original_path' => $filepath,
            'backup_path' => $backup_path,
            'timestamp' => time(),
            'created' => date('Y-m-d H:i:s'),
            'size' => filesize($filepath),
            'hash' => md5_file($filepath),
            'permissions' => substr(sprintf('%o', fileperms($filepath)), -4)
        ];

        file_put_contents(
            $backup_path . '.meta',
            json_encode($metadata, JSON_PRETTY_PRINT)
        );

        return [
            'success' => true,
            'backup_path' => $backup_path,
            'metadata' => $metadata
        ];
    }

    /**
     * Backup multiple files
     */
    public function backupFiles($filepaths) {
        $results = [];

        foreach ($filepaths as $filepath) {
            try {
                $results[] = $this->backupFile($filepath);
            } catch (\Exception $e) {
                $results[] = [
                    'error' => $e->getMessage(),
                    'file' => $filepath
                ];
            }
        }

        return $results;
    }

    /**
     * Backup entire directory
     */
    public function backupDirectory($directory, $exclude = []) {
        $directory = Security::validatePath($directory);

        if (!is_dir($directory)) {
            throw new \Exception('Directory not found');
        }

        $dir_name = basename($directory);
        $timestamp = date('Y-m-d_His');
        $backup_name = sprintf('%s_%s.tar.gz', $dir_name, $timestamp);
        $backup_path = $this->backup_dir . $backup_name;

        // Build tar command with exclusions
        $exclude_args = '';
        foreach ($exclude as $pattern) {
            $exclude_args .= sprintf(' --exclude="%s"', escapeshellarg($pattern));
        }

        $command = sprintf(
            'tar -czf %s -C %s %s %s 2>&1',
            escapeshellarg($backup_path),
            escapeshellarg(dirname($directory)),
            $exclude_args,
            escapeshellarg($dir_name)
        );

        exec($command, $output, $return_code);

        if ($return_code !== 0) {
            throw new \Exception('Backup failed: ' . implode("\n", $output));
        }

        return [
            'success' => true,
            'backup_path' => $backup_path,
            'size' => filesize($backup_path),
            'created' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Backup WordPress database
     */
    public function backupDatabase($wpdb = null) {
        if ($wpdb === null && !isset($GLOBALS['wpdb'])) {
            throw new \Exception('Database connection not available');
        }

        $wpdb = $wpdb ?: $GLOBALS['wpdb'];

        // Get database credentials from wp-config.php
        $wp_config = $this->wp_root . '/wp-config.php';
        if (!file_exists($wp_config)) {
            throw new \Exception('wp-config.php not found');
        }

        require_once $wp_config;

        $timestamp = date('Y-m-d_His');
        $backup_name = sprintf('database_%s.sql', $timestamp);
        $backup_path = $this->backup_dir . $backup_name;

        // Use mysqldump
        $command = sprintf(
            'mysqldump --user=%s --password=%s --host=%s %s > %s 2>&1',
            escapeshellarg(DB_USER),
            escapeshellarg(DB_PASSWORD),
            escapeshellarg(DB_HOST),
            escapeshellarg(DB_NAME),
            escapeshellarg($backup_path)
        );

        exec($command, $output, $return_code);

        if ($return_code !== 0) {
            throw new \Exception('Database backup failed: ' . implode("\n", $output));
        }

        // Compress the backup
        $compressed = $backup_path . '.gz';
        exec(sprintf('gzip %s', escapeshellarg($backup_path)), $output, $return_code);

        if ($return_code === 0 && file_exists($compressed)) {
            $backup_path = $compressed;
        }

        return [
            'success' => true,
            'backup_path' => $backup_path,
            'size' => filesize($backup_path),
            'created' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Create full WordPress backup (files + database)
     */
    public function fullBackup($auto_confirm = false) {
        if (!Security::confirmDestructive(
            "This will create a full backup of WordPress files and database. This may take several minutes.",
            $auto_confirm
        )) {
            return ['cancelled' => true];
        }

        echo "Creating full WordPress backup...\n";

        $results = [];

        // Backup critical files
        echo "Backing up critical files...\n";
        $critical_files = [
            $this->wp_root . '/wp-config.php',
            $this->wp_root . '/.htaccess',
        ];

        try {
            $results['critical_files'] = $this->backupFiles($critical_files);
        } catch (\Exception $e) {
            $results['critical_files_error'] = $e->getMessage();
        }

        // Backup wp-content directory
        echo "Backing up wp-content directory...\n";
        try {
            $results['wp_content'] = $this->backupDirectory(
                $this->wp_root . '/wp-content',
                ['cache', 'upgrade', '*.log']
            );
        } catch (\Exception $e) {
            $results['wp_content_error'] = $e->getMessage();
        }

        // Backup database
        echo "Backing up database...\n";
        try {
            $results['database'] = $this->backupDatabase();
        } catch (\Exception $e) {
            $results['database_error'] = $e->getMessage();
        }

        echo "✓ Backup completed\n";

        return [
            'success' => true,
            'results' => $results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Restore a file from backup
     */
    public function restoreFile($backup_path, $auto_confirm = false) {
        if (!file_exists($backup_path)) {
            throw new \Exception('Backup file not found');
        }

        $meta_file = $backup_path . '.meta';
        if (!file_exists($meta_file)) {
            throw new \Exception('Backup metadata not found');
        }

        $metadata = json_decode(file_get_contents($meta_file), true);
        $original_path = $metadata['original_path'];

        if (!Security::confirmDestructive(
            "This will restore {$original_path} from backup. Current file will be overwritten.",
            $auto_confirm
        )) {
            return ['cancelled' => true];
        }

        // Validate path
        $original_path = Security::validatePath($original_path);

        // Create a backup of the current file before restoring
        if (file_exists($original_path)) {
            $current_backup = $original_path . '.before_restore.' . time();
            copy($original_path, $current_backup);
        }

        // Restore file
        if (!copy($backup_path, $original_path)) {
            throw new \Exception('Failed to restore file');
        }

        // Restore permissions
        if (isset($metadata['permissions'])) {
            chmod($original_path, octdec($metadata['permissions']));
        }

        return [
            'success' => true,
            'restored_to' => $original_path,
            'from_backup' => $backup_path
        ];
    }

    /**
     * List all backups
     */
    public function listBackups() {
        $backups = [];

        $files = glob($this->backup_dir . '*');

        foreach ($files as $file) {
            if (pathinfo($file, PATHINFO_EXTENSION) === 'meta') {
                continue;
            }

            $meta_file = $file . '.meta';
            $metadata = null;

            if (file_exists($meta_file)) {
                $metadata = json_decode(file_get_contents($meta_file), true);
            }

            $backups[] = [
                'backup_path' => $file,
                'filename' => basename($file),
                'size' => filesize($file),
                'size_human' => $this->formatBytes(filesize($file)),
                'created' => date('Y-m-d H:i:s', filemtime($file)),
                'metadata' => $metadata
            ];
        }

        // Sort by creation time (newest first)
        usort($backups, function($a, $b) {
            return filemtime($b['backup_path']) - filemtime($a['backup_path']);
        });

        return $backups;
    }

    /**
     * Clean old backups
     */
    public function cleanOldBackups($days = 30) {
        $cutoff = time() - ($days * 86400);
        $deleted = [];

        $files = glob($this->backup_dir . '*');

        foreach ($files as $file) {
            if (filemtime($file) < $cutoff) {
                if (unlink($file)) {
                    $deleted[] = basename($file);
                }
            }
        }

        return [
            'deleted' => $deleted,
            'total_deleted' => count($deleted)
        ];
    }

    /**
     * Format bytes to human readable
     */
    private function formatBytes($bytes) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;

        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Get total backup size
     */
    public function getTotalBackupSize() {
        $total = 0;
        $files = glob($this->backup_dir . '*');

        foreach ($files as $file) {
            $total += filesize($file);
        }

        return [
            'bytes' => $total,
            'human' => $this->formatBytes($total),
            'file_count' => count($files)
        ];
    }
}
