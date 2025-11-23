<?php
/**
 * File Permissions & Ownership Checker
 *
 * Audits and validates file permissions and ownership for WordPress security
 */

namespace WPScanner\Filesystem\Permissions;

class PermissionChecker {

    private $wp_root;
    private $recommended_permissions = [
        'directories' => '0755',
        'files' => '0644',
        'wp-config.php' => '0440',
        '.htaccess' => '0644'
    ];

    public function __construct($wp_root) {
        $this->wp_root = rtrim($wp_root, '/');
    }

    /**
     * Audit file permissions across WordPress installation
     */
    public function auditPermissions() {
        $results = [
            'insecure_files' => [],
            'insecure_directories' => [],
            'world_writable' => [],
            'ownership_issues' => []
        ];

        $critical_paths = [
            $this->wp_root . '/wp-config.php',
            $this->wp_root . '/.htaccess',
            $this->wp_root . '/wp-admin',
            $this->wp_root . '/wp-includes',
            $this->wp_root . '/wp-content/themes',
            $this->wp_root . '/wp-content/plugins',
            $this->wp_root . '/wp-content/uploads'
        ];

        foreach ($critical_paths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            if (is_dir($path)) {
                $this->checkDirectoryPermissions($path, $results);
            } else {
                $this->checkFilePermissions($path, $results);
            }
        }

        return $results;
    }

    /**
     * Check directory permissions recursively
     */
    private function checkDirectoryPermissions($directory, &$results) {
        $perms = substr(sprintf('%o', fileperms($directory)), -4);

        // Check if directory is world writable
        if ($this->isWorldWritable($directory)) {
            $results['world_writable'][] = [
                'path' => $directory,
                'type' => 'directory',
                'permissions' => $perms,
                'severity' => 'CRITICAL'
            ];
        }

        // Check if permissions are too permissive
        if ($perms > $this->recommended_permissions['directories']) {
            $results['insecure_directories'][] = [
                'path' => $directory,
                'current' => $perms,
                'recommended' => $this->recommended_permissions['directories'],
                'severity' => $perms === '0777' ? 'CRITICAL' : 'HIGH'
            ];
        }

        // Recursively check subdirectories and files
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                if ($item->isDir()) {
                    $item_perms = substr(sprintf('%o', $item->getPerms()), -4);
                    if ($this->isWorldWritable($item->getPathname())) {
                        $results['world_writable'][] = [
                            'path' => $item->getPathname(),
                            'type' => 'directory',
                            'permissions' => $item_perms,
                            'severity' => 'CRITICAL'
                        ];
                    }
                } else {
                    $this->checkFilePermissions($item->getPathname(), $results);
                }
            }
        } catch (\Exception $e) {
            // Handle permission errors
        }
    }

    /**
     * Check individual file permissions
     */
    private function checkFilePermissions($filepath, &$results) {
        $perms = substr(sprintf('%o', fileperms($filepath)), -4);
        $filename = basename($filepath);

        // Check for world writable files
        if ($this->isWorldWritable($filepath)) {
            $results['world_writable'][] = [
                'path' => $filepath,
                'type' => 'file',
                'permissions' => $perms,
                'severity' => 'CRITICAL'
            ];
        }

        // Check specific files
        if ($filename === 'wp-config.php') {
            if ($perms !== $this->recommended_permissions['wp-config.php']) {
                $results['insecure_files'][] = [
                    'path' => $filepath,
                    'current' => $perms,
                    'recommended' => $this->recommended_permissions['wp-config.php'],
                    'severity' => 'HIGH'
                ];
            }
        } elseif ($filename === '.htaccess') {
            if ($perms !== $this->recommended_permissions['.htaccess']) {
                $results['insecure_files'][] = [
                    'path' => $filepath,
                    'current' => $perms,
                    'recommended' => $this->recommended_permissions['.htaccess'],
                    'severity' => 'MEDIUM'
                ];
            }
        } else {
            // Regular files
            if ($perms > $this->recommended_permissions['files']) {
                $results['insecure_files'][] = [
                    'path' => $filepath,
                    'current' => $perms,
                    'recommended' => $this->recommended_permissions['files'],
                    'severity' => $perms === '0777' ? 'CRITICAL' : 'MEDIUM'
                ];
            }
        }
    }

    /**
     * Check if file/directory is world writable
     */
    private function isWorldWritable($path) {
        $perms = fileperms($path);
        return ($perms & 0x0002) !== 0;
    }

    /**
     * Check file ownership
     */
    public function checkOwnership() {
        $results = [
            'ownership_mismatches' => [],
            'group_mismatches' => []
        ];

        // Get web server user
        $web_user = posix_getpwuid(posix_geteuid());
        $web_group = posix_getgrgid(posix_getegid());

        $critical_paths = [
            $this->wp_root . '/wp-config.php',
            $this->wp_root . '/wp-content/themes',
            $this->wp_root . '/wp-content/plugins',
            $this->wp_root . '/wp-content/uploads'
        ];

        foreach ($critical_paths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            $owner = posix_getpwuid(fileowner($path));
            $group = posix_getgrgid(filegroup($path));

            if ($owner['name'] !== $web_user['name']) {
                $results['ownership_mismatches'][] = [
                    'path' => $path,
                    'current_owner' => $owner['name'],
                    'expected_owner' => $web_user['name'],
                    'severity' => 'MEDIUM'
                ];
            }

            if ($group['name'] !== $web_group['name']) {
                $results['group_mismatches'][] = [
                    'path' => $path,
                    'current_group' => $group['name'],
                    'expected_group' => $web_group['name'],
                    'severity' => 'LOW'
                ];
            }
        }

        return $results;
    }

    /**
     * Fix permissions for a file or directory
     */
    public function fixPermissions($path, $mode = null) {
        if (!file_exists($path)) {
            return ['error' => 'Path not found'];
        }

        if ($mode === null) {
            // Determine appropriate mode
            if (is_dir($path)) {
                $mode = octdec($this->recommended_permissions['directories']);
            } else {
                $filename = basename($path);
                if ($filename === 'wp-config.php') {
                    $mode = octdec($this->recommended_permissions['wp-config.php']);
                } elseif ($filename === '.htaccess') {
                    $mode = octdec($this->recommended_permissions['.htaccess']);
                } else {
                    $mode = octdec($this->recommended_permissions['files']);
                }
            }
        }

        $old_perms = substr(sprintf('%o', fileperms($path)), -4);

        if (chmod($path, $mode)) {
            return [
                'success' => true,
                'path' => $path,
                'old_permissions' => $old_perms,
                'new_permissions' => substr(sprintf('%o', $mode), -4)
            ];
        }

        return ['error' => 'Failed to change permissions'];
    }

    /**
     * Fix ownership for a file or directory
     */
    public function fixOwnership($path, $user = null, $group = null) {
        if (!file_exists($path)) {
            return ['error' => 'Path not found'];
        }

        $results = [];

        if ($user !== null) {
            if (chown($path, $user)) {
                $results['owner_changed'] = true;
            } else {
                $results['owner_error'] = 'Failed to change owner';
            }
        }

        if ($group !== null) {
            if (chgrp($path, $group)) {
                $results['group_changed'] = true;
            } else {
                $results['group_error'] = 'Failed to change group';
            }
        }

        return $results;
    }

    /**
     * Generate comprehensive permission report
     */
    public function generateReport() {
        $audit = $this->auditPermissions();
        $ownership = $this->checkOwnership();

        $total_issues = count($audit['insecure_files']) +
                       count($audit['insecure_directories']) +
                       count($audit['world_writable']) +
                       count($ownership['ownership_mismatches']);

        return [
            'summary' => [
                'total_issues' => $total_issues,
                'insecure_files' => count($audit['insecure_files']),
                'insecure_directories' => count($audit['insecure_directories']),
                'world_writable' => count($audit['world_writable']),
                'ownership_issues' => count($ownership['ownership_mismatches'])
            ],
            'details' => array_merge($audit, $ownership),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
