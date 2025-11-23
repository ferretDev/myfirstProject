<?php
/**
 * User Role Editor & Manager
 *
 * Manage WordPress user roles and capabilities with security oversight
 */

namespace WPScanner\Utils;

class UserRoleEditor {

    private $db;

    public function __construct($wpdb) {
        $this->db = $wpdb;
    }

    /**
     * Get all users with their roles
     */
    public function getAllUsers() {
        $users = $this->db->get_results("
            SELECT ID, user_login, user_email, user_registered, display_name
            FROM {$this->db->prefix}users
            ORDER BY user_registered DESC
        ");

        $users_with_roles = [];

        foreach ($users as $user) {
            $user_meta = get_userdata($user->ID);
            $users_with_roles[] = [
                'id' => $user->ID,
                'login' => $user->user_login,
                'email' => $user->user_email,
                'registered' => $user->user_registered,
                'display_name' => $user->display_name,
                'roles' => $user_meta ? $user_meta->roles : [],
            ];
        }

        return $users_with_roles;
    }

    /**
     * Get users by role
     */
    public function getUsersByRole($role) {
        $users = get_users(['role' => $role]);
        $result = [];

        foreach ($users as $user) {
            $result[] = [
                'id' => $user->ID,
                'login' => $user->user_login,
                'email' => $user->user_email,
                'registered' => $user->user_registered,
                'roles' => $user->roles,
            ];
        }

        return $result;
    }

    /**
     * Get all administrator accounts
     */
    public function getAdministrators() {
        return $this->getUsersByRole('administrator');
    }

    /**
     * Audit user roles for security issues
     */
    public function auditUserRoles() {
        $issues = [];

        // Check for recently created admins
        $recent_admins = $this->db->get_results("
            SELECT u.ID, u.user_login, u.user_email, u.user_registered
            FROM {$this->db->prefix}users u
            INNER JOIN {$this->db->prefix}usermeta um ON u.ID = um.user_id
            WHERE um.meta_key = '{$this->db->prefix}capabilities'
            AND um.meta_value LIKE '%administrator%'
            AND u.user_registered >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");

        if (!empty($recent_admins)) {
            $issues['recent_admins'] = [
                'severity' => 'HIGH',
                'count' => count($recent_admins),
                'users' => $recent_admins,
                'message' => 'Administrator accounts created in the last 7 days'
            ];
        }

        // Check for suspicious usernames
        $suspicious_patterns = ['admin', 'test', 'demo', 'guest', 'root'];
        foreach ($suspicious_patterns as $pattern) {
            $users = $this->db->get_results($this->db->prepare("
                SELECT ID, user_login, user_email
                FROM {$this->db->prefix}users
                WHERE user_login LIKE %s
            ", '%' . $pattern . '%'));

            if (!empty($users)) {
                $issues['suspicious_usernames'][$pattern] = [
                    'severity' => 'MEDIUM',
                    'count' => count($users),
                    'users' => $users
                ];
            }
        }

        // Check for users with editor+ role and suspicious email domains
        $suspicious_domains = ['temp', 'throwaway', 'guerrilla'];
        $privileged_users = get_users(['role__in' => ['administrator', 'editor']]);

        foreach ($privileged_users as $user) {
            $email_domain = substr(strrchr($user->user_email, "@"), 1);
            foreach ($suspicious_domains as $suspicious) {
                if (stripos($email_domain, $suspicious) !== false) {
                    $issues['suspicious_emails'][] = [
                        'severity' => 'MEDIUM',
                        'user_id' => $user->ID,
                        'login' => $user->user_login,
                        'email' => $user->user_email,
                        'roles' => $user->roles
                    ];
                }
            }
        }

        return $issues;
    }

    /**
     * Change user role
     */
    public function changeUserRole($user_id, $new_role) {
        $user = get_userdata($user_id);

        if (!$user) {
            return ['error' => 'User not found'];
        }

        $old_roles = $user->roles;

        // Remove all current roles
        foreach ($old_roles as $role) {
            $user->remove_role($role);
        }

        // Add new role
        $user->add_role($new_role);

        return [
            'success' => true,
            'user_id' => $user_id,
            'user_login' => $user->user_login,
            'old_roles' => $old_roles,
            'new_role' => $new_role,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Remove user role (demote)
     */
    public function removeUserRole($user_id, $role) {
        $user = get_userdata($user_id);

        if (!$user) {
            return ['error' => 'User not found'];
        }

        $user->remove_role($role);

        return [
            'success' => true,
            'user_id' => $user_id,
            'removed_role' => $role,
            'remaining_roles' => $user->roles
        ];
    }

    /**
     * Demote all recently created admins
     */
    public function demoteRecentAdmins($days = 7, $new_role = 'subscriber') {
        $recent_admins = $this->db->get_results("
            SELECT u.ID
            FROM {$this->db->prefix}users u
            INNER JOIN {$this->db->prefix}usermeta um ON u.ID = um.user_id
            WHERE um.meta_key = '{$this->db->prefix}capabilities'
            AND um.meta_value LIKE '%administrator%'
            AND u.user_registered >= DATE_SUB(NOW(), INTERVAL {$days} DAY)
        ");

        $results = [];

        foreach ($recent_admins as $admin) {
            $result = $this->changeUserRole($admin->ID, $new_role);
            $results[] = $result;
        }

        return [
            'total_demoted' => count($results),
            'details' => $results
        ];
    }

    /**
     * Delete user account
     */
    public function deleteUser($user_id, $reassign_to = null) {
        $user = get_userdata($user_id);

        if (!$user) {
            return ['error' => 'User not found'];
        }

        // Don't allow deleting user ID 1 (usually primary admin)
        if ($user_id == 1) {
            return ['error' => 'Cannot delete primary admin account'];
        }

        require_once(ABSPATH . 'wp-admin/includes/user.php');

        $deleted = wp_delete_user($user_id, $reassign_to);

        if ($deleted) {
            return [
                'success' => true,
                'deleted_user_id' => $user_id,
                'deleted_user_login' => $user->user_login,
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        return ['error' => 'Failed to delete user'];
    }

    /**
     * Get available roles
     */
    public function getAvailableRoles() {
        global $wp_roles;

        if (!isset($wp_roles)) {
            $wp_roles = new \WP_Roles();
        }

        return $wp_roles->get_names();
    }

    /**
     * Create security report for users
     */
    public function generateUserSecurityReport() {
        $all_users = $this->getAllUsers();
        $admins = $this->getAdministrators();
        $issues = $this->auditUserRoles();

        return [
            'summary' => [
                'total_users' => count($all_users),
                'total_admins' => count($admins),
                'issues_found' => count($issues)
            ],
            'administrators' => $admins,
            'security_issues' => $issues,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Lock user account (set to subscriber with no capabilities)
     */
    public function lockUserAccount($user_id) {
        return $this->changeUserRole($user_id, 'subscriber');
    }

    /**
     * Bulk user management
     */
    public function bulkChangeRoles($user_ids, $new_role) {
        $results = [];

        foreach ($user_ids as $user_id) {
            $results[] = $this->changeUserRole($user_id, $new_role);
        }

        return [
            'total_processed' => count($results),
            'results' => $results
        ];
    }
}
