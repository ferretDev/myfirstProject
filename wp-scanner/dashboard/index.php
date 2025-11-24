<?php
/**
 * WordPress Security Scanner - Web Dashboard
 *
 * Enterprise-grade web interface for scanner management and reporting
 * Features: Interactive scans, one-click remediation, visual reports, history
 */

// Security check - must be run from within WordPress or with proper authentication
if (!defined('WP_SCANNER_AUTH') && !defined('ABSPATH')) {
    // Simple authentication for standalone mode
    session_start();

    if (!isset($_SESSION['scanner_authenticated'])) {
        if (isset($_POST['password'])) {
            $config = require __DIR__ . '/../config/config.php';
            $dashboard_password = $config['dashboard']['password'] ?? 'changeme';

            if (password_verify($_POST['password'], password_hash($dashboard_password, PASSWORD_DEFAULT)) ||
                $_POST['password'] === $dashboard_password) {
                $_SESSION['scanner_authenticated'] = true;
                header('Location: index.php');
                exit;
            }
        }

        // Show login form
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>WP Security Scanner - Login</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); max-width: 400px; width: 90%; }
                h1 { margin: 0 0 20px; color: #333; }
                input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; font-size: 16px; }
                button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; font-weight: 600; }
                button:hover { background: #5568d3; }
                .error { color: #dc3545; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h1>🔐 Security Scanner</h1>
                <p>Please authenticate to access the dashboard</p>
                <?php if (isset($_POST['password'])): ?>
                    <div class="error">Invalid password</div>
                <?php endif; ?>
                <form method="POST">
                    <input type="password" name="password" placeholder="Dashboard Password" required autofocus>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

define('WP_SCANNER_DIR', dirname(__DIR__));

// Load scanner
require_once WP_SCANNER_DIR . '/scanner.php';

// Get action
$action = $_GET['action'] ?? 'dashboard';
$format = $_GET['format'] ?? 'html';

// Handle AJAX requests
if ($format === 'json') {
    header('Content-Type: application/json');

    switch ($action) {
        case 'scan':
            // Start async scan
            $scan_type = $_POST['scan_type'] ?? 'comprehensive';

            // Execute in background
            $command = "php " . WP_SCANNER_DIR . "/scanner.php scan > /dev/null 2>&1 &";
            exec($command, $output, $return_var);

            echo json_encode([
                'success' => true,
                'message' => 'Scan started in background',
                'scan_id' => 'scan_' . time()
            ]);
            break;

        case 'remediate':
            // Auto-fix issues
            $issue_ids = $_POST['issues'] ?? [];

            $command = "php " . WP_SCANNER_DIR . "/scanner.php auto-fix --confirm > /dev/null 2>&1 &";
            exec($command, $output, $return_var);

            echo json_encode([
                'success' => true,
                'message' => 'Remediation started',
                'count' => count($issue_ids)
            ]);
            break;

        case 'reports':
            // List recent reports
            $reports_dir = WP_SCANNER_DIR . '/reports/';
            $reports = [];

            foreach (glob($reports_dir . 'security_report_*.json') as $file) {
                $data = json_decode(file_get_contents($file), true);
                $reports[] = [
                    'id' => $data['scan_id'],
                    'timestamp' => $data['timestamp'],
                    'risk_level' => $data['summary']['risk_level'],
                    'risk_score' => $data['summary']['risk_score'],
                    'total_issues' => $data['summary']['total_issues'],
                    'file' => basename($file)
                ];
            }

            // Sort by timestamp descending
            usort($reports, function($a, $b) {
                return strtotime($b['timestamp']) - strtotime($a['timestamp']);
            });

            echo json_encode([
                'success' => true,
                'reports' => array_slice($reports, 0, 10) // Last 10 reports
            ]);
            break;

        case 'stats':
            // Get dashboard statistics
            $stats = [
                'last_scan' => null,
                'total_scans' => 0,
                'current_risk' => 'UNKNOWN',
                'issues_fixed_30d' => 0,
                'scans_30d' => 0
            ];

            $reports = glob(WP_SCANNER_DIR . '/reports/security_report_*.json');
            $stats['total_scans'] = count($reports);

            if (!empty($reports)) {
                // Get latest report
                usort($reports, function($a, $b) {
                    return filemtime($b) - filemtime($a);
                });

                $latest = json_decode(file_get_contents($reports[0]), true);
                $stats['last_scan'] = $latest['timestamp'];
                $stats['current_risk'] = $latest['summary']['risk_level'];
                $stats['current_score'] = $latest['summary']['risk_score'];
                $stats['total_issues'] = $latest['summary']['total_issues'];
            }

            echo json_encode([
                'success' => true,
                'stats' => $stats
            ]);
            break;

        default:
            echo json_encode(['success' => false, 'error' => 'Unknown action']);
    }

    exit;
}

// HTML Dashboard
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WordPress Security Scanner - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            color: #333;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }

        .header .subtitle {
            opacity: 0.9;
            margin-top: 5px;
            font-size: 14px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.12);
        }

        .stat-card h3 {
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }

        .stat-card .value {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .stat-card .label {
            font-size: 12px;
            color: #999;
        }

        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .risk-unknown { color: #6c757d; }

        .actions {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 30px;
        }

        .actions h2 {
            margin-bottom: 20px;
            font-size: 20px;
        }

        .button-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .btn {
            padding: 15px 25px;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-align: center;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5568d3;
        }

        .btn-success {
            background: #28a745;
            color: white;
        }

        .btn-success:hover {
            background: #218838;
        }

        .btn-warning {
            background: #ffc107;
            color: #333;
        }

        .btn-warning:hover {
            background: #e0a800;
        }

        .btn-danger {
            background: #dc3545;
            color: white;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .reports-section {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .reports-section h2 {
            margin-bottom: 20px;
            font-size: 20px;
        }

        .report-list {
            list-style: none;
        }

        .report-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }

        .report-item:hover {
            background: #f8f9fa;
        }

        .report-item:last-child {
            border-bottom: none;
        }

        .report-info {
            flex: 1;
        }

        .report-info .timestamp {
            font-size: 14px;
            color: #666;
            margin-bottom: 5px;
        }

        .report-info .stats {
            font-size: 12px;
            color: #999;
        }

        .report-actions {
            display: flex;
            gap: 10px;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-critical {
            background: #dc3545;
            color: white;
        }

        .badge-high {
            background: #fd7e14;
            color: white;
        }

        .badge-medium {
            background: #ffc107;
            color: #333;
        }

        .badge-low {
            background: #28a745;
            color: white;
        }

        .badge-unknown {
            background: #6c757d;
            color: white;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 40px;
            color: #666;
        }

        .loading.active {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }

        .alert.active {
            display: block;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }

        .progress-bar {
            width: 100%;
            height: 6px;
            background: #eee;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 10px;
            display: none;
        }

        .progress-bar.active {
            display: block;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s;
            animation: progress-animation 2s ease-in-out infinite;
        }

        @keyframes progress-animation {
            0%, 100% { width: 30%; }
            50% { width: 70%; }
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .button-grid {
                grid-template-columns: 1fr;
            }

            .report-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WordPress Security Scanner</h1>
        <div class="subtitle">Enterprise Security Dashboard v2.0.1</div>
    </div>

    <div class="container">
        <div id="alert" class="alert"></div>

        <!-- Statistics Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Current Risk Level</h3>
                <div class="value risk-unknown" id="risk-level">Loading...</div>
                <div class="label">Overall security status</div>
            </div>

            <div class="stat-card">
                <h3>Risk Score</h3>
                <div class="value" id="risk-score">--</div>
                <div class="label">Out of 100</div>
            </div>

            <div class="stat-card">
                <h3>Total Issues</h3>
                <div class="value" id="total-issues">--</div>
                <div class="label">Requiring attention</div>
            </div>

            <div class="stat-card">
                <h3>Last Scan</h3>
                <div class="value" style="font-size: 16px; margin-top: 10px;" id="last-scan">Never</div>
                <div class="label">Most recent security check</div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="actions">
            <h2>⚡ Quick Actions</h2>
            <div class="progress-bar" id="progress-bar">
                <div class="progress-fill"></div>
            </div>
            <div class="button-grid">
                <button class="btn btn-primary" onclick="runScan('comprehensive')">
                    🔍 Run Full Scan
                </button>
                <button class="btn btn-success" onclick="runScan('quick')">
                    ⚡ Quick Scan
                </button>
                <button class="btn btn-warning" onclick="runRemediation()">
                    🔧 Auto-Fix Issues
                </button>
                <button class="btn btn-secondary" onclick="createBackup()">
                    💾 Create Backup
                </button>
                <button class="btn btn-primary" onclick="checkVulnerabilities()">
                    🔐 Check Vulnerabilities
                </button>
                <button class="btn btn-secondary" onclick="window.location.href='patterns.php'">
                    📋 Manage Patterns
                </button>
            </div>
        </div>

        <!-- Recent Reports -->
        <div class="reports-section">
            <h2>📊 Recent Scans</h2>
            <div class="loading" id="reports-loading">
                <div class="spinner"></div>
                <p>Loading reports...</p>
            </div>
            <ul class="report-list" id="report-list">
                <!-- Populated by JavaScript -->
            </ul>
        </div>
    </div>

    <script>
        // Load dashboard stats
        async function loadStats() {
            try {
                const response = await fetch('?action=stats&format=json');
                const data = await response.json();

                if (data.success) {
                    const stats = data.stats;

                    // Update risk level
                    const riskLevel = document.getElementById('risk-level');
                    riskLevel.textContent = stats.current_risk || 'UNKNOWN';
                    riskLevel.className = 'value risk-' + (stats.current_risk || 'unknown').toLowerCase();

                    // Update risk score
                    document.getElementById('risk-score').textContent = stats.current_score || '--';

                    // Update total issues
                    document.getElementById('total-issues').textContent = stats.total_issues || '0';

                    // Update last scan
                    if (stats.last_scan) {
                        const date = new Date(stats.last_scan);
                        const timeAgo = getTimeAgo(date);
                        document.getElementById('last-scan').textContent = timeAgo;
                    }
                }
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }

        // Load recent reports
        async function loadReports() {
            const loading = document.getElementById('reports-loading');
            const list = document.getElementById('report-list');

            loading.classList.add('active');

            try {
                const response = await fetch('?action=reports&format=json');
                const data = await response.json();

                if (data.success && data.reports.length > 0) {
                    list.innerHTML = data.reports.map(report => `
                        <li class="report-item">
                            <div class="report-info">
                                <div class="timestamp">${new Date(report.timestamp).toLocaleString()}</div>
                                <div class="stats">
                                    <span class="badge badge-${report.risk_level.toLowerCase()}">${report.risk_level}</span>
                                    Score: ${report.risk_score}/100 | Issues: ${report.total_issues}
                                </div>
                            </div>
                            <div class="report-actions">
                                <a href="../reports/${report.file.replace('.json', '.html')}" target="_blank" class="btn btn-primary" style="padding: 8px 16px; font-size: 13px;">
                                    View Report
                                </a>
                            </div>
                        </li>
                    `).join('');
                } else {
                    list.innerHTML = '<li class="report-item"><div class="report-info">No scans found. Run your first scan to get started!</div></li>';
                }
            } catch (error) {
                console.error('Error loading reports:', error);
                list.innerHTML = '<li class="report-item"><div class="report-info">Error loading reports</div></li>';
            } finally {
                loading.classList.remove('active');
            }
        }

        // Run scan
        async function runScan(type) {
            const alert = document.getElementById('alert');
            const progressBar = document.getElementById('progress-bar');

            alert.textContent = `Starting ${type} scan...`;
            alert.className = 'alert alert-info active';
            progressBar.classList.add('active');

            try {
                const formData = new FormData();
                formData.append('scan_type', type);

                const response = await fetch('?action=scan&format=json', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    alert.textContent = 'Scan started successfully! This may take a few minutes...';
                    alert.className = 'alert alert-success active';

                    // Refresh stats after 5 seconds
                    setTimeout(() => {
                        loadStats();
                        loadReports();
                        progressBar.classList.remove('active');
                    }, 60000); // 60 seconds
                } else {
                    alert.textContent = 'Error starting scan: ' + (data.error || 'Unknown error');
                    alert.className = 'alert alert-danger active';
                    progressBar.classList.remove('active');
                }
            } catch (error) {
                alert.textContent = 'Error: ' + error.message;
                alert.className = 'alert alert-danger active';
                progressBar.classList.remove('active');
            }
        }

        // Run remediation
        async function runRemediation() {
            if (!confirm('This will automatically fix common security issues. A backup will be created first. Continue?')) {
                return;
            }

            const alert = document.getElementById('alert');
            alert.textContent = 'Starting auto-remediation...';
            alert.className = 'alert alert-info active';

            try {
                const response = await fetch('?action=remediate&format=json', {
                    method: 'POST'
                });

                const data = await response.json();

                if (data.success) {
                    alert.textContent = 'Remediation started successfully!';
                    alert.className = 'alert alert-success active';

                    setTimeout(() => {
                        loadStats();
                        loadReports();
                    }, 30000);
                } else {
                    alert.textContent = 'Error: ' + (data.error || 'Unknown error');
                    alert.className = 'alert alert-danger active';
                }
            } catch (error) {
                alert.textContent = 'Error: ' + error.message;
                alert.className = 'alert alert-danger active';
            }
        }

        // Create backup
        function createBackup() {
            const alert = document.getElementById('alert');
            alert.textContent = 'Creating backup... (redirecting to CLI)';
            alert.className = 'alert alert-info active';

            // In a real implementation, this would trigger a background backup
            alert.textContent = 'Please run: php scanner.php backup';
            alert.className = 'alert alert-info active';
        }

        // Check vulnerabilities
        async function checkVulnerabilities() {
            const alert = document.getElementById('alert');
            alert.textContent = 'Checking for known vulnerabilities...';
            alert.className = 'alert alert-info active';

            // This would trigger vulnerability check
            runScan('vulnerabilities');
        }

        // Helper function for time ago
        function getTimeAgo(date) {
            const seconds = Math.floor((new Date() - date) / 1000);

            const intervals = {
                year: 31536000,
                month: 2592000,
                week: 604800,
                day: 86400,
                hour: 3600,
                minute: 60
            };

            for (const [name, secondsInInterval] of Object.entries(intervals)) {
                const interval = Math.floor(seconds / secondsInInterval);
                if (interval >= 1) {
                    return interval === 1 ? `1 ${name} ago` : `${interval} ${name}s ago`;
                }
            }

            return 'Just now';
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', () => {
            loadStats();
            loadReports();

            // Auto-refresh every 60 seconds
            setInterval(() => {
                loadStats();
                loadReports();
            }, 60000);
        });
    </script>
</body>
</html>
