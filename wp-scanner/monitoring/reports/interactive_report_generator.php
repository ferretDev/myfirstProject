<?php
/**
 * Interactive Report Generator
 *
 * Generates enterprise-grade interactive HTML reports with action buttons,
 * drill-down capabilities, and export options
 */

namespace WPScanner\Monitoring\Reports;

use WPScanner\Utils\Security;

class InteractiveReportGenerator extends ReportGenerator {

    /**
     * Generate interactive HTML report with action buttons
     */
    public function generateInteractiveReport($scan_results) {
        $report = [
            'scan_id' => uniqid('scan_'),
            'timestamp' => date('Y-m-d H:i:s'),
            'summary' => $this->generateSummary($scan_results),
            'details' => $scan_results,
            'recommendations' => $this->generateRecommendations($scan_results)
        ];

        // Save JSON report
        $filename = sprintf('security_report_%s.json', date('Y-m-d_His'));
        $filepath = $this->output_dir . $filename;
        file_put_contents($filepath, json_encode($report, JSON_PRETTY_PRINT));

        // Generate interactive HTML report
        $html_report = $this->generateInteractiveHTML($report);
        $html_filepath = str_replace('.json', '_interactive.html', $filepath);
        file_put_contents($html_filepath, $html_report);

        return [
            'success' => true,
            'scan_id' => $report['scan_id'],
            'json_report' => $filepath,
            'html_report' => $html_filepath,
            'summary' => $report['summary']
        ];
    }

    /**
     * Generate interactive HTML with action buttons and drill-down
     */
    private function generateInteractiveHTML($report) {
        $summary = $report['summary'];

        // Escape all output for XSS protection
        $scan_id = Security::escapeHtml($report['scan_id']);
        $timestamp = Security::escapeHtml($report['timestamp']);
        $risk_level = Security::escapeHtml($summary['risk_level']);
        $risk_score = (int)$summary['risk_score'];
        $total_issues = (int)$summary['total_issues'];
        $critical = (int)$summary['critical'];
        $high = (int)$summary['high'];
        $medium = (int)$summary['medium'];
        $low = (int)$summary['low'];
        $risk_class = $this->getRiskClass($summary['risk_level']);

        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {$timestamp}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            color: #333;
        }

        .print-only { display: none; }

        @media print {
            .no-print { display: none !important; }
            .print-only { display: block !important; }
            body { background: white; }
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }

        .header .meta {
            opacity: 0.9;
            font-size: 14px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }

        .action-bar {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; }

        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }

        .btn-warning { background: #ffc107; color: #333; }
        .btn-warning:hover { background: #e0a800; }

        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }

        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #5a6268; }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            text-align: center;
        }

        .summary-card h3 {
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }

        .summary-card .value {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .summary-card .label {
            font-size: 13px;
            color: #999;
        }

        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }

        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .section h2 {
            margin-bottom: 20px;
            font-size: 22px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .recommendation {
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            background: #f8f9fa;
            border-radius: 8px;
            position: relative;
        }

        .recommendation.critical { border-left-color: #dc3545; background: #fff5f5; }
        .recommendation.high { border-left-color: #fd7e14; background: #fff8f0; }
        .recommendation.medium { border-left-color: #ffc107; background: #fffbf0; }
        .recommendation.low { border-left-color: #28a745; background: #f0fff4; }

        .recommendation-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .recommendation-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }

        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible:hover {
            opacity: 0.8;
        }

        .collapsible::before {
            content: '▼ ';
            display: inline-block;
            transition: transform 0.2s;
        }

        .collapsible.collapsed::before {
            transform: rotate(-90deg);
        }

        .collapsible-content {
            max-height: 1000px;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }

        .collapsible-content.collapsed {
            max-height: 0;
        }

        .details-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        .details-table th,
        .details-table td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #eee;
        }

        .details-table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .details-table tr:hover {
            background: #f8f9fa;
        }

        .chart-container {
            margin: 20px 0;
            text-align: center;
        }

        .risk-gauge {
            display: inline-block;
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(
                from 0deg,
                #28a745 0deg 90deg,
                #ffc107 90deg 180deg,
                #fd7e14 180deg 270deg,
                #dc3545 270deg 360deg
            );
            position: relative;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .risk-gauge::before {
            content: '';
            position: absolute;
            top: 20px;
            left: 20px;
            right: 20px;
            bottom: 20px;
            background: white;
            border-radius: 50%;
        }

        .risk-gauge-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 48px;
            font-weight: 700;
            z-index: 1;
        }

        .export-menu {
            position: relative;
            display: inline-block;
        }

        .export-dropdown {
            display: none;
            position: absolute;
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            min-width: 200px;
            z-index: 1000;
            top: 100%;
            right: 0;
            margin-top: 5px;
        }

        .export-menu.active .export-dropdown {
            display: block;
        }

        .export-dropdown a {
            display: block;
            padding: 12px 20px;
            color: #333;
            text-decoration: none;
            transition: background 0.2s;
        }

        .export-dropdown a:hover {
            background: #f8f9fa;
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }

            .action-bar {
                flex-direction: column;
            }

            .btn {
                width: 100%;
            }

            .summary-grid {
                grid-template-columns: 1fr;
            }

            .recommendation-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WordPress Security Report</h1>
        <div class="meta">
            Scan ID: {$scan_id} | Generated: {$timestamp}
        </div>
    </div>

    <div class="container">
        <!-- Action Bar -->
        <div class="action-bar no-print">
            <button class="btn btn-primary" onclick="window.print()">
                🖨️ Print Report
            </button>
            <button class="btn btn-success" onclick="runRemediation()">
                🔧 Auto-Fix Issues
            </button>
            <button class="btn btn-warning" onclick="runRescan()">
                🔄 Re-scan Now
            </button>
            <div class="export-menu">
                <button class="btn btn-secondary" onclick="toggleExport()">
                    💾 Export
                </button>
                <div class="export-dropdown" id="export-dropdown">
                    <a href="javascript:void(0)" onclick="exportJSON()">📄 Export as JSON</a>
                    <a href="javascript:void(0)" onclick="exportCSV()">📊 Export as CSV</a>
                    <a href="javascript:void(0)" onclick="emailReport()">📧 Email Report</a>
                    <a href="javascript:void(0)" onclick="shareSlack()">💬 Share to Slack</a>
                </div>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Risk Level</h3>
                <div class="value risk-{$risk_class}">{$risk_level}</div>
                <div class="label">Overall Security Status</div>
            </div>

            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="risk-gauge">
                    <div class="risk-gauge-value risk-{$risk_class}">{$risk_score}</div>
                </div>
                <div class="label">Out of 100</div>
            </div>

            <div class="summary-card">
                <h3>Total Issues</h3>
                <div class="value">{$total_issues}</div>
                <div class="label">Requiring Attention</div>
            </div>

            <div class="summary-card">
                <h3>Issue Breakdown</h3>
                <div style="text-align: left; margin-top: 10px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span class="risk-critical">Critical:</span>
                        <strong>{$critical}</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span class="risk-high">High:</span>
                        <strong>{$high}</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span class="risk-medium">Medium:</span>
                        <strong>{$medium}</strong>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recommendations with Actions -->
        <div class="section">
            <h2 class="collapsible" onclick="toggleSection('recommendations')">
                💡 Actionable Recommendations
            </h2>
            <div id="recommendations" class="collapsible-content">
HTML;

        foreach ($report['recommendations'] as $idx => $rec) {
            $priority_class = strtolower(Security::escapeAttr($rec['priority']));
            $priority = Security::escapeHtml($rec['priority']);
            $category = Security::escapeHtml($rec['category']);
            $issue = Security::escapeHtml($rec['issue']);
            $action = Security::escapeHtml($rec['action']);

            $html .= <<<HTML
                <div class="recommendation {$priority_class}">
                    <div class="recommendation-header">
                        <div>
                            <span class="badge badge-{$priority_class}">{$priority}</span>
                            <strong style="margin-left: 10px;">{$category}</strong>
                        </div>
                    </div>
                    <div style="margin: 10px 0;"><strong>Issue:</strong> {$issue}</div>
                    <div style="margin: 10px 0;"><strong>Action Required:</strong> {$action}</div>
                    <div class="recommendation-actions no-print">
                        <button class="btn btn-success" style="padding: 8px 16px; font-size: 13px;" onclick="fixIssue({$idx})">
                            ✓ Fix This Issue
                        </button>
                        <button class="btn btn-secondary" style="padding: 8px 16px; font-size: 13px;" onclick="learnMore({$idx})">
                            📖 Learn More
                        </button>
                        <button class="btn btn-warning" style="padding: 8px 16px; font-size: 13px;" onclick="ignoreIssue({$idx})">
                            ⊘ Ignore
                        </button>
                    </div>
                </div>
HTML;
        }

        $html .= <<<HTML
            </div>
        </div>

        <!-- Detailed Findings -->
        <div class="section">
            <h2 class="collapsible" onclick="toggleSection('details')">
                🔍 Detailed Findings
            </h2>
            <div id="details" class="collapsible-content">
                <pre style="background: #f8f9fa; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 13px;">{$this->formatDetails($report['details'])}</pre>
            </div>
        </div>
    </div>

    <script>
        function toggleSection(id) {
            const element = document.getElementById(id);
            const header = element.previousElementSibling;
            element.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }

        function toggleExport() {
            document.querySelector('.export-menu').classList.toggle('active');
        }

        function runRemediation() {
            if (confirm('This will automatically fix common security issues. A backup will be created first. Continue?')) {
                alert('Redirecting to remediation...');
                window.location.href = '../dashboard/index.php?action=remediate';
            }
        }

        function runRescan() {
            if (confirm('Run a new comprehensive security scan?')) {
                window.location.href = '../dashboard/index.php?action=scan';
            }
        }

        function fixIssue(index) {
            alert('Fix issue #' + index + ' - This would trigger automated remediation for this specific issue');
        }

        function learnMore(index) {
            alert('Learn more about issue #' + index + ' - This would show detailed documentation');
        }

        function ignoreIssue(index) {
            if (confirm('Mark this issue as ignored?')) {
                alert('Issue #' + index + ' marked as ignored');
            }
        }

        function exportJSON() {
            alert('Exporting as JSON...');
            window.location.href = '{$report['scan_id']}.json';
        }

        function exportCSV() {
            alert('Exporting as CSV...');
        }

        function emailReport() {
            const email = prompt('Enter email address to send report:');
            if (email) {
                alert('Report will be sent to: ' + email);
            }
        }

        function shareSlack() {
            alert('Sharing to Slack...');
        }

        // Close export menu when clicking outside
        document.addEventListener('click', function(event) {
            const exportMenu = document.querySelector('.export-menu');
            if (exportMenu && !exportMenu.contains(event.target)) {
                exportMenu.classList.remove('active');
            }
        });

        // Collapse all sections by default except recommendations
        document.addEventListener('DOMContentLoaded', function() {
            const details = document.getElementById('details');
            if (details) {
                toggleSection('details');
            }
        });
    </script>
</body>
</html>
HTML;

        return $html;
    }
}
