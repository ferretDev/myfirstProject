<?php
/**
 * Report Generator
 *
 * Generates comprehensive security reports for WordPress scanning results
 */

namespace WPScanner\Monitoring\Reports;

use WPScanner\Utils\Security;

class ReportGenerator {

    private $output_dir;

    public function __construct($output_dir = null) {
        $this->output_dir = $output_dir ?: WP_SCANNER_DIR . '/reports/';

        if (!is_dir($this->output_dir)) {
            mkdir($this->output_dir, 0755, true);
        }
    }

    /**
     * Generate comprehensive security report
     */
    public function generateSecurityReport($scan_results) {
        $report = [
            'scan_id' => uniqid('scan_'),
            'timestamp' => date('Y-m-d H:i:s'),
            'summary' => $this->generateSummary($scan_results),
            'details' => $scan_results,
            'recommendations' => $this->generateRecommendations($scan_results)
        ];

        // Save JSON report
        $filename = sprintf(
            'security_report_%s.json',
            date('Y-m-d_His')
        );

        $filepath = $this->output_dir . $filename;
        file_put_contents($filepath, json_encode($report, JSON_PRETTY_PRINT));

        // Generate HTML report
        $html_report = $this->generateHTMLReport($report);
        $html_filepath = str_replace('.json', '.html', $filepath);
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
     * Generate summary from scan results
     */
    private function generateSummary($scan_results) {
        $summary = [
            'total_issues' => 0,
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'categories' => []
        ];

        // Count issues by severity
        $this->countIssues($scan_results, $summary);

        // Overall risk score (0-100)
        $summary['risk_score'] = $this->calculateRiskScore($summary);
        $summary['risk_level'] = $this->getRiskLevel($summary['risk_score']);

        return $summary;
    }

    /**
     * Recursively count issues
     */
    private function countIssues($data, &$summary) {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                if (isset($value['severity'])) {
                    $summary['total_issues']++;
                    $severity = strtolower($value['severity']);
                    if (isset($summary[$severity])) {
                        $summary[$severity]++;
                    }
                } else {
                    $this->countIssues($value, $summary);
                }
            }
        }
    }

    /**
     * Calculate overall risk score
     */
    private function calculateRiskScore($summary) {
        $score = 0;
        $score += $summary['critical'] * 25;
        $score += $summary['high'] * 10;
        $score += $summary['medium'] * 5;
        $score += $summary['low'] * 1;

        return min(100, $score);
    }

    /**
     * Get risk level from score
     */
    private function getRiskLevel($score) {
        if ($score >= 75) return 'CRITICAL';
        if ($score >= 50) return 'HIGH';
        if ($score >= 25) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Generate recommendations based on findings
     */
    private function generateRecommendations($scan_results) {
        $recommendations = [];

        // Database recommendations
        if (isset($scan_results['database'])) {
            if (!empty($scan_results['database']['infected'])) {
                $recommendations[] = [
                    'priority' => 'CRITICAL',
                    'category' => 'Database',
                    'issue' => 'Infected database content detected',
                    'action' => 'Immediately review and clean infected posts/options. Consider restoring from clean backup.'
                ];
            }
        }

        // File system recommendations
        if (isset($scan_results['filesystem'])) {
            if (!empty($scan_results['filesystem']['php_files'])) {
                $recommendations[] = [
                    'priority' => 'CRITICAL',
                    'category' => 'File System',
                    'issue' => 'PHP files found in uploads directory',
                    'action' => 'Remove all PHP files from wp-content/uploads/. Configure web server to prevent PHP execution in uploads.'
                ];
            }
        }

        // Permission recommendations
        if (isset($scan_results['permissions'])) {
            if (!empty($scan_results['permissions']['world_writable'])) {
                $recommendations[] = [
                    'priority' => 'HIGH',
                    'category' => 'Permissions',
                    'issue' => 'World-writable files/directories found',
                    'action' => 'Fix file permissions immediately. Files should be 0644, directories 0755.'
                ];
            }
        }

        // User recommendations
        if (isset($scan_results['users'])) {
            if (!empty($scan_results['users']['recent_admin_accounts'])) {
                $recommendations[] = [
                    'priority' => 'HIGH',
                    'category' => 'Users',
                    'issue' => 'Recently created admin accounts detected',
                    'action' => 'Review all admin accounts. Remove any unauthorized accounts and reset passwords.'
                ];
            }
        }

        return $recommendations;
    }

    /**
     * Generate HTML report
     */
    private function generateHTMLReport($report) {
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
        $risk_class = $this->getRiskClass($summary['risk_level']);

        $html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WordPress Security Report - {$timestamp}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0 0 10px 0;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }
        .summary-card .value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .section {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin-top: 0;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .recommendation {
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .recommendation.critical {
            border-left-color: #dc3545;
        }
        .recommendation.high {
            border-left-color: #fd7e14;
        }
        .recommendation.medium {
            border-left-color: #ffc107;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>WordPress Security Scan Report</h1>
        <p>Scan ID: {$scan_id}</p>
        <p>Generated: {$timestamp}</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Risk Level</h3>
            <div class="value risk-{$risk_class}">{$risk_level}</div>
        </div>
        <div class="summary-card">
            <h3>Risk Score</h3>
            <div class="value">{$risk_score}/100</div>
        </div>
        <div class="summary-card">
            <h3>Total Issues</h3>
            <div class="value">{$total_issues}</div>
        </div>
        <div class="summary-card">
            <h3>Critical</h3>
            <div class="value risk-critical">{$critical}</div>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <div class="value risk-high">{$high}</div>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <div class="value risk-medium">{$medium}</div>
        </div>
    </div>

    <div class="section">
        <h2>Recommendations</h2>
HTML;

        foreach ($report['recommendations'] as $rec) {
            $priority_class = strtolower(Security::escapeAttr($rec['priority']));
            $priority = Security::escapeHtml($rec['priority']);
            $category = Security::escapeHtml($rec['category']);
            $issue = Security::escapeHtml($rec['issue']);
            $action = Security::escapeHtml($rec['action']);

            $html .= <<<HTML
        <div class="recommendation {$priority_class}">
            <div><span class="badge badge-{$priority_class}">{$priority}</span> <strong>{$category}</strong></div>
            <div style="margin-top: 10px;"><strong>Issue:</strong> {$issue}</div>
            <div style="margin-top: 5px;"><strong>Action:</strong> {$action}</div>
        </div>
HTML;
        }

        $html .= <<<HTML
    </div>

    <div class="section">
        <h2>Detailed Findings</h2>
        <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto;">{$this->formatDetails($report['details'])}</pre>
    </div>
</body>
</html>
HTML;

        return $html;
    }

    private function getRiskClass($level) {
        return strtolower($level);
    }

    private function formatDetails($details) {
        return htmlspecialchars(json_encode($details, JSON_PRETTY_PRINT));
    }

    /**
     * Generate executive summary report
     */
    public function generateExecutiveSummary($scan_results) {
        $summary = $this->generateSummary($scan_results);

        return [
            'scan_date' => date('Y-m-d H:i:s'),
            'risk_assessment' => [
                'level' => $summary['risk_level'],
                'score' => $summary['risk_score'],
                'description' => $this->getRiskDescription($summary['risk_level'])
            ],
            'findings' => [
                'critical_issues' => $summary['critical'],
                'high_priority' => $summary['high'],
                'total_issues' => $summary['total_issues']
            ],
            'next_steps' => $this->getNextSteps($summary['risk_level'])
        ];
    }

    private function getRiskDescription($level) {
        $descriptions = [
            'CRITICAL' => 'Immediate action required. Site is likely compromised.',
            'HIGH' => 'Urgent attention needed. Significant security vulnerabilities detected.',
            'MEDIUM' => 'Security improvements recommended. Some risks identified.',
            'LOW' => 'Site appears secure. Minor improvements suggested.'
        ];

        return $descriptions[$level] ?? 'Unknown risk level';
    }

    private function getNextSteps($level) {
        $steps = [
            'CRITICAL' => [
                'Take site offline immediately',
                'Contact security professional',
                'Restore from clean backup',
                'Change all passwords'
            ],
            'HIGH' => [
                'Review all findings immediately',
                'Fix critical vulnerabilities',
                'Update WordPress core and plugins',
                'Run additional scans'
            ],
            'MEDIUM' => [
                'Review findings',
                'Implement recommended fixes',
                'Schedule regular scans',
                'Update security policies'
            ],
            'LOW' => [
                'Review minor findings',
                'Maintain current security practices',
                'Schedule periodic scans',
                'Stay updated on security news'
            ]
        ];

        return $steps[$level] ?? [];
    }
}
