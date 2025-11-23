<?php
/**
 * Notification System
 *
 * Sends security alerts via email, Slack, or webhooks
 */

namespace WPScanner\Utils;

class Notifier {

    private $config;
    private $logger;

    public function __construct($config = []) {
        $this->config = $config;
        $this->logger = new Logger();
    }

    /**
     * Send notification based on scan results
     */
    public function sendScanNotification($scan_results) {
        $summary = $scan_results['summary'] ?? [];

        // Only send if there are issues
        if (($summary['total_issues'] ?? 0) === 0) {
            return ['sent' => false, 'reason' => 'No issues to report'];
        }

        $notifications_sent = [];

        // Email notification
        if ($this->config['alerts']['email'] ?? false) {
            $result = $this->sendEmail($scan_results);
            $notifications_sent['email'] = $result;
        }

        // Slack notification
        if ($this->config['alerts']['slack'] ?? false) {
            $result = $this->sendSlack($scan_results);
            $notifications_sent['slack'] = $result;
        }

        // Webhook notification
        if (isset($this->config['alerts']['webhook_url'])) {
            $result = $this->sendWebhook($scan_results);
            $notifications_sent['webhook'] = $result;
        }

        $this->logger->info("Notifications sent", $notifications_sent);

        return $notifications_sent;
    }

    /**
     * Send email notification
     */
    private function sendEmail($scan_results) {
        $to = $this->config['alerts']['email_to'] ?? 'admin@example.com';
        $summary = $scan_results['summary'] ?? [];

        $subject = sprintf(
            "[%s] WordPress Security Alert - %d issues detected",
            $summary['risk_level'] ?? 'UNKNOWN',
            $summary['total_issues'] ?? 0
        );

        $message = $this->buildEmailMessage($scan_results);

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'From: WordPress Scanner <noreply@' . $_SERVER['HTTP_HOST'] . '>',
        ];

        $sent = mail($to, $subject, $message, implode("\r\n", $headers));

        if ($sent) {
            $this->logger->info("Email notification sent", ['to' => $to]);
        } else {
            $this->logger->error("Email notification failed", ['to' => $to]);
        }

        return $sent;
    }

    /**
     * Build HTML email message
     */
    private function buildEmailMessage($scan_results) {
        $summary = $scan_results['summary'] ?? [];
        $risk_level = $summary['risk_level'] ?? 'UNKNOWN';
        $risk_color = $this->getRiskColor($risk_level);

        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .risk-badge { display: inline-block; padding: 5px 15px; border-radius: 3px; color: white; background: {$risk_color}; }
        .issue-list { list-style: none; padding: 0; }
        .issue-list li { padding: 10px; border-left: 4px solid #667eea; margin: 10px 0; background: #f8f9fa; }
        .critical { border-left-color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WordPress Security Scan Alert</h1>
            <p>Scan completed: {$scan_results['completed_at']}</p>
        </div>

        <div class="summary">
            <h2>Security Summary</h2>
            <p><strong>Risk Level:</strong> <span class="risk-badge">{$risk_level}</span></p>
            <p><strong>Risk Score:</strong> {$summary['risk_score']}/100</p>
            <p><strong>Total Issues:</strong> {$summary['total_issues']}</p>
            <p><strong>Critical Issues:</strong> {$summary['critical_issues']}</p>
        </div>

        <h3>Issues Detected</h3>
        <ul class="issue-list">
HTML;

        // Add issues by category
        foreach ($summary['categories'] ?? [] as $category => $count) {
            if ($count > 0) {
                $category_name = ucwords(str_replace('_', ' ', $category));
                $html .= "<li>{$category_name}: <strong>{$count}</strong> issues</li>\n";
            }
        }

        $html .= <<<HTML
        </ul>

        <div style="background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0;">⚠️ Recommended Actions</h3>
            <ol>
                <li>Review detailed scan report immediately</li>
                <li>Create backup before making changes</li>
                <li>Update vulnerable plugins and themes</li>
                <li>Remove unauthorized files</li>
                <li>Fix file permissions</li>
            </ol>
        </div>

        <div class="footer">
            <p>This is an automated security notification from WordPress Scanner</p>
            <p>Scan ID: {$scan_results['scan_id']}</p>
        </div>
    </div>
</body>
</html>
HTML;

        return $html;
    }

    /**
     * Send Slack notification
     */
    private function sendSlack($scan_results) {
        $webhook_url = $this->config['alerts']['slack_webhook'] ?? null;

        if (!$webhook_url) {
            return ['sent' => false, 'error' => 'No Slack webhook configured'];
        }

        $summary = $scan_results['summary'] ?? [];

        $payload = [
            'text' => sprintf(
                "🔒 WordPress Security Scan Alert - %s Risk Level",
                $summary['risk_level'] ?? 'UNKNOWN'
            ),
            'attachments' => [
                [
                    'color' => $this->getRiskColor($summary['risk_level'] ?? 'UNKNOWN'),
                    'fields' => [
                        [
                            'title' => 'Total Issues',
                            'value' => $summary['total_issues'] ?? 0,
                            'short' => true
                        ],
                        [
                            'title' => 'Risk Score',
                            'value' => ($summary['risk_score'] ?? 0) . '/100',
                            'short' => true
                        ],
                        [
                            'title' => 'Critical Issues',
                            'value' => $summary['critical_issues'] ?? 0,
                            'short' => true
                        ],
                        [
                            'title' => 'Scan ID',
                            'value' => $scan_results['scan_id'] ?? 'N/A',
                            'short' => true
                        ]
                    ],
                    'footer' => 'WordPress Scanner',
                    'ts' => time()
                ]
            ]
        ];

        $ch = curl_init($webhook_url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $success = ($http_code === 200);

        if ($success) {
            $this->logger->info("Slack notification sent");
        } else {
            $this->logger->error("Slack notification failed", ['http_code' => $http_code]);
        }

        return ['sent' => $success, 'http_code' => $http_code];
    }

    /**
     * Send webhook notification
     */
    private function sendWebhook($scan_results) {
        $webhook_url = $this->config['alerts']['webhook_url'];

        $payload = [
            'event' => 'security_scan_completed',
            'timestamp' => time(),
            'scan_results' => $scan_results
        ];

        $ch = curl_init($webhook_url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $success = ($http_code >= 200 && $http_code < 300);

        if ($success) {
            $this->logger->info("Webhook notification sent", ['url' => $webhook_url]);
        } else {
            $this->logger->error("Webhook notification failed", [
                'url' => $webhook_url,
                'http_code' => $http_code
            ]);
        }

        return ['sent' => $success, 'http_code' => $http_code];
    }

    /**
     * Get color for risk level
     */
    private function getRiskColor($level) {
        $colors = [
            'CRITICAL' => '#dc3545',
            'HIGH' => '#fd7e14',
            'MEDIUM' => '#ffc107',
            'LOW' => '#28a745',
        ];

        return $colors[$level] ?? '#6c757d';
    }

    /**
     * Send test notification
     */
    public function sendTest() {
        $test_results = [
            'scan_id' => 'test_' . time(),
            'completed_at' => date('Y-m-d H:i:s'),
            'summary' => [
                'risk_level' => 'LOW',
                'risk_score' => 15,
                'total_issues' => 3,
                'critical_issues' => 0,
                'categories' => [
                    'test_category' => 3
                ]
            ]
        ];

        return $this->sendScanNotification($test_results);
    }
}
