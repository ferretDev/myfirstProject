# WordPress Security Scanner

A comprehensive security scanning and monitoring tool for WordPress installations. Detect malware, unauthorized changes, spam content, security misconfigurations, and malicious actors.

## 🔒 Features

### Database Scanning
- **Malicious Content Detection**: Scans posts, pages, and options for malware patterns
- **Pattern-Based Scanning**: Detects obfuscated code, backdoors, SQL injections
- **Spam Content Flags**: Identifies pharmaceutical, gambling, adult content spam
- **Post Count Analysis**: Detects unusual spikes in post creation
- **User Role Monitoring**: Tracks admin account creation and modifications
- **OAuth/JSON Credential Exposure**: Detects exposed API keys and tokens
- **Table Integrity**: Identifies unauthorized database tables

### File System Scanning
- **Malware Detection**: Scans PHP files for malicious code patterns
- **Heuristic Scanning**: Advanced pattern matching for obfuscation techniques
- **Uploads Directory Monitoring**: Detects PHP files and suspicious uploads
- **File Integrity Checking**: Monitors file changes and modifications
- **Double Extension Detection**: Finds files like `image.jpg.php`
- **File Quarantine System**: Automatically isolate suspicious files

### Permission & Ownership Control
- **Permission Auditing**: Checks file and directory permissions
- **World-Writable Detection**: Identifies insecure file permissions
- **Ownership Analysis**: Validates file ownership configurations
- **Auto-Fix Capabilities**: Automatically correct permission issues

### .htaccess Security
- **Malicious Redirect Detection**: Identifies unauthorized redirects
- **Rewrite Rule Analysis**: Detects suspicious URL rewrites
- **PHP Injection Detection**: Finds auto_prepend/auto_append attacks
- **Base64 Content Detection**: Identifies obfuscated .htaccess content
- **Baseline Comparison**: Track changes to .htaccess files

### File Watching
- **Real-time Monitoring**: Track file system changes
- **Change Detection**: Identify added, modified, and deleted files
- **Severity Assessment**: Prioritize critical file changes
- **Snapshot Comparison**: Compare against known-good baselines

### Anomaly Detection
- **Spam Content Detection**: Hidden links, hidden text, iframe injections
- **Post Count Spikes**: Statistical analysis of content creation patterns
- **User Activity Monitoring**: Detect suspicious user behavior
- **robots.txt Changes**: Monitor changes to robots.txt file
- **Credential Exposure**: Scan for exposed OAuth tokens and API keys

### User Management
- **Role Auditing**: Review and audit user roles
- **User Role Editor**: Modify user permissions
- **Suspicious Username Detection**: Identify potentially malicious accounts
- **Bulk Operations**: Mass user role modifications
- **Account Locking**: Quickly disable compromised accounts

### Reporting & Oversight
- **Comprehensive Reports**: HTML and JSON report generation
- **Risk Scoring**: Calculate overall security risk level
- **Executive Summaries**: High-level security overview
- **Actionable Recommendations**: Specific remediation steps
- **Historical Tracking**: Compare scans over time

## 📁 Project Structure

```
wp-scanner/
├── core/                       # Core scanner orchestration
│   └── scanner.php            # Main scanner class
├── database/                   # Database scanning modules
│   ├── scanners/
│   │   └── db_scanner.php     # Database malware scanner
│   ├── patterns/
│   │   └── malicious_patterns.php  # Pattern definitions
│   └── analyzers/
│       └── change_detector.php     # Change detection
├── filesystem/                 # File system modules
│   ├── scanners/
│   │   ├── file_scanner.php   # File malware scanner
│   │   └── htaccess_scanner.php    # .htaccess scanner
│   ├── watchers/
│   │   └── file_watcher.php   # File change monitoring
│   └── permissions/
│       └── permission_checker.php  # Permission auditor
├── monitoring/                 # Monitoring & detection
│   ├── detectors/
│   │   └── anomaly_detector.php    # Anomaly detection
│   └── reports/
│       └── report_generator.php    # Report generation
├── utils/                      # Utilities
│   ├── logger.php             # Logging system
│   └── user_role_editor.php  # User management
├── config/                     # Configuration
│   └── config.php             # Main configuration
├── ui/                         # Web interface (future)
│   ├── dashboard/
│   ├── components/
│   └── api/
├── quarantine/                 # Quarantined files
├── logs/                       # Log files
├── reports/                    # Generated reports
├── data/                       # Baseline data
├── scanner.php                # CLI entry point
└── README.md                  # Documentation
```

## 🚀 Installation

### Requirements
- PHP 7.4 or higher
- WordPress 5.0+
- MySQL/MariaDB
- Read/write permissions on WordPress directory

### Setup

1. **Clone or download** the scanner to your WordPress installation:
```bash
cd /path/to/wordpress
git clone <repository> wp-scanner
```

2. **Set permissions**:
```bash
chmod +x wp-scanner/scanner.php
```

3. **Initialize baselines**:
```bash
php wp-scanner/scanner.php init
```

## 📖 Usage

### Command Line Interface

#### Full Security Scan
```bash
php scanner.php scan
```
Runs comprehensive scan including:
- Database malware scanning
- File system integrity checking
- Permission auditing
- .htaccess analysis
- Anomaly detection
- Generates HTML and JSON reports

#### Quick Scan
```bash
php scanner.php quick
```
Essential security checks only (faster):
- Critical database checks
- User role audit
- Uploads directory scan
- Permission audit

#### Initialize Baselines
```bash
php scanner.php init
```
Creates baseline snapshots of:
- Database state
- File system
- .htaccess configuration

#### File Change Detection
```bash
php scanner.php watch
```
Detects file system changes since last baseline.

#### User Account Audit
```bash
php scanner.php users
```
Audits user accounts for:
- Recently created admins
- Suspicious usernames
- Role misconfigurations

#### Permission Audit
```bash
php scanner.php permissions
```
Checks file and directory permissions.

#### .htaccess Scan
```bash
php scanner.php htaccess
```
Scans .htaccess files for malicious modifications.

#### Anomaly Detection
```bash
php scanner.php anomalies
```
Runs advanced anomaly detection algorithms.

### Configuration

Edit `config/config.php` to customize:

```php
return [
    'wp_root' => '/var/www/html',  // WordPress path

    'scans' => [
        'database' => true,
        'filesystem' => true,
        'permissions' => true,
        'htaccess' => true,
        'anomalies' => true,
        'file_watching' => true,
    ],

    'thresholds' => [
        'post_spike_multiplier' => 10,
        'recent_admin_days' => 7,
    ],

    'whitelist' => [
        'files' => [
            // Whitelist specific files
        ],
        'patterns' => [
            '*/vendor/*',
            '*/node_modules/*',
        ],
    ],

    // More configuration options...
];
```

## 🔍 Detection Capabilities

### Malware Patterns

**Obfuscation Techniques:**
- `eval(base64_decode())`
- `gzinflate(base64_decode())`
- `str_rot13()`
- Hex and Unicode obfuscation

**Dangerous Functions:**
- `eval`, `exec`, `system`, `shell_exec`
- `assert`, `create_function`
- `proc_open`, `popen`, `passthru`

**Known Backdoors:**
- C99 Shell
- R57 Shell
- WSO Shell
- FilesMan
- Password/Command backdoors

### Spam Detection

**Content Types:**
- Pharmaceutical spam (viagra, cialis, etc.)
- Gambling content
- Adult content
- SEO spam
- Hidden links and text

**Techniques:**
- Hidden iframes
- Invisible divs
- Tiny text (font-size: 0)
- JavaScript redirects

### Security Misconfigurations

**File Permissions:**
- World-writable files (777)
- Insecure wp-config.php
- Incorrect ownership

**.htaccess Issues:**
- Unauthorized redirects
- External rewrites
- PHP injections
- Auto-prepend/append attacks

## 📊 Reports

### HTML Reports
Beautiful, interactive HTML reports with:
- Risk scoring and severity levels
- Issue categorization
- Actionable recommendations
- Detailed findings
- Color-coded severity indicators

### JSON Reports
Machine-readable JSON format for:
- Integration with other tools
- Automated processing
- Historical analysis
- Custom reporting

### Report Locations
- HTML: `wp-scanner/reports/security_report_YYYY-MM-DD_HHMMSS.html`
- JSON: `wp-scanner/reports/security_report_YYYY-MM-DD_HHMMSS.json`

## 🛡️ Security Best Practices

1. **Run Regular Scans**: Schedule weekly full scans
2. **Initialize Baselines**: Create baselines after clean installation
3. **Review Reports**: Immediately investigate HIGH and CRITICAL findings
4. **Quarantine Suspicious Files**: Use auto-quarantine for uploads
5. **Monitor User Accounts**: Audit admin accounts regularly
6. **Update WordPress**: Keep core, themes, and plugins updated
7. **Fix Permissions**: Correct permission issues immediately
8. **Backup Before Remediation**: Always backup before making changes

## 🔧 Advanced Usage

### Programmatic Usage

```php
<?php
require_once 'wp-scanner/core/scanner.php';

$config = require 'wp-scanner/config/config.php';
$scanner = new WPScanner\Core\Scanner($config);

// Run full scan
$results = $scanner->runFullScan();

// Run quick scan
$quick_results = $scanner->runQuickScan();

// Initialize baselines
$baselines = $scanner->initializeBaselines();

// Get results
$scan_data = $scanner->getResults();
```

### User Management

```php
<?php
$editor = new WPScanner\Utils\UserRoleEditor($wpdb);

// Get all admins
$admins = $editor->getAdministrators();

// Audit user roles
$issues = $editor->auditUserRoles();

// Change user role
$editor->changeUserRole(123, 'subscriber');

// Delete suspicious user
$editor->deleteUser(456);
```

### File Quarantine

```php
<?php
$scanner = new WPScanner\Filesystem\Scanners\FileScanner($wp_root);

// Quarantine a file
$result = $scanner->quarantineFile('/path/to/suspicious/file.php');

// Quarantined files stored in: wp-scanner/quarantine/
```

## 📝 Logging

Logs are stored in `wp-scanner/logs/scanner.log`

Log levels:
- `DEBUG`: Detailed debugging information
- `INFO`: General information
- `WARNING`: Warning messages
- `ERROR`: Error messages
- `CRITICAL`: Critical issues

## 🤝 Integration

### Scheduled Scans (Cron)

Add to crontab:
```bash
# Daily quick scan
0 2 * * * /usr/bin/php /path/to/wp-scanner/scanner.php quick

# Weekly full scan
0 3 * * 0 /usr/bin/php /path/to/wp-scanner/scanner.php scan

# Hourly file watching
0 * * * * /usr/bin/php /path/to/wp-scanner/scanner.php watch
```

### Email Alerts

Configure in `config/config.php`:
```php
'alerts' => [
    'email' => true,
    'email_to' => 'security@example.com',
],
```

## 🐛 Troubleshooting

### Permission Issues
```bash
# Fix scanner directory permissions
chmod -R 755 wp-scanner/
chmod -R 777 wp-scanner/quarantine/
chmod -R 777 wp-scanner/logs/
chmod -R 777 wp-scanner/reports/
chmod -R 777 wp-scanner/data/
```

### Memory Limits
Increase PHP memory limit in `config/config.php`:
```php
'performance' => [
    'memory_limit' => '512M',
    'max_execution_time' => 600,
],
```

### Database Connection
Ensure WordPress is properly loaded or configure database manually.

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is provided as-is for security research and authorized testing only. Always:
- Backup your site before running scans
- Test in staging environment first
- Review all findings before taking action
- Consult with security professionals for critical issues

## 🎯 Roadmap

- [ ] Web-based dashboard UI
- [ ] Real-time monitoring with inotify
- [ ] Email/Slack notifications
- [ ] WordPress plugin integration
- [ ] Multi-site support
- [ ] Malware signature database
- [ ] Automated remediation
- [ ] REST API
- [ ] Integration with VirusTotal
- [ ] Machine learning anomaly detection

## 📧 Support

For issues, questions, or contributions, please open an issue in the repository.

---

**Stay secure! 🔐**
