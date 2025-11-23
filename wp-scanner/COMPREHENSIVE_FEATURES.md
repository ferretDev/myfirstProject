# WordPress Security Scanner - Comprehensive Features Guide

Complete guide to all features in WordPress Security Scanner v2.0

---

## 🎯 Overview

This is a **production-ready**, enterprise-grade WordPress security scanner that provides:
- ✅ **Complete threat detection** across all attack vectors
- ✅ **Automated remediation** for common security issues
- ✅ **Intelligent orchestration** of all security modules
- ✅ **Email/Slack notifications** for security alerts
- ✅ **Comprehensive reporting** with risk scoring
- ✅ **Scheduled scanning** via cron integration
- ✅ **Backup before fix** for safe remediation

---

## 🚀 New Features (v2.0)

### 1. Comprehensive Scan Orchestrator

**File**: `core/comprehensive_scan.php`

**What it does**:
- Coordinates ALL security modules in optimal order
- Runs 6 scanning phases automatically
- Generates unified risk assessment
- Beautiful CLI output with progress tracking
- Actionable recommendations based on findings

**Usage**:
```bash
php scanner.php scan
```

**Phases**:
1. **WordPress Core Integrity** - Verify core files against official checksums
2. **Plugins & Themes Integrity** - Check all plugins/themes for modifications
3. **Database Security** - Scan for malware, spam, and anomalies
4. **File System Security** - Check uploads, permissions, .htaccess
5. **Configuration & Hardening** - Audit wp-config.php and security settings
6. **Vulnerability Detection** - Check against WPScan database (50k+ vulns)

**Output Example**:
```
╔════════════════════════════════════════════════════════════════╗
║      WordPress Comprehensive Security Scan - Version 2.0      ║
╚════════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────────┐
│ Phase 1: WordPress Core Integrity                             │
└────────────────────────────────────────────────────────────────┘

  → Checking WordPress core files...
  ✓  Core files verified successfully

┌────────────────────────────────────────────────────────────────┐
│ Phase 2: Plugins & Themes Integrity                           │
└────────────────────────────────────────────────────────────────┘

  → Checking plugin file integrity...
  ⚠  3 plugin issues in 1 plugins
  → Checking theme file integrity...
  ✓  All themes verified successfully

... (continues for all phases)

┌────────────────────────────────────────────────────────────────┐
│                        SECURITY SUMMARY                        │
└────────────────────────────────────────────────────────────────┘

  Risk Level:        HIGH
  Risk Score:        67/100
  Total Issues:      12
  Critical Issues:   3

  Issues by Category:
    • Plugin Integrity              3
    • Filesystem                    4
    • Vulnerabilities              2
    • Hardening                    3

  ⚠️  URGENT ACTIONS REQUIRED:
    1. Create backup immediately (php scanner.php backup)
    2. Review detailed report in wp-scanner/reports/
    3. Update all vulnerable plugins/themes
    4. Remove PHP files from uploads directory
    5. Consider taking site offline until issues resolved
```

**Risk Scoring Algorithm**:
- Core file issues: 10 points each
- Plugin/Theme integrity issues: 8 points each
- Known vulnerabilities: 25 points each (CRITICAL!)
- PHP in uploads: 20 points each (CRITICAL!)
- Permission issues: 5 points each
- Hardening issues: 3 points each

**Risk Levels**:
- **CRITICAL**: Score ≥ 100
- **HIGH**: Score 50-99
- **MEDIUM**: Score 25-49
- **LOW**: Score 0-24

---

### 2. Automated Remediation Engine

**File**: `core/auto_remediation.php`

**What it does**:
- Automatically fixes common security issues
- Creates backup before making changes
- Requires user confirmation (safety first!)
- Dry-run mode available for testing
- Detailed logging of all actions

**Usage**:
```bash
# Run scan first
php scanner.php scan

# Then auto-fix issues
php scanner.php auto-fix
```

**What it can fix automatically**:

1. **PHP files in uploads directory** [CRITICAL]
   - Action: Quarantine suspicious files
   - Creates copy in quarantine directory
   - Logs original location

2. **World-writable files** [HIGH]
   - Action: Fix to proper permissions
   - Files: 0644
   - Directories: 0755
   - wp-config.php: 0440

3. **Missing index.php files** [MEDIUM]
   - Action: Create index.php in vulnerable directories
   - Prevents directory listing
   - Adds "Silence is golden" placeholder

4. **WP_DEBUG enabled** [MEDIUM]
   - Action: Set to false in wp-config.php
   - Prevents information disclosure

5. **File editing enabled** [MEDIUM]
   - Action: Add DISALLOW_FILE_EDIT to wp-config.php
   - Prevents malicious plugin uploads

**Example Output**:
```
╔════════════════════════════════════════════════════════════════╗
║              Automated Remediation Engine                      ║
╚════════════════════════════════════════════════════════════════╝

  Remediation Plan:
  ────────────────────────────────────────────────────────────────
  01. [CRITICAL] Quarantine PHP file in uploads: shell.php
  02. [HIGH] Fix world-writable: index.php
  03. [MEDIUM] Fix file permissions: wp-config.php
  04. [MEDIUM] Create index.php in: /wp-content/uploads/
  05. [MEDIUM] Disable WP_DEBUG in production

Apply 5 automated fixes? Type 'yes' to confirm: yes

  Executing remediation...
  ────────────────────────────────────────────────────────────────

  → Quarantine PHP file in uploads: shell.php... ✓
  → Fix world-writable: index.php... ✓
  → Fix file permissions: wp-config.php... ✓
  → Create index.php in: /wp-content/uploads/... ✓
  → Disable WP_DEBUG in production... ✓

  ✓ Remediation complete
  5 fixes applied successfully
```

**Safety Features**:
- ✅ Creates backup before changes (optional but recommended)
- ✅ User confirmation required
- ✅ Detailed logging of all actions
- ✅ Dry-run mode available
- ✅ Preserves original files in quarantine

---

### 3. Email & Slack Notifications

**File**: `utils/notifier.php`

**What it does**:
- Sends security alerts after scans
- Beautiful HTML emails with risk badges
- Slack integration for team notifications
- Webhook support for custom integrations
- Only sends if issues are found

**Email Configuration**:
Edit `config/config.php`:
```php
'alerts' => [
    'email' => true,
    'email_to' => 'security@yourcompany.com',
],
```

**Email Example**:
```
Subject: [HIGH] WordPress Security Alert - 12 issues detected

┌─────────────────────────────────────┐
│  🔒 WordPress Security Scan Alert   │
│  Scan completed: 2025-11-23 15:30   │
└─────────────────────────────────────┘

Security Summary
─────────────────
Risk Level: HIGH
Risk Score: 67/100
Total Issues: 12
Critical Issues: 3

Issues Detected
─────────────────
• Plugin Integrity: 3 issues
• Filesystem: 4 issues
• Vulnerabilities: 2 issues
• Hardening: 3 issues

⚠️ Recommended Actions
───────────────────────
1. Review detailed scan report immediately
2. Create backup before making changes
3. Update vulnerable plugins and themes
4. Remove unauthorized files
5. Fix file permissions
```

**Slack Configuration**:
```php
'alerts' => [
    'slack' => true,
    'slack_webhook' => 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
],
```

**Test Notifications**:
```bash
php scanner.php test-email
```

**Webhook Integration**:
```php
'alerts' => [
    'webhook_url' => 'https://your-server.com/webhook',
],
```

Webhook payload:
```json
{
  "event": "security_scan_completed",
  "timestamp": 1700753400,
  "scan_results": { ... full scan results ... }
}
```

---

### 4. Scheduled Scanning (Cron)

**File**: `utils/cron_helper.sh`

**What it does**:
- Interactive cron setup script
- Recommended schedules for different scan types
- Auto-configures crontab
- Logging to cron.log file

**Usage**:
```bash
cd wp-scanner
./utils/cron_helper.sh
```

**Recommended Schedules**:

1. **Daily Vulnerability Check** (2 AM):
   ```bash
   0 2 * * * php scanner.php check-vulnerabilities
   ```

2. **Weekly Full Scan** (Sunday 3 AM):
   ```bash
   0 3 * * 0 php scanner.php scan
   ```

3. **Daily Quick Scan** (1 AM):
   ```bash
   0 1 * * * php scanner.php quick
   ```

4. **Hourly File Watch**:
   ```bash
   0 * * * * php scanner.php watch
   ```

5. **Monthly Full Backup** (1st of month, 4 AM):
   ```bash
   0 4 1 * * php scanner.php backup
   ```

**Manual Cron Setup**:
```bash
crontab -e
```

Add:
```bash
# WordPress Security Scanner
0 2 * * * cd /var/www/html && /usr/bin/php wp-scanner/scanner.php check-vulnerabilities >> wp-scanner/logs/cron.log 2>&1
0 3 * * 0 cd /var/www/html && /usr/bin/php wp-scanner/scanner.php scan >> wp-scanner/logs/cron.log 2>&1
```

**View Cron Logs**:
```bash
tail -f wp-scanner/logs/cron.log
```

---

## 📊 Complete Command Reference

### Security Scanning
```bash
php scanner.php scan                    # Comprehensive scan (all 6 phases)
php scanner.php quick                   # Quick scan (essential checks)
php scanner.php integrity               # WordPress core integrity
php scanner.php check-plugins           # Plugin file integrity
php scanner.php check-themes            # Theme file integrity
php scanner.php check-vulnerabilities   # Known vulnerabilities
php scanner.php harden                  # Security hardening audit
php scanner.php permissions             # File permissions audit
php scanner.php htaccess                # .htaccess security scan
php scanner.php users                   # User account audit
php scanner.php anomalies               # Anomaly detection
php scanner.php watch                   # File change detection
```

### Remediation & Fixing
```bash
php scanner.php auto-fix                # Auto-fix issues from last scan
php scanner.php apply-hardening         # Apply hardening recommendations
```

### Baselines & Setup
```bash
php scanner.php init                    # Initialize all baselines
php scanner.php create-plugin-baselines # Plugin baselines
php scanner.php create-theme-baselines  # Theme baselines
```

### Backups
```bash
php scanner.php backup                  # Full backup (files + DB)
php scanner.php list-backups            # List all backups
```

### Notifications
```bash
php scanner.php test-email              # Test email notification
```

### Information
```bash
php scanner.php version                 # Show version
php scanner.php help                    # Show help
```

---

## 🔄 Recommended Workflows

### Initial Setup (New Installation)
```bash
# 1. Initialize baselines
php scanner.php init

# 2. Create plugin/theme baselines
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines

# 3. Run first comprehensive scan
php scanner.php scan

# 4. Review report and address issues
# (Report location shown in output)

# 5. Set up scheduled scans
./utils/cron_helper.sh

# 6. Test email notifications
php scanner.php test-email
```

### Daily Monitoring
```bash
# Automated via cron:
# - 2 AM: Vulnerability check
# - 3 AM Sunday: Full comprehensive scan
# - Hourly: File change detection
```

### Weekly Security Review
```bash
# 1. Check for new vulnerabilities
php scanner.php check-vulnerabilities

# 2. If vulnerabilities found, update immediately
# (via WordPress admin)

# 3. Re-baseline after updates
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines
```

### Suspected Compromise
```bash
# 1. Create backup IMMEDIATELY
php scanner.php backup

# 2. Run comprehensive scan
php scanner.php scan

# 3. Review detailed report
# Check: wp-scanner/reports/security_report_*.html

# 4. If compromised, use auto-fix
php scanner.php auto-fix

# 5. Verify fixes with another scan
php scanner.php scan

# 6. Manual cleanup if needed
# - Remove malicious users
# - Change all passwords
# - Review database for backdoors

# 7. Re-baseline after cleanup
php scanner.php init
```

### Before Going Live
```bash
# 1. Full security scan
php scanner.php scan

# 2. Ensure ZERO critical/high issues
# 3. Apply all hardening recommendations
php scanner.php apply-hardening

# 4. Create baseline for production
php scanner.php init

# 5. Set up automated monitoring
./utils/cron_helper.sh
```

---

## 📈 Performance & Scaling

### Scan Times (Approximate)

**Small Site** (< 5 plugins, < 10GB):
- Quick Scan: 5-10 seconds
- Full Scan: 30-60 seconds

**Medium Site** (5-20 plugins, 10-50GB):
- Quick Scan: 10-20 seconds
- Full Scan: 1-3 minutes

**Large Site** (20+ plugins, 50GB+):
- Quick Scan: 20-40 seconds
- Full Scan: 3-10 minutes

### Performance Tips

1. **Use baselines**: Faster than re-checking against repos
2. **Cache vulnerabilities**: 24-hour cache reduces API calls
3. **Exclude cache dirs**: Configure in config.php
4. **Run during off-hours**: Schedule for low-traffic times
5. **Monitor resources**: Scanner respects PHP memory limits

---

## 🔐 Security Best Practices

1. **Regular Scanning**:
   - Daily vulnerability checks
   - Weekly comprehensive scans
   - After any plugin/theme updates

2. **Immediate Response**:
   - Create backup when issues found
   - Update vulnerable components ASAP
   - Use auto-fix for quick remediation

3. **Baseline Management**:
   - Re-baseline after legitimate updates
   - Keep baselines current
   - Document custom modifications

4. **Monitoring**:
   - Enable email notifications
   - Review cron logs regularly
   - Check reports promptly

5. **Incident Response**:
   - Follow workflow above
   - Don't skip backup step
   - Document findings
   - Consider professional help for severe compromises

---

## 📧 Support & Resources

- **Full Documentation**: See README.md
- **Plugin/Theme Integrity**: See PLUGIN_THEME_INTEGRITY.md
- **Security Improvements**: See SECURITY_IMPROVEMENTS.md
- **Security Audit**: See SECURITY_AUDIT.md
- **Logs**: wp-scanner/logs/scanner.log

---

## 🎉 Summary

WordPress Security Scanner v2.0 provides:

✅ **Complete Coverage**:
- WordPress Core
- Plugins & Themes
- Database
- File System
- Configuration
- Known Vulnerabilities

✅ **Intelligent Automation**:
- Orchestrated scanning
- Auto-fix capabilities
- Email/Slack alerts
- Scheduled scans

✅ **Enterprise Features**:
- Risk scoring
- Comprehensive reports
- Backup integration
- Detailed logging

✅ **Production Ready**:
- Input validation
- Path protection
- Rate limiting
- Confirmation prompts
- Extensive testing

**This is now a fully-featured, production-ready WordPress security solution!**
