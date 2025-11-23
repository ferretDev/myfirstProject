# WordPress Security Scanner - Quick Start Guide

Fast setup guide to get scanning in under 5 minutes.

---

## ⚡ Installation

### 1. Copy Scanner to WordPress Root

```bash
# Copy wp-scanner directory to your WordPress installation
cp -r wp-scanner /var/www/html/

# Set proper permissions
chmod -R 755 /var/www/html/wp-scanner
chmod 644 /var/www/html/wp-scanner/config/config.php
```

### 2. Configure Scanner

Edit `wp-scanner/config/config.php`:

```php
<?php
return [
    // WordPress installation path (REQUIRED)
    'wp_root' => '/var/www/html',  // Change to your WordPress root

    // Email notifications (OPTIONAL)
    'alerts' => [
        'email' => true,
        'email_to' => 'your-email@example.com',  // Change to your email
    ],

    // All other settings have sensible defaults
];
```

**That's it!** The scanner is configured and ready to use.

---

## 🚀 First Scan (60 seconds)

### Quick Test Run

```bash
cd /var/www/html/wp-scanner

# Run your first comprehensive scan
php scanner.php scan
```

**What happens**:
1. Scans WordPress core integrity
2. Checks all plugins and themes
3. Scans database for malware
4. Checks file system security
5. Audits configuration
6. Checks for known vulnerabilities
7. Generates risk score and recommendations
8. Creates detailed HTML report

**Expected output**:
```
╔════════════════════════════════════════════════════════════════╗
║      WordPress Comprehensive Security Scan - Version 2.0      ║
╚════════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────────┐
│ Phase 1: WordPress Core Integrity                             │
└────────────────────────────────────────────────────────────────┘

  → Checking WordPress core files...
  ✓  Core files verified successfully

[... continues for all 6 phases ...]

┌────────────────────────────────────────────────────────────────┐
│                        SECURITY SUMMARY                        │
└────────────────────────────────────────────────────────────────┘

  Risk Level:        LOW
  Risk Score:        12/100
  Total Issues:      3
  Critical Issues:   0

✓ Comprehensive scan completed!
ℹ HTML Report: /var/www/html/wp-scanner/reports/security_report_2025-11-23_153045.html
```

### View the Report

```bash
# Open report in browser
# Navigate to: file:///var/www/html/wp-scanner/reports/security_report_*.html

# Or view JSON report
cat wp-scanner/reports/security_report_*.json | jq .
```

---

## 🔧 Essential Commands

### Scanning

```bash
# Full comprehensive scan (recommended weekly)
php scanner.php scan

# Quick scan (recommended daily)
php scanner.php quick

# Check for vulnerabilities only (recommended daily)
php scanner.php check-vulnerabilities
```

### Fixing Issues

```bash
# If issues found, create backup first
php scanner.php backup

# Auto-fix common security issues
php scanner.php auto-fix

# Verify fixes with another scan
php scanner.php scan
```

### Setup Baselines

**Important**: Run this after confirming your site is clean!

```bash
# Initialize all baselines
php scanner.php init

# Create plugin baselines (for custom/premium plugins)
php scanner.php create-plugin-baselines

# Create theme baselines
php scanner.php create-theme-baselines
```

**Note**: Baselines allow the scanner to detect unauthorized file changes.

---

## 📧 Email Notifications (Optional)

### Test Email Setup

```bash
php scanner.php test-email
```

If emails aren't working, check `config/config.php`:

```php
'alerts' => [
    'email' => true,
    'email_to' => 'security@yourcompany.com',
    'email_from' => 'scanner@yoursite.com',
],
```

### Slack Notifications (Optional)

```php
'alerts' => [
    'slack' => true,
    'slack_webhook' => 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
],
```

---

## ⏰ Scheduled Scans (Recommended)

### Automatic Daily Scans

```bash
# Run interactive setup wizard
./utils/cron_helper.sh
```

**Or manually add to crontab**:

```bash
crontab -e
```

Add these lines:
```cron
# Daily vulnerability check at 2 AM
0 2 * * * cd /var/www/html && /usr/bin/php wp-scanner/scanner.php check-vulnerabilities >> wp-scanner/logs/cron.log 2>&1

# Weekly full scan on Sundays at 3 AM
0 3 * * 0 cd /var/www/html && /usr/bin/php wp-scanner/scanner.php scan >> wp-scanner/logs/cron.log 2>&1

# Daily backup on 1st of month at 4 AM
0 4 1 * * cd /var/www/html && /usr/bin/php wp-scanner/scanner.php backup >> wp-scanner/logs/cron.log 2>&1
```

### View Cron Logs

```bash
tail -f wp-scanner/logs/cron.log
```

---

## 🛠️ Common Workflows

### New WordPress Installation

```bash
# 1. Run initial scan
php scanner.php scan

# 2. Fix any issues found
php scanner.php auto-fix

# 3. Verify fixes
php scanner.php scan

# 4. Create baselines (once site is clean)
php scanner.php init
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines

# 5. Set up automated scans
./utils/cron_helper.sh

# 6. Test email notifications
php scanner.php test-email
```

### Weekly Security Check

```bash
# Check for new vulnerabilities
php scanner.php check-vulnerabilities

# If vulnerabilities found:
# 1. Update plugins/themes via WordPress admin
# 2. Re-create baselines
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines
```

### Suspected Compromise

```bash
# 1. Create backup IMMEDIATELY
php scanner.php backup

# 2. Run comprehensive scan
php scanner.php scan

# 3. Review HTML report (look for CRITICAL/HIGH issues)

# 4. Use auto-fix for common issues
php scanner.php auto-fix

# 5. Manual cleanup if needed
# - Remove suspicious files shown in report
# - Check database for backdoor users
# - Review recent file changes

# 6. Scan again to verify
php scanner.php scan

# 7. Reset all passwords
# 8. Re-create baselines
php scanner.php init
```

---

## 🎯 Understanding Results

### Risk Levels

- **CRITICAL** (≥100): Site likely compromised, take offline immediately
- **HIGH** (50-99): Urgent attention needed, significant vulnerabilities
- **MEDIUM** (25-49): Security improvements recommended
- **LOW** (0-24): Site appears secure, minor improvements suggested

### Common Issues

| Issue | Severity | Action |
|-------|----------|--------|
| PHP files in uploads | CRITICAL | Run auto-fix, blocks execution |
| Known vulnerability | CRITICAL | Update plugin/theme immediately |
| Modified core file | HIGH | Restore from WordPress.org |
| Modified plugin file | HIGH | Reinstall plugin or update baseline |
| World-writable file | HIGH | Run auto-fix, sets proper permissions |
| WP_DEBUG enabled | MEDIUM | Run auto-fix, disables debug mode |
| Weak permissions | MEDIUM | Run auto-fix or manually fix |

---

## 📁 File Locations

```
wp-scanner/
├── reports/           # HTML and JSON scan reports
├── logs/              # Scanner and cron logs
├── data/              # Baselines and scan results
├── backups/           # Backup files
├── quarantine/        # Quarantined suspicious files
└── config/            # Configuration files
```

---

## 🔍 Troubleshooting

### Scanner Won't Run

**Check PHP version**:
```bash
php -v  # Requires PHP 7.4+
```

**Check permissions**:
```bash
chmod +x scanner.php
chmod -R 755 wp-scanner/
```

### No Issues Detected But Site is Compromised

**Create fresh baselines**:
```bash
# Delete old baselines
rm -rf wp-scanner/data/*

# Re-initialize
php scanner.php init
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines
```

### False Positives

**Update baselines after legitimate changes**:
```bash
# After plugin/theme updates
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines

# After core updates
php scanner.php init
```

---

## 📚 Documentation

- **README.md** - Complete feature documentation
- **COMPREHENSIVE_FEATURES.md** - All features and workflows
- **PATTERN_MANAGEMENT.md** - Custom malware pattern system
- **PLUGIN_THEME_INTEGRITY.md** - Plugin/theme verification guide
- **SECURITY_IMPROVEMENTS.md** - Security hardening details
- **SECURITY_AUDIT.md** - Security audit report
- **QUICKSTART.md** - This guide

---

## ✅ Security Checklist

Before considering your site secure:

- [ ] Run comprehensive scan with ZERO critical issues
- [ ] All plugins and themes updated to latest versions
- [ ] No known vulnerabilities detected
- [ ] WordPress core files verified
- [ ] File permissions properly configured
- [ ] No PHP files in uploads directory
- [ ] WP_DEBUG disabled in production
- [ ] File editing disabled in wp-config.php
- [ ] Strong passwords for all admin accounts
- [ ] Regular backups configured
- [ ] Automated scans scheduled
- [ ] Email notifications working
- [ ] Baselines created and up-to-date

---

## 🎉 You're Ready!

The WordPress Security Scanner is now protecting your site.

**Recommended**: Schedule weekly review of scan reports and keep patterns updated.

For questions or issues, review the comprehensive documentation in the `wp-scanner/` directory.

**Stay secure!** 🔐
